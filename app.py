import os
import json
import logging
import re
import asyncio
from datetime import datetime, timezone, timedelta

import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from telethon import TelegramClient
from telethon.sessions import StringSession

from db import init_db, get_conn, get_secret, set_secret, set_status, get_status

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - miniapp - %(levelname)s - %(message)s",
)
logger = logging.getLogger("miniapp")

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app, resources={r"/*": {"origins": "*"}})

PORT = int(os.getenv("PORT", "8080"))

# ===== Security / secrets =====
API_SECRET = (os.getenv("API_SECRET") or "").strip()

# ===== Telegram bot (alerts + job notify) =====
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN") or ""
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID") or ""
ADMINS_RAW = os.getenv("ADMINS", "")

# ===== Alert throttling (first immediately, repeats ~1h) =====
ALERT_RATE_LIMIT_SECONDS = int(os.getenv("ALERT_RATE_LIMIT_SECONDS") or "3600")
_last_alert_sent_at: dict[str, datetime] = {}

# ===== Job notify anti-flood (vacancies go immediately; protection only for abnormal burst) =====
NOTIFY_CHAT_IDS_RAW = (os.getenv("NOTIFY_CHAT_IDS") or "").strip()
NOTIFY_PER_CHAT_PER_MINUTE = int(os.getenv("NOTIFY_PER_CHAT_PER_MINUTE") or "0")  # 0 = off

NOTIFY_BURST_WINDOW_SECONDS = int(os.getenv("NOTIFY_BURST_WINDOW_SECONDS") or "60")
NOTIFY_BURST_LIMIT = int(os.getenv("NOTIFY_BURST_LIMIT") or "200")
NOTIFY_BURST_COOLDOWN_SECONDS = int(os.getenv("NOTIFY_BURST_COOLDOWN_SECONDS") or "1800")

_notify_window: dict[int, dict[str, object]] = {}
_notify_state: dict[int, dict[str, object]] = {}

# ===== TG auth service (proxy) =====
TG_AUTH_SERVICE_URL = (os.getenv("TG_AUTH_SERVICE_URL") or "").rstrip("/")
TG_AUTH_SERVICE_TOKEN = os.getenv("TG_AUTH_SERVICE_TOKEN") or os.getenv("AUTH_TOKEN") or ""

# ===== For checking tg session via Telethon =====
TG_API_ID_DEFAULT = int(os.getenv("TG_API_ID_DEFAULT") or "0")
TG_API_HASH_DEFAULT = os.getenv("TG_API_HASH_DEFAULT") or ""


# ---------------- Error handler (always JSON) ----------------
@app.errorhandler(Exception)
def _handle_any_exception(e):
    if isinstance(e, HTTPException):
        return jsonify({"error": e.name}), e.code
    logger.exception("Unhandled exception")
    return jsonify({"error": "internal_error"}), 500


# ---------------- Helpers ----------------
def _username_norm(u: str | None) -> str:
    u = (u or "").strip().lower()
    if u.startswith("@"):
        u = u[1:]
    return u


def _admins_set() -> set[str]:
    parts = [p.strip().lower().lstrip("@") for p in (ADMINS_RAW or "").split(",") if p.strip()]
    return set(parts)


def _is_admin_username(username_norm: str) -> bool:
    return bool(username_norm) and username_norm in _admins_set()


def _get_admin_username() -> str:
    # фронт шлёт X-ADMIN-USERNAME
    return _username_norm(request.headers.get("X-ADMIN-USERNAME") or request.headers.get("X-Admin-Username") or "")


def _require_admin():
    username_norm = _get_admin_username()
    if not username_norm:
        return False, (jsonify({"error": "admin_required"}), 401)
    if not _is_admin_username(username_norm):
        return False, (jsonify({"error": "forbidden"}), 403)
    return True, None


def _get_parser_key_from_request() -> str | None:
    x = request.headers.get("X-API-KEY")
    if x is not None:
        return x
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def _require_parser_key():
    # если API_SECRET не задан — разрешаем (но на проде ставь всегда)
    if not API_SECRET:
        return True, None
    provided = _get_parser_key_from_request()
    if not provided or provided != API_SECRET:
        return False, (jsonify({"error": "forbidden"}), 403)
    return True, None


def _admin_or_parser():
    # для секретов/статусов: допускаем админа ИЛИ парсер-ключ
    if _is_admin_username(_get_admin_username()):
        return True, None
    return _require_parser_key()


def _parse_notify_chat_ids() -> list[int]:
    ids: list[int] = []
    if NOTIFY_CHAT_IDS_RAW:
        for part in NOTIFY_CHAT_IDS_RAW.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ids.append(int(part))
            except Exception:
                logger.warning("Bad NOTIFY_CHAT_IDS entry ignored: %r", part)
    return ids


def _can_send_per_minute(chat_id: int) -> bool:
    if NOTIFY_PER_CHAT_PER_MINUTE <= 0:
        return True
    now = datetime.now(timezone.utc)
    rec = _notify_window.get(chat_id)
    if not rec or not isinstance(rec.get("reset_at"), datetime):
        _notify_window[chat_id] = {"reset_at": now + timedelta(minutes=1), "count": 1}
        return True
    if now >= rec["reset_at"]:
        _notify_window[chat_id] = {"reset_at": now + timedelta(minutes=1), "count": 1}
        return True
    cnt = int(rec.get("count") or 0)
    if cnt >= NOTIFY_PER_CHAT_PER_MINUTE:
        return False
    rec["count"] = cnt + 1
    return True


def _burst_allowed(chat_id: int) -> bool:
    now = datetime.now(timezone.utc)
    st = _notify_state.get(chat_id)
    if not st:
        st = {
            "window_reset_at": now + timedelta(seconds=NOTIFY_BURST_WINDOW_SECONDS),
            "count": 0,
            "disabled_until": None,
        }
        _notify_state[chat_id] = st

    disabled_until = st.get("disabled_until")
    if isinstance(disabled_until, datetime) and now < disabled_until:
        return False

    if not isinstance(st.get("window_reset_at"), datetime) or now >= st["window_reset_at"]:
        st["window_reset_at"] = now + timedelta(seconds=NOTIFY_BURST_WINDOW_SECONDS)
        st["count"] = 0

    st["count"] = int(st.get("count") or 0) + 1

    if int(st["count"]) > NOTIFY_BURST_LIMIT:
        st["disabled_until"] = now + timedelta(seconds=NOTIFY_BURST_COOLDOWN_SECONDS)
        try:
            send_alert_human(
                f"🚨 Flood protection: too many NEW posts. Disable notify for chat_id={chat_id} "
                f"for {NOTIFY_BURST_COOLDOWN_SECONDS}s"
            )
        except Exception:
            pass
        return False

    return True


def _normalize_alert_key(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    first = t.splitlines()[0].strip()[:200]
    # выкидываем длинные числа (таймстемпы/ids), чтобы не обходили лимит
    first = re.sub(r"\d{2,}", "#", first)
    return first


def send_alert_human(text: str):
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        logger.warning("Alert skipped (no BOT_TOKEN/ADMIN_CHAT_ID): %s", text)
        return

    now = datetime.now(timezone.utc)
    key = _normalize_alert_key(text)

    last = _last_alert_sent_at.get(key)
    if last and now - last < timedelta(seconds=ALERT_RATE_LIMIT_SECONDS):
        return

    _last_alert_sent_at[key] = now

    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": ADMIN_CHAT_ID, "text": text},
            timeout=10,
        )
    except Exception as e:
        logger.error("Failed to send alert: %s", e)


def _build_job_message(data: dict) -> tuple[str, dict | None]:
    url = (data.get("url") or "").strip()
    text = (data.get("text") or "").strip()

    preview = text.strip()
    if len(preview) > 700:
        preview = preview[:700].rstrip() + "…"

    msg_lines = []
    if url:
        msg_lines.append("📣 Получена вакансия из группы:")
        msg_lines.append(url)
    else:
        msg_lines.append("📣 Получена вакансия:")

    msg_lines.append("")
    msg_lines.append("📝 Краткое описание:")
    msg_lines.append(preview if preview else "(без текста)")

    message_text = "\n".join(msg_lines)

    buttons = []
    if url:
        buttons.append([{"text": "🔗 Открыть пост", "url": url}])

    sender_username = (data.get("sender_username") or "").strip()
    if sender_username:
        if sender_username.startswith("http://") or sender_username.startswith("https://"):
            dm_url = sender_username
        else:
            uname = sender_username.lstrip("@")
            dm_url = f"https://t.me/{uname}" if uname else ""
        if dm_url:
            buttons.append([{"text": "✉️ Написать автору", "url": dm_url}])

    reply_markup = {"inline_keyboard": buttons} if buttons else None
    return message_text, reply_markup


def send_job_notification(data: dict):
    # вакансии: “единоразово” обеспечивается тем, что вызываем только после INSERT нового external_id
    if not BOT_TOKEN:
        return

    chat_ids = _parse_notify_chat_ids()
    if not chat_ids:
        # если явно не задано — шлём всем, у кого есть user_id в allowed_users + админу
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT user_id FROM allowed_users WHERE user_id IS NOT NULL")
            rows = cur.fetchall() or []
            conn.close()
            for r in rows:
                try:
                    chat_ids.append(int(r.get("user_id")))
                except Exception:
                    pass
        except Exception as e:
            logger.error("load allowed_users for notify failed: %s", e)

        if ADMIN_CHAT_ID:
            try:
                chat_ids.append(int(ADMIN_CHAT_ID))
            except Exception:
                pass

    chat_ids = list(dict.fromkeys(chat_ids))
    if not chat_ids:
        return

    message_text, reply_markup = _build_job_message(data)

    for chat_id in chat_ids:
        if not _can_send_per_minute(chat_id):
            continue
        if not _burst_allowed(chat_id):
            continue

        payload = {
            "chat_id": chat_id,
            "text": message_text,
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup

        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                logger.error("notify failed chat_id=%s http=%s body=%s", chat_id, resp.status_code, resp.text[:300])
        except Exception as e:
            logger.error("notify failed chat_id=%s err=%s", chat_id, e)


# ---------------- Static ----------------
@app.route("/")
def index_page():
    return send_from_directory(app.static_folder, "index.html")


# ---------------- Access check (used by frontend bootstrap) ----------------
@app.route("/check_access", methods=["POST"])
def check_access():
    data = request.get_json(silent=True) or {}
    header_username = request.headers.get("X-Username") or ""
    username = data.get("username") or data.get("user") or header_username
    username_norm = _username_norm(username)

    # admin allowed
    if _is_admin_username(username_norm):
        return jsonify({"access_granted": True, "is_admin": True})

    if not username_norm:
        return jsonify({"access_granted": False, "is_admin": False})

    user_id = data.get("user_id")
    try:
        user_id = int(user_id) if user_id is not None else None
    except Exception:
        user_id = None

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, username, user_id FROM allowed_users WHERE username = %s", (username_norm,))
        row = cur.fetchone()
        if row and row.get("user_id") is None and user_id is not None:
            cur.execute("UPDATE allowed_users SET user_id=%s, updated_at=NOW() WHERE id=%s", (user_id, row["id"]))
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error("check_access db error: %s", e)
        # важный момент: фронт ждёт JSON => возвращаем JSON
        return jsonify({"access_granted": False, "is_admin": False}), 200

    return jsonify({"access_granted": bool(row), "is_admin": False})


# ---------------- Jobs ----------------
@app.route("/api/jobs", methods=["GET"])
def api_jobs():
    archived = (request.args.get("archived") or "false").lower() in ("1", "true", "yes")
    limit = int(request.args.get("limit") or "50")
    limit = max(1, min(limit, 200))

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, source, source_name, external_id, url, text, sender_username,
               created_at, received_at, archived, archived_at
        FROM jobs
        WHERE archived = %s
        ORDER BY received_at DESC
        LIMIT %s
        """,
        (archived, limit),
    )
    rows = cur.fetchall() or []
    conn.close()
    return jsonify({"jobs": rows})


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def api_job_archive(job_id: int):
    ok, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    archived = bool(data.get("archived", True))

    conn = get_conn()
    cur = conn.cursor()
    if archived:
        cur.execute("UPDATE jobs SET archived=TRUE, archived_at=NOW() WHERE id=%s", (job_id,))
    else:
        cur.execute("UPDATE jobs SET archived=FALSE, archived_at=NULL WHERE id=%s", (job_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------------- Groups (frontend expects this) ----------------
@app.route("/api/groups", methods=["GET"])
def api_groups_get():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, group_id, group_name, enabled, added_at FROM fb_groups ORDER BY added_at DESC")
    rows = cur.fetchall() or []
    conn.close()
    return jsonify({"groups": rows})


@app.route("/api/groups", methods=["POST"])
def api_groups_add():
    ok, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    group_name = (data.get("group_name") or "").strip() or None

    if not group_id:
        return jsonify({"error": "group_id_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO fb_groups (group_id, group_name, enabled)
        VALUES (%s, %s, TRUE)
        ON CONFLICT (group_id) DO UPDATE SET group_name = EXCLUDED.group_name, enabled = TRUE
        RETURNING id
        """,
        (group_id, group_name),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "id": row["id"] if row else None})


@app.route("/api/groups/<int:gid>/toggle", methods=["POST"])
def api_groups_toggle(gid: int):
    ok, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE fb_groups SET enabled = NOT enabled WHERE id=%s", (gid,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/groups/<int:gid>", methods=["DELETE"])
def api_groups_delete(gid: int):
    ok, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM fb_groups WHERE id=%s", (gid,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------------- Allowed users (frontend expects users[]) ----------------
@app.route("/api/allowed_users", methods=["GET"])
def api_allowed_users():
    ok, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    # ВАЖНО: в БД updated_at, не created_at
    cur.execute("SELECT id, username, user_id, updated_at FROM allowed_users ORDER BY updated_at DESC")
    rows = cur.fetchall() or []
    conn.close()

    # фронт ждёт `users`
    return jsonify({"users": rows})


@app.route("/api/allowed_users", methods=["POST"])
def api_add_allowed_user():
    ok, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = _username_norm(data.get("username"))
    if not username:
        return jsonify({"error": "username_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO allowed_users (username, user_id, updated_at)
        VALUES (%s, NULL, NOW())
        ON CONFLICT (username) DO UPDATE SET updated_at = NOW()
        RETURNING id
        """,
        (username,),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "id": row["id"] if row else None})


@app.route("/api/allowed_users/<int:user_id>", methods=["DELETE"])
def api_delete_allowed_user(user_id: int):
    ok, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM allowed_users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------------- Parser secrets/status (admin OR parser key) ----------------
@app.route("/api/parser_secrets/<key>", methods=["GET"])
def api_get_parser_secret(key: str):
    ok, err = _admin_or_parser()
    if err:
        return err

    key = (key or "").strip()
    if not key:
        return jsonify({"error": "key_required"}), 400

    row = get_secret(key)
    if not row:
        # fallback to env if exists
        v = os.getenv(key)
        if v is None:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"key": key, "value": v})

    return jsonify({"key": row.get("key"), "value": row.get("value"), "updated_at": row.get("updated_at")})


@app.route("/api/parser_status/<key>", methods=["POST"])
def api_set_parser_status(key: str):
    ok, err = _admin_or_parser()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    value = (data.get("value") or "").strip()
    if not value:
        return jsonify({"error": "value_required"}), 400

    set_status(key, value)
    return jsonify({"status": "ok"})


@app.route("/api/parser_status/<key>", methods=["GET"])
def api_get_parser_status(key: str):
    ok, err = _require_admin()
    if err:
        return err

    row = get_status(key)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(row)


# ---------------- Admin settings endpoints (frontend expects these) ----------------
@app.route("/api/admin/secrets", methods=["GET"])
def api_admin_secrets_overview():
    ok, err = _require_admin()
    if err:
        return err

    fb = get_secret("fb_cookies_json")
    tg = get_secret("tg_session")
    # tg_auth_pending можем не знать (в tg-auth-service это в памяти), вернём null
    return jsonify({
        "fb_cookies_updated_at": fb.get("updated_at") if fb else None,
        "tg_session_updated_at": tg.get("updated_at") if tg else None,
        "tg_auth_pending": None,
    })


@app.route("/api/admin/fb_cookies", methods=["POST"])
def api_admin_set_fb_cookies():
    ok, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    cookies_json = (data.get("cookies_json") or "").strip()
    if not cookies_json:
        return jsonify({"error": "cookies_json_required"}), 400

    # валидируем, что это JSON массив
    try:
        parsed = json.loads(cookies_json)
        if not isinstance(parsed, list):
            return jsonify({"error": "cookies_json_must_be_array"}), 400
    except Exception:
        return jsonify({"error": "cookies_json_invalid"}), 400

    set_secret("fb_cookies_json", cookies_json)
    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_session", methods=["POST"])
def api_admin_set_tg_session():
    ok, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    session = (data.get("session") or "").strip()
    if not session:
        return jsonify({"error": "session_required"}), 400

    set_secret("tg_session", session)
    return jsonify({"status": "ok"})


async def _tg_check_session_async(session_str: str):
    client = TelegramClient(StringSession(session_str), TG_API_ID_DEFAULT, TG_API_HASH_DEFAULT)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"ok": False, "reason": "not_authorized"}
        me = await client.get_me()
        return {
            "ok": True,
            "me": {
                "id": getattr(me, "id", None),
                "username": getattr(me, "username", None),
                "first_name": getattr(me, "first_name", None),
                "last_name": getattr(me, "last_name", None),
            },
        }
    finally:
        await client.disconnect()


@app.route("/api/admin/tg_session/check", methods=["GET"])
def api_admin_tg_session_check():
    ok, err = _require_admin()
    if err:
        return err

    if not TG_API_ID_DEFAULT or not TG_API_HASH_DEFAULT:
        return jsonify({"ok": False, "reason": "TG_API_ID_DEFAULT/TG_API_HASH_DEFAULT not set"}), 200

    row = get_secret("tg_session")
    session_str = (row.get("value") if row else "") or ""
    if not session_str:
        return jsonify({"ok": False, "reason": "tg_session_empty"}), 200

    try:
        res = asyncio.run(_tg_check_session_async(session_str))
        return jsonify(res)
    except Exception as e:
        logger.error("tg_session check failed: %s", e)
        return jsonify({"ok": False, "reason": "check_failed"}), 200


@app.route("/api/admin/tg_auth/start", methods=["POST"])
def api_admin_tg_auth_start():
    ok, err = _require_admin()
    if err:
        return err

    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        return jsonify({"error": "TG_AUTH_SERVICE_URL/TG_AUTH_SERVICE_TOKEN not configured"}), 400

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    r = requests.post(
        f"{TG_AUTH_SERVICE_URL}/auth/start",
        headers={"Authorization": f"Bearer {TG_AUTH_SERVICE_TOKEN}"},
        json={"phone": phone},
        timeout=30,
    )
    if r.status_code >= 400:
        # tg-auth-service возвращает JSON, прокидываем как error
        try:
            j = r.json()
        except Exception:
            j = {"error": r.text[:300]}
        return jsonify({"error": j.get("error") or "tg_auth_start_failed"}), 400

    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_auth/confirm", methods=["POST"])
def api_admin_tg_auth_confirm():
    ok, err = _require_admin()
    if err:
        return err

    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        return jsonify({"error": "TG_AUTH_SERVICE_URL/TG_AUTH_SERVICE_TOKEN not configured"}), 400

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    password = data.get("password")

    if not phone or not code:
        return jsonify({"error": "phone_and_code_required"}), 400

    r = requests.post(
        f"{TG_AUTH_SERVICE_URL}/auth/confirm",
        headers={"Authorization": f"Bearer {TG_AUTH_SERVICE_TOKEN}"},
        json={"phone": phone, "code": code, "password": password},
        timeout=60,
    )
    if r.status_code >= 400:
        try:
            j = r.json()
        except Exception:
            j = {"error": r.text[:300]}
        return jsonify({"error": j.get("error") or "tg_auth_confirm_failed"}), 400

    # tg-auth-service возвращает string_session — сохраняем в parser_secrets как tg_session
    try:
        j = r.json() or {}
        session_str = (j.get("string_session") or "").strip()
        if session_str:
            set_secret("tg_session", session_str)
    except Exception:
        pass

    return jsonify({"status": "ok"})


# ---------------- Parsers: alerts and job ingest ----------------
@app.route("/api/alert", methods=["POST"])
def api_alert():
    ok, err = _require_parser_key()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    text = data.get("text") or data.get("message")
    if not text:
        return jsonify({"error": "text_required"}), 400
    send_alert_human(text)
    return jsonify({"status": "ok"})


@app.route("/post", methods=["POST"])
def add_job():
    ok, err = _require_parser_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    source = (data.get("source") or "").strip()
    source_name = (data.get("source_name") or "").strip()
    external_id = (data.get("external_id") or "").strip()
    url = (data.get("url") or "").strip()
    text = (data.get("text") or "").strip()
    sender_username = (data.get("sender_username") or "").strip()
    created_at = data.get("created_at")

    if not source or not external_id or not text:
        return jsonify({"error": "bad_request"}), 400

    created_at_dt = None
    if created_at:
        try:
            if isinstance(created_at, (int, float)):
                created_at_dt = datetime.fromtimestamp(float(created_at), tz=timezone.utc)
            elif isinstance(created_at, str):
                created_at_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except Exception:
            created_at_dt = None

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO jobs (source, source_name, external_id, url, text, sender_username, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (external_id, source) DO NOTHING
        RETURNING id
        """,
        (source, source_name or source, external_id, url, text, sender_username, created_at_dt),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()

    if row:
        # новый пост -> уведомление СРАЗУ и 1 раз (только на новый insert)
        try:
            send_job_notification(data)
        except Exception as e:
            logger.error("send_job_notification failed: %s", e)

    return jsonify({"status": "ok", "id": row["id"] if row else None})


if __name__ == "__main__":
    init_db()
    logger.info("Start miniapp on port %s", PORT)
    app.run(host="0.0.0.0", port=PORT)
