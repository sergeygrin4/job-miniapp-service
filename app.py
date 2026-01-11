import os
import json
import hmac
import hashlib
import asyncio
import logging
from urllib.parse import parse_qsl
from datetime import datetime, timezone, timedelta
from typing import Optional

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from telegram import Bot
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

from db import get_conn, init_db, get_secret, set_secret, get_status, set_status

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("miniapp")

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

PORT = int(os.getenv("PORT", "8080"))

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN") or ""
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
ADMINS_RAW = os.getenv("ADMINS", "")

API_SECRET = os.getenv("API_SECRET", "")
TELEGRAM_BOT_TOKEN = BOT_TOKEN

bot = Bot(token=BOT_TOKEN) if BOT_TOKEN else None

ADMINS = set()
for a in (ADMINS_RAW or "").split(","):
    a = a.strip()
    if a:
        ADMINS.add(a.lstrip("@").lower())


def _username_norm(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    username = username.strip()
    if not username:
        return None
    username = username.lstrip("@")
    return username.lower()


def is_admin(username_norm: Optional[str]) -> bool:
    if not username_norm:
        return False
    return username_norm in ADMINS


# ---------------- Telegram WebApp auth (initData) ----------------

def _verify_tg_init_data(init_data: str) -> Optional[dict]:
    """
    Проверка подписи Telegram WebApp initData.
    Возвращает dict, если подпись валидна, иначе None.
    """
    if not init_data or not TELEGRAM_BOT_TOKEN:
        return None

    try:
        data = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = data.pop("hash", None)
        if not received_hash:
            return None

        data_check_string = "\n".join(f"{k}={data[k]}" for k in sorted(data.keys()))
        secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode("utf-8")).digest()
        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            return None

        return data
    except Exception:
        return None


def _get_admin_from_request() -> Optional[dict]:
    """
    Админ-аутентификация для UI-запросов:
      - заголовок X-TG-INIT-DATA (window.Telegram.WebApp.initData)
      - если подпись валидна → username должен быть в ADMINS
      - fallback: заголовок X-ADMIN-USERNAME (если initData не пришёл/невалиден)
    """
    # 1) Пытаемся верифицировать initData
    init_data = request.headers.get("X-TG-INIT-DATA") or ""
    if init_data:
        verified = _verify_tg_init_data(init_data)
        if verified:
            user_raw = verified.get("user")
            if user_raw:
                try:
                    user_obj = json.loads(user_raw)
                except Exception:
                    user_obj = None

                if isinstance(user_obj, dict):
                    username_norm = _username_norm(user_obj.get("username"))
                    if is_admin(username_norm):
                        user_id = user_obj.get("id")
                        try:
                            user_id = int(user_id) if user_id is not None else None
                        except Exception:
                            user_id = None
                        return {"user_id": user_id, "username_norm": username_norm}

    # 2) Fallback: доверяем username из заголовка (миниапп его сам ставит)
    username_hdr = request.headers.get("X-ADMIN-USERNAME") or ""
    username_norm = _username_norm(username_hdr)
    if is_admin(username_norm):
        return {"user_id": None, "username_norm": username_norm}

    return None


def _require_admin():
    admin = _get_admin_from_request()
    if not admin:
        return None, (jsonify({"error": "admin_forbidden"}), 403)
    return admin, None


def _iso(dt):
    if not dt:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return None


# ---------------- Alerts ----------------

def send_alert_human(text: str):
    if not bot or not ADMIN_CHAT_ID:
        logger.warning("No bot/admin chat configured, alert skipped: %s", text)
        return

    try:
        bot.send_message(chat_id=ADMIN_CHAT_ID, text=text)
    except Exception as e:
        logger.error("Failed to send alert: %s", e)


@app.route("/api/alert", methods=["POST"])
def api_alert():
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    src = data.get("source") or "unknown"
    msg = data.get("message") or ""
    if not msg:
        return jsonify({"error": "message_required"}), 400

    send_alert_human(f"🔔 {src}:\n{msg}")
    return jsonify({"status": "ok"})


# ---------------- Static ----------------

@app.route("/")
def index_page():
    return send_from_directory("static", "index.html")


# ---------------- Jobs API ----------------

@app.route("/post", methods=["POST"])
def add_job():
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
        (
            source,
            source_name or source,
            external_id,
            url,
            text,
            sender_username,
            created_at_dt,
        ),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()

    if row:
        return jsonify({"status": "ok", "id": row["id"]})
    return jsonify({"status": "ok", "id": None})


@app.route("/api/jobs", methods=["GET"])
def api_get_jobs():
    try:
        limit = int(request.args.get("limit") or "50")
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))

    archived_str = request.args.get("archived") or "false"
    archived = archived_str.lower() == "true"

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, source, source_name, external_id, url, text, sender_username,
               created_at, received_at, archived, archived_at
        FROM jobs
        WHERE archived = %s
        ORDER BY id DESC
        LIMIT %s
        """,
        (archived, limit),
    )
    rows = cur.fetchall()
    conn.close()

    jobs = []
    for r in rows:
        jobs.append(
            {
                "id": r["id"],
                "source": r["source"],
                "source_name": r["source_name"],
                "external_id": r["external_id"],
                "url": r["url"],
                "text": r["text"],
                "sender_username": r.get("sender_username"),
                "created_at": _iso(r.get("created_at")),
                "received_at": _iso(r.get("received_at")),
                "archived": bool(r.get("archived")),
                "archived_at": _iso(r.get("archived_at")),
            }
        )

    return jsonify({"jobs": jobs})


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def api_archive_job(job_id: int):
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    archived = bool(data.get("archived", True))

    conn = get_conn()
    cur = conn.cursor()
    if archived:
        cur.execute(
            """
            UPDATE jobs
               SET archived = TRUE,
                   archived_at = NOW()
             WHERE id = %s
            """,
            (job_id,),
        )
    else:
        cur.execute(
            """
            UPDATE jobs
               SET archived = FALSE,
                   archived_at = NULL
             WHERE id = %s
            """,
            (job_id,),
        )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# ---------------- Access control ----------------

@app.route("/check_access", methods=["POST"])
def check_access():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    username = data.get("username")

    username_norm = _username_norm(username)

    if is_admin(username_norm):
        return jsonify({"access_granted": True, "is_admin": True})

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, user_id FROM allowed_users WHERE username = %s", (username_norm,))
    row = cur.fetchone()
    if row:
        db_user_id = row.get("user_id")
        try:
            db_user_id = int(db_user_id) if db_user_id is not None else None
        except Exception:
            db_user_id = None

        if not db_user_id and user_id:
            try:
                user_id_int = int(user_id)
            except Exception:
                user_id_int = None

            if user_id_int:
                cur.execute(
                    "UPDATE allowed_users SET user_id = %s, updated_at = NOW() WHERE id = %s",
                    (user_id_int, row["id"]),
                )
                conn.commit()

        conn.close()
        return jsonify({"access_granted": True, "is_admin": False})

    conn.close()
    return jsonify({"access_granted": False, "is_admin": False})


@app.route("/api/allowed_users", methods=["GET"])
def list_allowed_users():
    admin, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, user_id, updated_at FROM allowed_users ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    users = []
    for r in rows:
        users.append(
            {
                "id": r["id"],
                "username": r["username"],
                "user_id": r.get("user_id"),
                "updated_at": _iso(r.get("updated_at")),
            }
        )

    return jsonify({"users": users})


@app.route("/api/allowed_users", methods=["POST"])
def add_allowed_user():
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    username_norm = _username_norm(username)

    if not username_norm:
        return jsonify({"error": "username_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM allowed_users WHERE username = %s", (username_norm,))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE allowed_users SET updated_at = NOW() WHERE id = %s",
            (row["id"],),
        )
    else:
        cur.execute(
            "INSERT INTO allowed_users (username, user_id, updated_at) VALUES (%s, %s, NOW())",
            (username_norm, None),
        )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@app.route("/api/allowed_users/<int:allowed_id>", methods=["DELETE"])
def delete_allowed_user(allowed_id: int):
    admin, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM allowed_users WHERE id = %s", (allowed_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# ---------------- Groups API ----------------

@app.route("/api/groups", methods=["GET"])
def api_get_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, group_id, group_name, enabled, added_at FROM fb_groups ORDER BY id DESC"
    )
    rows = cur.fetchall()
    conn.close()

    groups = []
    for r in rows:
        groups.append(
            {
                "id": r["id"],
                "group_id": r["group_id"],
                "group_name": r["group_name"],
                "enabled": bool(r["enabled"]),
                "added_at": _iso(r.get("added_at")),
            }
        )
    return jsonify({"groups": groups})


@app.route("/api/groups", methods=["POST"])
def api_add_group():
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    group_name = (data.get("group_name") or "").strip()

    if not group_id:
        return jsonify({"error": "group_id_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO fb_groups (group_id, group_name)
        VALUES (%s, %s)
        ON CONFLICT (group_id) DO UPDATE
        SET group_name = EXCLUDED.group_name,
            enabled = TRUE
        RETURNING id
        """,
        (group_id, group_name),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "id": row["id"]})


@app.route("/api/groups/<int:group_id>/toggle", methods=["POST"])
def api_toggle_group(group_id: int):
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", True))

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE fb_groups SET enabled = %s WHERE id = %s",
        (enabled, group_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@app.route("/api/groups/<int:group_id>", methods=["DELETE"])
def api_delete_group(group_id: int):
    admin, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM fb_groups WHERE id = %s", (group_id,))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# ---------------- Parser secrets / status ----------------

@app.route("/api/parser_secrets/<key>", methods=["GET"])
def api_get_parser_secret(key: str):
    """
    Для парсеров: получить секрет из БД.
    Авторизация: X-API-KEY == API_SECRET (если задан).
    """
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    row = get_secret(key)
    if not row:
        return jsonify({"key": key, "value": None, "updated_at": None})
    return jsonify({"key": row["key"], "value": row["value"], "updated_at": _iso(row.get("updated_at"))})


@app.route("/api/parser_status/<key>", methods=["POST"])
def api_set_parser_status(key: str):
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    value = json.dumps(data.get("value"))
    set_status(key, value)
    return jsonify({"status": "ok"})


# ---------------- Admin: secrets overview ----------------

@app.route("/api/admin/secrets", methods=["GET"])
def api_admin_secrets_overview():
    """Статус секретов для UI (без значений)."""
    admin, err = _require_admin()
    if err:
        return err

    fb = get_secret("fb_cookies_json")
    tg = get_secret("tg_session")
    pending = get_status("tg_auth_pending")

    pending_val = None
    if pending and pending.get("value"):
        try:
            pending_val = json.loads(pending["value"])
        except Exception:
            pending_val = None

    return jsonify(
        {
            "fb_cookies_updated_at": _iso(fb.get("updated_at")) if fb else None,
            "tg_session_updated_at": _iso(tg.get("updated_at")) if tg else None,
            "tg_auth_pending": pending_val,
        }
    )


@app.route("/api/admin/fb_cookies", methods=["POST"])
def api_admin_set_fb_cookies():
    """
    UI: сохранить FB cookies JSON (формат Apify cookie array).
    Тело: {"cookies_json": "[...]"} или {"cookies": [...]}.
    """
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    cookies_json = data.get("cookies_json")
    cookies = data.get("cookies")

    if cookies is not None:
        try:
            cookies_json = json.dumps(cookies, ensure_ascii=False)
        except Exception:
            return jsonify({"error": "cookies_must_be_json_serializable"}), 400

    if not cookies_json or not str(cookies_json).strip():
        return jsonify({"error": "cookies_json_required"}), 400

    try:
        parsed = json.loads(str(cookies_json))
        if not isinstance(parsed, list):
            return jsonify({"error": "cookies_json_must_be_list"}), 400
    except Exception:
        return jsonify({"error": "cookies_json_invalid"}), 400

    set_secret("fb_cookies_json", str(cookies_json))
    return jsonify({"status": "ok"})


@app.route("/api/admin/fb_cookies_dynamic", methods=["POST"])
def api_admin_update_fb_cookies_dynamic():
    """
    UI: обновить только "динамичные" значения cookies (c_user, xs, fr и т.п.).
    Тело: {"cookie_kv": "c_user=...; xs=...; fr=..."}.
    Берём сохранённый ранее fb_cookies_json, подменяем value для совпадающих key.
    """
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    raw = (data.get("cookie_kv") or "").strip()
    if not raw:
        return jsonify({"error": "cookie_kv_required"}), 400

    mapping = {}
    for part in raw.replace("\n", ";").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k:
            mapping[k] = v

    if not mapping:
        return jsonify({"error": "no_pairs"}), 400

    base = get_secret("fb_cookies_json")
    if not base or not base.get("value"):
        return jsonify({"error": "no_base_cookies"}), 400

    try:
        cookies = json.loads(base["value"])
    except Exception:
        return jsonify({"error": "stored_cookies_invalid"}), 500

    if not isinstance(cookies, list):
        return jsonify({"error": "stored_cookies_not_list"}), 500

    changed = 0
    for item in cookies:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if key in mapping:
            item["value"] = mapping[key]
            changed += 1

    if not changed:
        return jsonify(
            {"error": "no_keys_matched", "known_keys": sorted(mapping.keys())}
        ), 400

    set_secret("fb_cookies_json", json.dumps(cookies, ensure_ascii=False))
    return jsonify({"status": "ok", "updated": changed})


@app.route("/api/admin/tg_session", methods=["POST"])
def api_admin_set_tg_session_manual():
    """UI: вручную сохранить TG StringSession."""
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    session_str = (data.get("session") or "").strip()
    if not session_str:
        return jsonify({"error": "session_required"}), 400

    set_secret("tg_session", session_str)
    return jsonify({"status": "ok"})


# ---------------- Telegram login flow (semi-auto) ----------------

def _tg_api_creds():
    api_id = int(os.getenv("TG_API_ID") or os.getenv("API_ID") or "0")
    api_hash = os.getenv("TG_API_HASH") or os.getenv("API_HASH") or ""
    return api_id, api_hash


async def _tg_send_code(phone: str):
    api_id, api_hash = _tg_api_creds()
    if not api_id or not api_hash:
        raise RuntimeError("TG_API_ID / TG_API_HASH not configured")

    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()

    result = await client.send_code_request(phone)
    phone_code_hash = result.phone_code_hash

    await client.disconnect()
    return phone_code_hash


async def _tg_sign_in(phone: str, code: str, phone_code_hash: str, password: Optional[str]):
    api_id, api_hash = _tg_api_creds()
    if not api_id or not api_hash:
        raise RuntimeError("TG_API_ID / TG_API_HASH not configured")

    session = StringSession()
    client = TelegramClient(session, api_id, api_hash)
    await client.connect()

    try:
        await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
    except SessionPasswordNeededError:
        if not password:
            raise
        await client.sign_in(password=password)

    session_str = session.save()
    await client.disconnect()
    return session_str


@app.route("/api/admin/tg_auth/start", methods=["POST"])
def api_admin_tg_auth_start():
    """
    UI шаг 1: отправить код на телефон.
    Тело: {"phone": "+79990000000"}
    """
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    try:
        phone_code_hash = asyncio.run(_tg_send_code(phone))
    except Exception as e:
        logger.error("tg_auth_start: %s", e)
        return jsonify({"error": str(e)}), 500

    pending = {
        "phone": phone,
        "phone_code_hash": phone_code_hash,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    set_status("tg_auth_pending", json.dumps(pending, ensure_ascii=False))
    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_auth/confirm", methods=["POST"])
def api_admin_tg_auth_confirm():
    """
    UI шаг 2: подтвердить код (и пароль 2FA).
    Тело: {"code": "...", "password": "optional"}
    """
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip() or None

    if not code:
        return jsonify({"error": "code_required"}), 400

    pending = get_status("tg_auth_pending")
    if not pending or not pending.get("value"):
        return jsonify({"error": "no_pending_session"}), 400

    try:
        pending_val = json.loads(pending["value"])
        phone = pending_val["phone"]
        phone_code_hash = pending_val["phone_code_hash"]
    except Exception:
        return jsonify({"error": "pending_data_invalid"}), 500

    try:
        session_str = asyncio.run(_tg_sign_in(phone, code, phone_code_hash, password))
    except Exception as e:
        logger.error("tg_auth_confirm: %s", e)
        return jsonify({"error": str(e)}), 500

    set_secret("tg_session", session_str)
    set_status("tg_auth_pending", "")
    return jsonify({"status": "ok"})


# ---------------- Cron helpers (Railway Scheduled Jobs) ----------------

CRON_SECRET = os.getenv("CRON_SECRET", "")


@app.route("/cron/fb_cookies_reminder", methods=["POST", "GET"])
def cron_fb_cookies_reminder():
    if CRON_SECRET:
        provided = request.args.get("secret") or request.headers.get("X-CRON-KEY")
        if provided != CRON_SECRET:
            return jsonify({"error": "forbidden"}), 403

    fb = get_secret("fb_cookies_json")
    updated_at = fb.get("updated_at") if fb else None

    need_alert = False
    if updated_at:
        try:
            dt = updated_at
            if isinstance(dt, str):
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            if isinstance(dt, datetime):
                now = datetime.now(timezone.utc)
                if now - dt > timedelta(days=7):
                    need_alert = True
        except Exception:
            need_alert = True
    else:
        need_alert = True

    if need_alert:
        send_alert_human(
            "🔔 Напоминание:\n"
            "Обнови Facebook cookies в миниаппе (⚙️ Настройки → Facebook cookies)."
        )

    return jsonify({"status": "ok"})


@app.route("/cron/parsers_watchdog", methods=["POST", "GET"])
def cron_parsers_watchdog():
    if CRON_SECRET:
        provided = request.args.get("secret") or request.headers.get("X-CRON-KEY")
        if provided != CRON_SECRET:
            return jsonify({"error": "forbidden"}), 403

    now = datetime.now(timezone.utc)

    fb_last_ok = get_status("fb_last_ok")
    tg_last_ok = get_status("tg_last_ok")
    tg_auth_required = get_status("tg_auth_required")

    def _needs_alert(row, max_minutes: int) -> bool:
        if not row or not row.get("value"):
            return True
        try:
            ts = row["value"]
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = ts
            if not isinstance(dt, datetime):
                return True
            return (now - dt) > timedelta(minutes=max_minutes)
        except Exception:
            return True

    alerts = []

    if _needs_alert(fb_last_ok, 60):
        alerts.append("FB парсер давно не присылал статус (fb_last_ok).")

    if _needs_alert(tg_last_ok, 60):
        alerts.append("TG парсер давно не присылал статус (tg_last_ok).")

    if tg_auth_required and tg_auth_required.get("value"):
        try:
            val = json.loads(tg_auth_required["value"])
        except Exception:
            val = tg_auth_required["value"]
        alerts.append(f"TG сессия требует переавторизации: {val!r}")

    if alerts:
        send_alert_human("🔔 Watchdog:\n" + "\n".join(alerts))

    return jsonify({"status": "ok", "alerts": alerts})


# ---------------- Main ----------------

if __name__ == "__main__":
    logger.info("Инициализация БД...")
    init_db()
    logger.info("Запуск Flask на порту %s", PORT)
    app.run(host="0.0.0.0", port=PORT)
