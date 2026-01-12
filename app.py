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
import httpx
from telegram import Bot
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError,
    AuthKeyUnregisteredError,
    SessionRevokedError,
)

from db import get_conn, init_db, get_secret, set_secret, get_status, set_status

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("miniapp")

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

PORT = int(os.getenv("PORT", "8080"))

# ---- Telegram / бот / админы ----

TG_API_ID_DEFAULT = 34487940
TG_API_HASH_DEFAULT = "6f1242a8c3796d44fb761364b35a83f0"

BOT_TOKEN_DEFAULT = "7952407611:AAEG9eqd6KBmmatspCgpfx2bZtcU1YcdmWI"
ADMIN_CHAT_ID_DEFAULT = "794618749"

BOT_TOKEN = (
    os.getenv("TELEGRAM_BOT_TOKEN")
    or os.getenv("BOT_TOKEN")
    or BOT_TOKEN_DEFAULT
)
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID") or ADMIN_CHAT_ID_DEFAULT

ADMINS_RAW = os.getenv("ADMINS", "")

API_SECRET = os.getenv("API_SECRET", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ==== rate-limit для алертов (по умолчанию 1 раз в час) ====
ALERT_RATE_LIMIT_SECONDS = int(os.getenv("ALERT_RATE_LIMIT_SECONDS") or "3600")
_last_alert_sent_at: dict[str, datetime] = {}
# ==========================================================

TELEGRAM_BOT_TOKEN = BOT_TOKEN

# Внешний сервис для авторизации в Telegram
TG_AUTH_SERVICE_URL = os.getenv("TG_AUTH_SERVICE_URL", "").rstrip("/")
TG_AUTH_SERVICE_TOKEN = os.getenv("TG_AUTH_SERVICE_TOKEN", "")

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


def _verify_tg_init_data(init_data: str) -> Optional[dict]:
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
    Определяем админа:
    1) пробуем валидировать Telegram WebApp initData;
    2) если не получилось / нет initData — падаем на X-ADMIN-USERNAME.
    """
    # 1. Пробуем initData от Telegram
    init_data = request.headers.get("X-TG-INIT-DATA") or ""
    if init_data:
        verified = _verify_tg_init_data(init_data)
        if verified:
            user_raw = verified.get("user")
            user_obj = None
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
        else:
            # Если подпись не сошлась — логируем и пробуем X-ADMIN-USERNAME.
            logger.warning("init_data verification failed, falling back to X-ADMIN-USERNAME")

    # 2. Фоллбек по заголовку X-ADMIN-USERNAME
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


# ---- Алерты в телеграм ----

def send_alert_human(text: str):
    """
    Отправка уведомления админу в Telegram.

    Rate-limit: одно и то же сообщение (по точному тексту) не чаще,
    чем раз в ALERT_RATE_LIMIT_SECONDS (по умолчанию 3600 сек == 1 час).
    """
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        logger.warning("No bot/admin chat configured, alert skipped: %s", text)
        return

    now = datetime.now(timezone.utc)
    key = (text or "").strip()

    last = _last_alert_sent_at.get(key)
    if last is not None and now - last < timedelta(seconds=ALERT_RATE_LIMIT_SECONDS):
        # Уже слали такое же сообщение недавно — пропускаем
        logger.info(
            "Alert skipped due to rate limit (%.0f seconds since last): %r",
            (now - last).total_seconds(),
            key,
        )
        return

    _last_alert_sent_at[key] = now

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        resp = httpx.post(
            url,
            json={"chat_id": ADMIN_CHAT_ID, "text": text},
            timeout=10.0,
        )
        if resp.status_code != 200:
            logger.error(
                "Failed to send alert: HTTP %s, body=%s",
                resp.status_code,
                resp.text[:500],
            )
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


# ---- Статическая страница (миниапп) ----

@app.route("/")
def index_page():
    return send_from_directory("static", "index.html")


# ---- Jobs (вакансии) ----

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


# ---- Доступ (allowed_users) ----

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


# ---- Группы (fb_groups) ----

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


@app.route("/api/fb_groups", methods=["GET"])
def api_get_fb_groups():
    return api_get_groups()


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


# ---- Parser secrets & status ----

@app.route("/api/parser_secrets/<key>", methods=["GET"])
def api_get_parser_secret(key: str):
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


# ---- Admin: обзор секретов ----

@app.route("/api/admin/secrets", methods=["GET"])
def api_admin_secrets_overview():
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


# ---- Admin: FB cookies ----

@app.route("/api/admin/fb_cookies", methods=["POST"])
def api_admin_set_fb_cookies():
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
    Обновление только динамичных ключей из одной строки:
    xs=AAA; sb=BBB; fr=CCC ...
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


# ---- Admin: Telegram session (ручной ввод) ----

@app.route("/api/admin/tg_session", methods=["POST"])
def api_admin_set_tg_session_manual():
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    session_str = (data.get("session") or "").strip()
    if not session_str:
        return jsonify({"error": "session_required"}), 400

    set_secret("tg_session", session_str)
    return jsonify({"status": "ok"})


# ---- Проверка активности TG-сессии ----

def _tg_api_creds():
    raw_id = os.getenv("TG_API_ID") or os.getenv("API_ID")
    if raw_id:
        try:
            api_id = int(raw_id)
        except Exception:
            api_id = TG_API_ID_DEFAULT
    else:
        api_id = TG_API_ID_DEFAULT

    api_hash = os.getenv("TG_API_HASH") or os.getenv("API_HASH") or TG_API_HASH_DEFAULT
    return api_id, api_hash


async def _tg_check_session_active():
    api_id, api_hash = _tg_api_creds()
    if not api_id or not api_hash:
        return {"ok": False, "reason": "no_api_creds", "me": None}

    row = get_secret("tg_session")
    if not row or not row.get("value"):
        return {"ok": False, "reason": "no_session_stored", "me": None}

    session_str = row["value"]

    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    await client.connect()
    try:
        me = await client.get_me()
        if not me:
            result = {"ok": False, "reason": "not_authorized", "me": None}
        else:
            info = {
                "id": me.id,
                "username": me.username,
                "first_name": me.first_name,
                "bot": bool(getattr(me, "bot", False)),
            }
            result = {"ok": True, "reason": None, "me": info}
    except (AuthKeyUnregisteredError, SessionRevokedError):
        result = {"ok": False, "reason": "session_revoked", "me": None}
    except Exception as e:
        result = {"ok": False, "reason": str(e), "me": None}
    finally:
        await client.disconnect()
    return result


@app.route("/api/admin/tg_session/check", methods=["GET"])
def api_admin_tg_session_check():
    admin, err = _require_admin()
    if err:
        return err

    try:
        result = asyncio.run(_tg_check_session_active())
    except Exception as e:
        logger.error("tg_session_check error: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify(result)


# ---- Telegram auth через внешний tg_auth_service ----

def _call_tg_auth_service(path: str, payload: dict) -> tuple[int, dict]:
    """
    Синхронный вызов внешнего tg_auth_service.
    Возвращает (status_code, json_dict).
    """
    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        raise RuntimeError("auth_service_not_configured")

    url = TG_AUTH_SERVICE_URL + path
    headers = {"Authorization": f"Bearer {TG_AUTH_SERVICE_TOKEN}"}

    resp = httpx.post(url, json=payload, headers=headers, timeout=30.0)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data


@app.route("/api/admin/tg_auth/start", methods=["POST"])
def api_admin_tg_auth_start():
    """
    Шаг 1: запросить отправку кода через внешний tg_auth_service.
    Тело: {"phone": "+7999..."}
    """
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    logger.info("tg_auth_start requested by %s for phone=%s", admin["username_norm"], phone)

    try:
        status, result = _call_tg_auth_service("/auth/start", {"phone": phone})
    except Exception as e:
        logger.error("tg_auth_start: http error: %s", e)
        return jsonify({"error": "http_error", "details": str(e)}), 500

    if status != 200 or not result.get("ok"):
        msg = result.get("error") or f"HTTP {status}"
        logger.error("tg_auth_start: service error: %s (result=%r)", msg, result)
        return jsonify({"error": msg}), 400

    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_auth/confirm", methods=["POST"])
def api_admin_tg_auth_confirm():
    """
    Шаг 2: подтвердить код через внешний tg_auth_service и сохранить StringSession.
    Тело: {"phone": "+7999...", "code": "...", "password": "optional"}
    """
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip() or None

    if not phone:
        return jsonify({"error": "phone_required"}), 400
    if not code:
        return jsonify({"error": "code_required"}), 400

    logger.info(
        "tg_auth_confirm requested by %s for phone=%s",
        admin["username_norm"],
        phone,
    )

    try:
        status, result = _call_tg_auth_service(
            "/auth/confirm",
            {"phone": phone, "code": code, "password": password},
        )
    except Exception as e:
        logger.error("tg_auth_confirm: http error: %s", e)
        return jsonify({"error": "http_error", "details": str(e)}), 500

    if status != 200 or not result.get("ok"):
        msg = result.get("error") or f"HTTP {status}"
        logger.error("tg_auth_confirm: service error: %s (result=%r)", msg, result)
        return jsonify({"error": msg}), 400

    session_str = result.get("session")
    if not session_str:
        return jsonify({"error": "no_session_returned"}), 500

    set_secret("tg_session", session_str)
    set_status("tg_auth_pending", "")

    logger.info("tg_auth_confirm: tg_session saved, length=%d", len(session_str))
    return jsonify({"status": "ok"})


# ---- Cron / напоминания ----

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


# ---- main ----

if __name__ == "__main__":
    logger.info("Инициализация БД...")
    init_db()
    logger.info("Запуск Flask на порту %s", PORT)
    logger.info(
        "TG_API_ID_DEFAULT=%s, BOT_TOKEN set=%s, ADMIN_CHAT_ID=%s",
        TG_API_ID_DEFAULT,
        bool(BOT_TOKEN),
        ADMIN_CHAT_ID,
    )
    app.run(host="0.0.0.0", port=PORT)
