import os
import re
import json
import hmac
import hashlib
import asyncio
import logging
import requests
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

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

bot = Bot(token=BOT_TOKEN) if BOT_TOKEN else None

ADMINS = set()
for a in (ADMINS_RAW or "").split(","):
    a = a.strip()
    if a:
        ADMINS.add(a.lstrip("@").lower())

# ---------------- Helper ----------------

def _username_norm(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    return username.strip().lstrip("@").lower()


def is_admin(username_norm: Optional[str]) -> bool:
    if not username_norm:
        return False
    return username_norm in ADMINS


# ---------------- Telegram WebApp auth (initData) ----------------

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN") or ""


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
      - проверяем подпись
      - проверяем username в ADMINS
    """
    init_data = request.headers.get("X-TG-INIT-DATA") or ""
    verified = _verify_tg_init_data(init_data)
    if not verified:
        return None

    user_raw = verified.get("user")
    if not user_raw:
        return None

    try:
        user_obj = json.loads(user_raw)
    except Exception:
        return None

    username_norm = _username_norm(user_obj.get("username"))
    if not is_admin(username_norm):
        return None

    user_id = user_obj.get("id")
    try:
        user_id = int(user_id) if user_id is not None else None
    except Exception:
        user_id = None

    return {"user_id": user_id, "username_norm": username_norm}


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


# ---------------- Access check ----------------

@app.route("/check_access", methods=["POST"])
def check_access():
    """
    Миниапп присылает { user_id, username }.
    Разрешаем:
      - если username в ADMINS
      - или если username есть в allowed_users (таблица)
    """
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
        if user_id:
            cur.execute(
                "UPDATE allowed_users SET user_id = %s, updated_at = NOW() WHERE id = %s",
                (user_id, row["id"]),
            )
            conn.commit()

        conn.close()
        return jsonify({"access_granted": True, "is_admin": False})

    conn.close()
    return jsonify({"access_granted": False, "is_admin": False})


# ---------------- Jobs ----------------

@app.route("/post", methods=["POST"])
def receive_post():
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}

    source = (data.get("source") or "").strip()
    external_id = (data.get("external_id") or "").strip()
    text = (data.get("text") or "").strip()

    if not source or not external_id or not text:
        return jsonify({"error": "source/external_id/text required"}), 400

    source_name = data.get("source_name")
    url = data.get("url")
    sender_username = data.get("sender_username")
    created_at = data.get("created_at")

    def _parse_dt(v):
        if not v:
            return None
        try:
            if isinstance(v, str):
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return None
        return None

    created_dt = _parse_dt(created_at)

    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO jobs (source, source_name, external_id, url, text, sender_username, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (external_id, source) DO NOTHING
            RETURNING id
            """,
            (source, source_name, external_id, url, text, sender_username, created_dt),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()
    return jsonify({"status": "ok", "inserted": bool(row)})


@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    archived = request.args.get("archived") == "1"
    limit = int(request.args.get("limit") or "100")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM jobs
        WHERE archived = %s
        ORDER BY received_at DESC
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
                "source_name": r.get("source_name"),
                "external_id": r["external_id"],
                "url": r.get("url"),
                "text": r.get("text"),
                "sender_username": r.get("sender_username"),
                "created_at": _iso(r.get("created_at")),
                "received_at": _iso(r.get("received_at")),
                "archived": r.get("archived", False),
                "archived_at": _iso(r.get("archived_at")),
            }
        )

    return jsonify({"jobs": jobs})


@app.route("/api/archive", methods=["POST"])
def archive_job():
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    job_id = data.get("job_id")
    archived = bool(data.get("archived", True))

    if not job_id:
        return jsonify({"error": "job_id required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    if archived:
        cur.execute(
            "UPDATE jobs SET archived = TRUE, archived_at = NOW() WHERE id = %s",
            (job_id,),
        )
    else:
        cur.execute(
            "UPDATE jobs SET archived = FALSE, archived_at = NULL WHERE id = %s",
            (job_id,),
        )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------------- Groups ----------------

@app.route("/api/groups", methods=["GET"])
def api_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, group_id, group_name, enabled, added_at
        FROM fb_groups
        WHERE enabled = TRUE
        ORDER BY id
        """
    )
    rows = cur.fetchall()
    conn.close()

    groups = []
    for row in rows:
        groups.append(
            {
                "id": row["id"],
                "group_id": row["group_id"],
                "group_name": row.get("group_name") or row["group_id"],
                "enabled": row.get("enabled", True),
                "added_at": _iso(row.get("added_at")),
            }
        )

    return jsonify({"groups": groups})


@app.route("/api/fb_groups", methods=["GET"])
def api_fb_groups():
    """
    Отдаём FB группы для FB парсера.
    Формат:
    { "groups": [ { "group_url": "...", "enabled": true, ... }, ... ] }
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, group_id, group_name, enabled, added_at
        FROM fb_groups
        WHERE group_id LIKE 'http%%facebook.com%%'
           OR group_id LIKE 'https://www.facebook.com%%'
           OR group_id LIKE '%facebook.com/groups/%'
        ORDER BY id
        """
    )
    rows = cur.fetchall()
    conn.close()

    groups = []
    for row in rows:
        groups.append(
            {
                "id": row["id"],
                "group_url": row["group_id"],
                "group_name": row.get("group_name") or row["group_id"],
                "enabled": row.get("enabled", True),
                "added_at": _iso(row.get("added_at")),
            }
        )
    return jsonify({"groups": groups})


# ---------------- Управление источниками (TG/FB) ----------------

@app.route("/api/source", methods=["POST"])
def add_source():
    admin, err = _require_admin()
    if err:
        return err

    """
    Добавление нового источника (TG канал или FB группа).
    Тело:
    {
      "group_id": "https://t.me/...",
      "group_name": "Название" (опционально)
    }
    """
    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    group_name = (data.get("group_name") or "").strip()

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO fb_groups (group_id, group_name, enabled)
            VALUES (%s, %s, TRUE)
            ON CONFLICT (group_id) DO UPDATE SET
              group_name = EXCLUDED.group_name,
              enabled = TRUE
            RETURNING id, group_id, group_name, enabled, added_at
            """,
            (group_id, group_name or group_id),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()
    return jsonify({"status": "ok", "group": row})


@app.route("/api/source/toggle", methods=["POST"])
def toggle_source():
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    enabled = bool(data.get("enabled", True))

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE fb_groups SET enabled = %s WHERE group_id = %s", (enabled, group_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/source/delete", methods=["POST"])
def delete_source():
    admin, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM fb_groups WHERE group_id = %s", (group_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------------- Allowed users (admin) ----------------

@app.route("/api/allowed_users", methods=["GET"])
def list_allowed_users():
    admin, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, user_id, updated_at FROM allowed_users ORDER BY id;")
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
    username = (data.get("username") or "").strip().lstrip("@")
    if not username:
        return jsonify({"error": "username required"}), 400

    username_norm = username.lower()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO allowed_users (username, user_id, updated_at)
        VALUES (%s, NULL, NOW())
        ON CONFLICT (username) DO UPDATE SET
            updated_at = NOW()
        RETURNING id, username, user_id, updated_at
        """,
        (username_norm,),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "user": row})


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
    return jsonify({"status": "deleted"})


# ---------------- Secrets for parsers + UI ----------------

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
    """
    Для парсеров: выставить статус/пинг.
    Авторизация: X-API-KEY == API_SECRET (если задан).
    """
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    value = str(data.get("value") or "")
    if not value:
        return jsonify({"error": "value_required"}), 400

    set_status(key, value)
    return jsonify({"status": "ok"})


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
        raise RuntimeError("TG_API_ID/TG_API_HASH not configured in miniapp")

    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()
    try:
        sent = await client.send_code_request(phone)
        return sent.phone_code_hash
    finally:
        await client.disconnect()


async def _tg_sign_in(phone: str, code: str, phone_code_hash: str, password: str | None):
    api_id, api_hash = _tg_api_creds()
    if not api_id or not api_hash:
        raise RuntimeError("TG_API_ID/TG_API_HASH not configured in miniapp")

    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()
    try:
        try:
            await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
        except SessionPasswordNeededError:
            if not password:
                raise
            await client.sign_in(password=password)

        session_str = client.session.save()
        return session_str
    finally:
        await client.disconnect()


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
        logger.error("TG auth start error: %s", e)
        return jsonify({"error": "tg_send_code_failed", "details": str(e)}), 500

    pending = {
        "phone": phone,
        "phone_code_hash": phone_code_hash,
        "started_at": datetime.utcnow().isoformat() + "Z",
    }
    set_status("tg_auth_pending", json.dumps(pending, ensure_ascii=False))
    return jsonify({"status": "code_sent"})


@app.route("/api/admin/tg_auth/confirm", methods=["POST"])
def api_admin_tg_auth_confirm():
    """
    UI шаг 2: подтвердить код, создать StringSession и сохранить.
    Тело: {"code": "12345", "password": "..."(опц.)}
    """
    admin, err = _require_admin()
    if err:
        return err

    pending_row = get_status("tg_auth_pending")
    if not pending_row or not pending_row.get("value"):
        return jsonify({"error": "no_pending_auth"}), 400

    try:
        pending = json.loads(pending_row["value"])
    except Exception:
        return jsonify({"error": "pending_corrupted"}), 500

    phone = pending.get("phone")
    phone_code_hash = pending.get("phone_code_hash")
    if not phone or not phone_code_hash:
        return jsonify({"error": "pending_incomplete"}), 500

    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip() or None
    if not code:
        return jsonify({"error": "code_required"}), 400

    try:
        session_str = asyncio.run(_tg_sign_in(phone, code, phone_code_hash, password))
    except SessionPasswordNeededError:
        return jsonify({"error": "2fa_required"}), 400
    except Exception as e:
        logger.error("TG auth confirm error: %s", e)
        return jsonify({"error": "tg_sign_in_failed", "details": str(e)}), 500

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

    row = get_secret("fb_cookies_json")
    if not row or not row.get("updated_at"):
        send_alert_human("❗️Facebook cookies ещё не заданы. Зайди в ⚙️ Настройки → Аккаунты и вставь cookies JSON.")
        return jsonify({"status": "alert_sent", "reason": "missing"})

    updated_at = row.get("updated_at")
    try:
        age_days = (datetime.utcnow() - updated_at).total_seconds() / 86400.0
    except Exception:
        age_days = 0

    if age_days >= 6:
        send_alert_human(
            f"⏰ Напоминание: пора обновить Facebook cookies (прошло ~{int(age_days)} дн).\\n"
            "Открой миниапп → ⚙️ Настройки → Аккаунты → Facebook cookies."
        )
        return jsonify({"status": "alert_sent", "age_days": age_days})

    return jsonify({"status": "ok", "age_days": age_days})


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------- Точка входа ----------------

if __name__ == "__main__":
    logger.info("Инициализация БД...")
    init_db()
    logger.info("Запуск Flask на порту %s", PORT)
    app.run(host="0.0.0.0", port=PORT)
