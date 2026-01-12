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

TG_API_ID = int(os.getenv("TG_API_ID", TG_API_ID_DEFAULT))
TG_API_HASH = os.getenv("TG_API_HASH", TG_API_HASH_DEFAULT)

# Внешний сервис для авторизации в Telegram
TG_AUTH_SERVICE_URL = os.getenv("TG_AUTH_SERVICE_URL", "").rstrip("/")
TG_AUTH_SERVICE_TOKEN = os.getenv("TG_AUTH_SERVICE_TOKEN", "")

bot = Bot(token=BOT_TOKEN) if BOT_TOKEN else None

ADMINS_RAW = os.getenv("ADMINS", "")
ADMINS = set()
for a in (ADMINS_RAW or "").split(","):
    a = a.strip()
    if a:
        ADMINS.add(a.lstrip("@").lower())


def _username_norm(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    return username.lstrip("@").lower()


# ---- верификация initData из Telegram ----

API_SECRET = os.getenv("API_SECRET", "")  # секрет с BotFather (для проверки initData)


def verify_telegram_init_data(init_data_str: str) -> Optional[dict]:
    """
    Проверка подписи initData по алгоритму из доки Telegram.
    Возвращает dict с данными или None, если подпись невалидна.
    """
    if not init_data_str or not API_SECRET:
        return None

    try:
        parsed = dict(parse_qsl(init_data_str, strict_parsing=True))
        hash_str = parsed.pop("hash", None)
        if not hash_str:
            return None

        data_check_arr = [f"{k}={v}" for k, v in sorted(parsed.items())]
        data_check_string = "\n".join(data_check_arr)

        secret_key = hashlib.sha256(API_SECRET.encode()).digest()
        hmac_string = hmac.new(secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256).hexdigest()

        if hmac_string != hash_str:
            return None

        return parsed
    except Exception:
        logger.exception("init_data verification error")
        return None


def get_current_user():
    """
    Пытаемся достать пользователя из Telegram initData.
    Если не получилось — вернём None.
    """
    init_data = request.headers.get("X-TG-INIT-DATA") or ""
    if not init_data:
        return None

    parsed = verify_telegram_init_data(init_data)
    if not parsed:
        logger.warning("init_data verification failed, falling back to X-ADMIN-USERNAME")
        return None

    try:
        user_json = parsed.get("user")
        if not user_json:
            return None
        return json.loads(user_json)
    except Exception:
        logger.exception("Failed to parse user from init_data")
        return None


def _require_admin():
    """
    Проверка, что текущий пользователь — админ.
    Сначала берём init_data, если нет/невалидно — X-ADMIN-USERNAME.
    """
    user = get_current_user()
    if user and user.get("username"):
        uname = _username_norm(user["username"])
        if uname in ADMINS:
            return uname, None

    # fallback: заголовок X-ADMIN-USERNAME от фронта
    fallback = request.headers.get("X-ADMIN-USERNAME", "").strip()
    if fallback:
        uname = _username_norm(fallback)
        if uname in ADMINS:
            return uname, None

    return None, (jsonify({"error": "admin_forbidden"}), 403)


# ---- утилиты ----

def send_alert_human(text: str):
    """
    Отправка уведомления в Telegram-бота (в ADMIN_CHAT_ID).
    Используем httpx (sync), чтобы не мучиться с event loop.
    """
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        logger.warning("No bot/admin chat configured, alert skipped: %s", text)
        return

    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": ADMIN_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
        }
        resp = httpx.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Alert sent to admin chat: %s", text)
    except Exception as e:
        logger.error("Failed to send alert: %s", e)


def get_json():
    return request.get_json(silent=True) or {}


# ---- статика ----

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---- access / allowed_users ----

@app.route("/check_access", methods=["POST"])
def check_access():
    data = get_json()
    user_id = data.get("user_id")
    username = (data.get("username") or "").lstrip("@").lower()

    res = {"access_granted": False, "is_admin": False}

    if username and username in ADMINS:
        res["access_granted"] = True
        res["is_admin"] = True
        return jsonify(res)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM allowed_users WHERE username = %s LIMIT 1",
            (username,),
        )
        allowed = cur.fetchone() is not None

    res["access_granted"] = allowed
    res["is_admin"] = username in ADMINS
    return jsonify(res)


@app.route("/api/allowed_users", methods=["GET"])
def get_allowed_users():
    admin, err = _require_admin()
    if err:
        return err

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, user_id FROM allowed_users ORDER BY id ASC"
        )
        rows = cur.fetchall()

    users = [
        {"id": r[0], "username": r[1], "user_id": r[2]}
        for r in rows
    ]
    return jsonify({"users": users})


@app.route("/api/allowed_users", methods=["POST"])
def add_allowed_user():
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    username = (data.get("username") or "").strip().lstrip("@").lower()
    if not username:
        return jsonify({"error": "username_required"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO allowed_users (username)
            VALUES (%s)
            ON CONFLICT (username) DO NOTHING
            """,
            (username,),
        )
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/allowed_users/<int:user_id>", methods=["DELETE"])
def delete_allowed_user(user_id):
    admin, err = _require_admin()
    if err:
        return err

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM allowed_users WHERE id = %s", (user_id,))
        conn.commit()

    return jsonify({"status": "ok"})


# ---- groups ----

@app.route("/api/groups", methods=["GET"])
def get_groups():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, created_at
            FROM groups
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()

    groups = []
    for r in rows:
        groups.append(
            {
                "id": r[0],
                "group_id": r[1],
                "group_name": r[2],
                "enabled": r[3],
                "created_at": r[4].isoformat() if r[4] else None,
            }
        )
    return jsonify({"groups": groups})


@app.route("/api/groups", methods=["POST"])
def add_group():
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    group_id = (data.get("group_id") or "").strip()
    group_name = (data.get("group_name") or "").strip()
    if not group_id:
        return jsonify({"error": "group_id_required"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO groups (group_id, group_name, enabled)
            VALUES (%s, %s, TRUE)
            """,
            (group_id, group_name or None),
        )
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/groups/<int:gid>/toggle", methods=["POST"])
def toggle_group(gid):
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    enabled = bool(data.get("enabled", True))

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE groups SET enabled = %s WHERE id = %s",
            (enabled, gid),
        )
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/groups/<int:gid>", methods=["DELETE"])
def delete_group(gid):
    admin, err = _require_admin()
    if err:
        return err

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM groups WHERE id = %s", (gid,))
        conn.commit()

    return jsonify({"status": "ok"})


# ---- jobs ----

def _job_to_dict(row):
    return {
        "id": row[0],
        "source": row[1],
        "source_name": row[2],
        "text": row[3],
        "url": row[4],
        "sender_username": row[5],
        "created_at": row[6].isoformat() if row[6] else None,
        "received_at": row[7].isoformat() if row[7] else None,
        "archived": row[8],
    }


@app.route("/api/jobs", methods=["GET"])
def get_jobs():
    limit = int(request.args.get("limit", 50))
    archived = request.args.get("archived", "false").lower() == "true"

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, source, source_name, text, url, sender_username,
                   created_at, received_at, archived
            FROM jobs
            WHERE archived = %s
            ORDER BY received_at DESC, id DESC
            LIMIT %s
            """,
            (archived, limit),
        )
        rows = cur.fetchall()

    jobs = [_job_to_dict(r) for r in rows]
    return jsonify({"jobs": jobs})


@app.route("/api/jobs", methods=["POST"])
def add_job():
    data = get_json()
    source = (data.get("source") or "").strip()
    text = (data.get("text") or "").strip()
    if not source or not text:
        return jsonify({"error": "source_and_text_required"}), 400

    source_name = (data.get("source_name") or "").strip() or None
    url = (data.get("url") or "").strip() or None
    sender_username = (data.get("sender_username") or "").strip() or None
    created_at = data.get("created_at")
    created_dt = None
    if created_at:
        try:
            created_dt = datetime.fromisoformat(created_at)
        except Exception:
            created_dt = None

    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO jobs (source, source_name, text, url, sender_username,
                              created_at, received_at, archived)
            VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE)
            RETURNING id
            """,
            (source, source_name, text, url, sender_username, created_dt, now),
        )
        job_id = cur.fetchone()[0]
        conn.commit()

    # уведомление в бота о новой вакансии
    try:
        src_label = source_name or source
        msg_lines = [
            "🔔 Новая вакансия",
            f"Источник: <b>{src_label}</b>",
        ]
        if sender_username:
            msg_lines.append(f"Автор: @{sender_username}")
        msg_lines.append("")
        if len(text) > 200:
            msg_lines.append(text[:200] + "…")
        else:
            msg_lines.append(text)
        if url:
            msg_lines.append("")
            msg_lines.append(url)

        send_alert_human("\n".join(msg_lines))
    except Exception as e:
        logger.error("Failed to send new job alert: %s", e)

    return jsonify({"status": "ok", "id": job_id})


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def archive_job(job_id):
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    archived = bool(data.get("archived", True))

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE jobs SET archived = %s WHERE id = %s",
            (archived, job_id),
        )
        conn.commit()

    return jsonify({"status": "ok"})


# ---- parser secrets / statuses ----

@app.route("/api/parser_secrets/<key>", methods=["GET"])
def get_parser_secret(key):
    with get_conn() as conn:
        value = get_secret(conn, key)
    return jsonify({"key": key, "value": value})


@app.route("/api/admin/parser_secrets/<key>", methods=["POST"])
def set_parser_secret(key):
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    value = data.get("value")
    with get_conn() as conn:
        set_secret(conn, key, value)
        conn.commit()
    return jsonify({"status": "ok"})


# Специальный ключ fb_cookies_json (полный JSON)
@app.route("/api/admin/fb_cookies", methods=["POST"])
def set_fb_cookies():
    """
    Сохраняем ПОЛНЫЙ JSON cookies из Apify в ключ fb_cookies_json.
    Тело: {"value": "[{...}, ...]"}
    """
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    val = data.get("value")
    if not val:
        return jsonify({"error": "value_required"}), 400

    # просто сохраняем как строку; валидацию JSON не навязываем
    with get_conn() as conn:
        set_secret(conn, "fb_cookies_json", val)
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/parser_secrets/fb_cookies_json", methods=["GET"])
def get_fb_cookies_json():
    with get_conn() as conn:
        val = get_secret(conn, "fb_cookies_json")
    return jsonify({"key": "fb_cookies_json", "value": val})


@app.route("/api/parser_status/<key>", methods=["POST"])
def set_parser_status(key):
    data = get_json()
    value = data.get("value")
    with get_conn() as conn:
        set_status(conn, key, value)
        conn.commit()
    return jsonify({"status": "ok"})


@app.route("/api/parser_status/<key>", methods=["GET"])
def get_parser_status(key):
    with get_conn() as conn:
        val = get_status(conn, key)
    return jsonify({"key": key, "value": val})


@app.route("/api/alert", methods=["POST"])
def api_alert():
    data = get_json()
    text = data.get("text") or ""
    if not text:
        return jsonify({"error": "text_required"}), 400

    send_alert_human(text)
    return jsonify({"status": "ok"})


# ---- admin overview ----

@app.route("/api/admin/secrets", methods=["GET"])
def admin_secrets_overview():
    admin, err = _require_admin()
    if err:
        return err

    with get_conn() as conn:
        fb_cookies_updated_at = get_status(conn, "fb_cookies_updated_at")
        tg_session_updated_at = get_status(conn, "tg_session_updated_at")
        tg_auth_pending = get_status(conn, "tg_auth_pending")

    return jsonify(
        {
            "fb_cookies_updated_at": fb_cookies_updated_at,
            "tg_session_updated_at": tg_session_updated_at,
            "tg_auth_pending": json.loads(tg_auth_pending)
            if tg_auth_pending
            else None,
        }
    )


# ---- Telegram auth через внешний сервис ----

def _auth_service_headers():
    headers = {"Content-Type": "application/json"}
    if TG_AUTH_SERVICE_TOKEN:
        headers["X-Auth-Token"] = TG_AUTH_SERVICE_TOKEN
    return headers


@app.route("/api/admin/tg_auth/start", methods=["POST"])
def tg_auth_start():
    """
    Старт авторизации: просим внешний сервис отправить код.
    Тело: {"phone": "+7999..."}
    """
    admin, err = _require_admin()
    if err:
        return err

    if not TG_AUTH_SERVICE_URL:
        return jsonify({"error": "auth_service_not_configured"}), 500

    data = get_json()
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    logger.info("tg_auth_start requested by %s for phone=%s", admin, phone)

    try:
        resp = httpx.post(
            TG_AUTH_SERVICE_URL + "/auth/start",
            json={"phone": phone},
            headers=_auth_service_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
    except httpx.HTTPError as e:
        logger.error("tg_auth_start: http error: %s", e)
        return jsonify({"error": "auth_service_http_error"}), 500

    if not result.get("ok"):
        logger.error("tg_auth_start: service error: %s", result)
        return jsonify({"error": result.get("error", "auth_service_error")}), 400

    # сохраняем pending state
    pending = {
        "phone": phone,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    with get_conn() as conn:
        set_status(conn, "tg_auth_pending", json.dumps(pending))
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_auth/confirm", methods=["POST"])
def tg_auth_confirm():
    """
    Подтверждение кода.
    Тело: {"phone": "+7999...", "code": "12345", "password": "optional"}
    """
    admin, err = _require_admin()
    if err:
        return err

    if not TG_AUTH_SERVICE_URL:
        return jsonify({"error": "auth_service_not_configured"}), 500

    data = get_json()
    phone = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip() or None

    if not phone or not code:
        return jsonify({"error": "phone_and_code_required"}), 400

    try:
        resp = httpx.post(
            TG_AUTH_SERVICE_URL + "/auth/confirm",
            json={"phone": phone, "code": code, "password": password},
            headers=_auth_service_headers(),
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()
    except httpx.HTTPError as e:
        logger.error("tg_auth_confirm: http error: %s", e)
        return jsonify({"error": "auth_service_http_error"}), 500

    if not result.get("ok"):
        err_code = result.get("error", "auth_service_error")
        logger.error("tg_auth_confirm error: %s", result)
        return jsonify({"error": err_code}), 400

    session = result.get("session")
    if not session:
        return jsonify({"error": "no_session_returned"}), 500

    # сохраняем сессию и статус
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        set_secret(conn, "tg_session", session)
        set_status(conn, "tg_session_updated_at", now)
        set_status(conn, "tg_auth_pending", None)
        conn.commit()

    logger.info("tg_auth_confirm: new session saved at %s", now)

    return jsonify({"status": "ok"})


# ---- ручное управление TG-сессией ----

@app.route("/api/admin/tg_session", methods=["POST"])
def admin_set_tg_session():
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    session = (data.get("session") or "").strip()
    if not session:
        return jsonify({"error": "session_required"}), 400

    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        set_secret(conn, "tg_session", session)
        set_status(conn, "tg_session_updated_at", now)
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_session/check", methods=["GET"])
def admin_check_tg_session():
    admin, err = _require_admin()
    if err:
        return err

    with get_conn() as conn:
        session_str = get_secret(conn, "tg_session")

    if not session_str:
        return jsonify({"ok": False, "reason": "no_session"})

    async def _check():
        try:
            async with TelegramClient(
                StringSession(session_str),
                TG_API_ID,
                TG_API_HASH,
            ) as client:
                me = await client.get_me()
                return {"ok": True, "me": {"id": me.id, "username": me.username}}
        except (AuthKeyUnregisteredError, SessionRevokedError):
            return {"ok": False, "reason": "session_invalid"}
        except Exception as e:
            logger.exception("check_tg_session error")
            return {"ok": False, "reason": str(e)}

    result = asyncio.run(_check())
    return jsonify(result)


# ---- watchdog endpoint для парсеров ----

@app.route("/api/watchdog", methods=["POST"])
def watchdog():
    """
    Парсеры могут сюда слать периодические статусы.
    Например:
      {"source": "tg_parser", "status": "auth_error"}
    """
    data = get_json()
    source = data.get("source") or "unknown"
    status = data.get("status") or "unknown"
    ts = datetime.now(timezone.utc).isoformat()

    key = f"watchdog:{source}"
    with get_conn() as conn:
        set_status(conn, key, json.dumps({"status": status, "ts": ts}))
        conn.commit()

    alerts = []
    # пример: если tg_parser сообщил, что нет авторизации
    if source == "tg_parser" and status == "auth_required":
        alerts.append(
            "🔔 tg_parser:\nTelegram парсер: сессия не авторизована.\n"
            "Открой миниапп → ⚙️ Настройки → Аккаунты → Telegram сессия и пересоздай её."
        )

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
