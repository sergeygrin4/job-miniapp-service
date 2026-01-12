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

from db import get_conn, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - miniapp - %(levelname)s - %(message)s",
)
logger = logging.getLogger("miniapp")

# ---------------- Конфиг из окружения ----------------

API_SECRET = os.getenv("API_SECRET", "")

# Telegram MiniApp verification secret
TG_BOT_TOKEN = os.getenv("BOT_TOKEN") or os.getenv("TELEGRAM_BOT_TOKEN") or ""
TG_BOT_API = os.getenv("BOT_API", "https://api.telegram.org")
TELEGRAM_WEBAPP_SECRET = os.getenv("API_SECRET", "")

ALLOWED_USERNAMES_ENV = os.getenv("ALLOWED_USERNAMES", "")
ADMINS_ENV = os.getenv("ADMINS", "")

TG_API_ID_DEFAULT = int(os.getenv("TG_API_ID") or os.getenv("API_ID") or "34487940")
TG_API_HASH_DEFAULT = os.getenv("TG_API_HASH") or os.getenv(
    "API_HASH"
) or "6f1242a8c3796d44fb761364b35a83f0"

PARSER_ALERT_INTERVAL_MINUTES = int(os.getenv("PARSER_ALERT_INTERVAL_MINUTES", "60"))

# Telegram bot for alerts
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or TG_BOT_TOKEN
ADMIN_CHAT_ID = int(os.getenv("MANAGER_CHAT_ID") or os.getenv("ADMIN_CHAT_ID") or "0")

if TG_API_ID_DEFAULT:
    logger.info(
        "TG_API_ID_DEFAULT=%s, BOT_TOKEN set=%s, ADMIN_CHAT_ID=%s",
        TG_API_ID_DEFAULT,
        bool(TELEGRAM_BOT_TOKEN),
        ADMIN_CHAT_ID,
    )

bot: Optional[Bot] = None
if TELEGRAM_BOT_TOKEN:
    try:
        bot = Bot(token=TELEGRAM_BOT_TOKEN, base_url=TG_BOT_API)
    except Exception as e:
        logger.error("Failed to init Telegram Bot: %s", e)
        bot = None

# ---------------- Flask init ----------------

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)


# ---------------- DB init ----------------

@app.before_first_request
def _init_db():
    logger.info("Инициализация БД...")
    init_db()
    logger.info("БД инициализирована")


# ---------------- Helpers ----------------

def _username_norm(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    username = username.strip().lstrip("@")
    if not username:
        return None
    return username


def _get_admins() -> set[str]:
    res = set()
    if ADMINS_ENV:
        for part in ADMINS_ENV.split(","):
            u = _username_norm(part)
            if u:
                res.add(u.lower())
    return res


def _get_allowed_from_env() -> set[str]:
    res = set()
    if ALLOWED_USERNAMES_ENV:
        for part in ALLOWED_USERNAMES_ENV.split(","):
            u = _username_norm(part)
            if u:
                res.add(u.lower())
    return res


ADMINS = _get_admins()
ALLOWED_FROM_ENV = _get_allowed_from_env()


def is_admin(username: Optional[str]) -> bool:
    if not username:
        return False
    return username.lower() in ADMINS


def is_allowed_env(username: Optional[str]) -> bool:
    if not username:
        return False
    return username.lower() in ALLOWED_FROM_ENV


def verify_telegram_webapp(init_data: str) -> Optional[dict]:
    """
    Проверка подписи MiniApp initData по токену бота.
    Возвращает dict с initData или None, если подпись невалидна.
    """
    if not TG_BOT_TOKEN:
        logger.warning("TG_BOT_TOKEN not set, skipping init_data verification")
        return None

    try:
        parsed = dict(parse_qsl(init_data, strict_parsing=True))
    except Exception:
        logger.exception("Failed to parse init_data")
        return None

    hash_value = parsed.pop("hash", None)
    if not hash_value:
        logger.warning("No hash in init_data")
        return None

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
    secret_key = hmac.new(
        f"WebAppData{TG_BOT_TOKEN}".encode(), digestmod=hashlib.sha256
    ).digest()
    computed_hash = hmac.new(
        secret_key, data_check_string.encode(), hashlib.sha256
    ).hexdigest()

    if computed_hash != hash_value:
        logger.warning("init_data hash mismatch")
        return None

    return parsed


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
    username = _username_norm(data.get("username"))

    if username and is_admin(username):
        return jsonify({"access": "admin"})

    # Сначала проверим env-allowed (backdoor)
    if username and is_allowed_env(username):
        return jsonify({"access": "allowed"})

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT 1 FROM allowed_users WHERE username = %s OR user_id = %s LIMIT 1",
            (username, user_id),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if row:
        return jsonify({"access": "allowed"})

    return jsonify({"access": "denied"})


# ---------------- Static / UI ----------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ---------------- Groups ----------------

@app.route("/api/groups", methods=["GET"])
def api_list_groups():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, group_id, name, enabled, created_at FROM groups ORDER BY id DESC"
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    groups = []
    for r in rows:
        groups.append(
            {
                "id": r["id"],
                "group_id": r["group_id"],
                "name": r["name"],
                "enabled": r["enabled"],
                "created_at": r["created_at"].isoformat()
                if r["created_at"]
                else None,
            }
        )
    return jsonify({"groups": groups})


@app.route("/api/groups", methods=["POST"])
def api_add_group():
    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    name = (data.get("name") or "").strip()

    if not group_id:
        return jsonify({"error": "group_id_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO groups (group_id, name, enabled, created_at)
            VALUES (%s, %s, TRUE, NOW())
            RETURNING id
            """,
            (group_id, name or None),
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "ok", "id": row["id"]})


@app.route("/api/groups/<int:group_id>", methods=["DELETE"])
def api_delete_group(group_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM groups WHERE id = %s", (group_id,))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "ok"})


@app.route("/api/groups/<int:group_id>/toggle", methods=["POST"])
def api_toggle_group(group_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE groups SET enabled = NOT enabled WHERE id = %s RETURNING enabled",
            (group_id,),
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "not_found"}), 404

    return jsonify({"status": "ok", "enabled": row["enabled"]})


# ---------------- Jobs ----------------

def _clean_text(text: str) -> str:
    text = (text or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text


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
        return jsonify({"error": "source, external_id, text required"}), 400

    text = _clean_text(text)

    # created_at may be iso string
    created_dt = None
    if created_at:
        try:
            # normalize Z
            if isinstance(created_at, str) and created_at.endswith("Z"):
                created_at = created_at[:-1] + "+00:00"
            created_dt = datetime.fromisoformat(created_at)
        except Exception:
            created_dt = None

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO jobs (source, source_name, external_id, url, text, sender_username, created_at, received_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (external_id, source) DO NOTHING
            RETURNING id
            """,
            (
                source,
                source_name or None,
                external_id,
                url or None,
                text,
                sender_username or None,
                created_dt,
            ),
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    # если запись действительно вставлена (а не конфликт по external_id+source) —
    # шлём уведомление в Telegram-бота
    if row:
        try:
            preview = text
            if len(preview) > 400:
                preview = preview[:400].rstrip() + "…"

            group_label = source_name or source
            author_label = sender_username or ""

            lines = [
                "🆕 Новая вакансия",
                "",
                preview,
            ]

            if group_label:
                lines.append(f"Группа: {group_label}")
            if author_label:
                if not author_label.startswith("@"):
                    author_label = "@" + author_label
                lines.append(f"Автор: {author_label}")

            if url:
                lines.append(f"Открыть пост: {url}")

            send_alert_human("\n".join(lines))
        except Exception as e:
            logger.error("Failed to send new job alert: %s", e)

        return jsonify({"status": "ok", "inserted": True, "id": row["id"]})
    return jsonify({"status": "ok", "inserted": False})


@app.route("/api/jobs", methods=["GET"])
def api_list_jobs():
    """
    Параметры:
      - limit (по умолчанию 50)
      - offset (по умолчанию 0)
      - archived: "true"/"false" (по
      умолчанию false)
      - q: поиск по тексту (ILIKE)
      - source: фильтр по source
    """
    limit = int(request.args.get("limit") or 50)
    offset = int(request.args.get("offset") or 0)
    archived_str = request.args.get("archived") or "false"
    archived = archived_str.lower() == "true"
    q = (request.args.get("q") or "").strip()
    source_filter = (request.args.get("source") or "").strip()

    conn = get_conn()
    cur = conn.cursor()
    try:
        sql = """
            SELECT id, source, source_name, external_id, url, text, sender_username,
                   created_at, received_at, archived
            FROM jobs
        """
        where_parts = []
        params = []
        if archived:
            where_parts.append("archived = TRUE")
        else:
            where_parts.append("archived = FALSE")

        if q:
            where_parts.append("text ILIKE %s")
            params.append(f"%{q}%")

        if source_filter:
            where_parts.append("source = %s")
            params.append(source_filter)

        if where_parts:
            sql += " WHERE " + " AND ".join(where_parts)

        sql += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(sql, params)
        rows = cur.fetchall()
    finally:
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
                "sender_username": r["sender_username"],
                "created_at": r["created_at"].isoformat()
                if r["created_at"]
                else None,
                "received_at": r["received_at"].isoformat()
                if r["received_at"]
                else None,
                "archived": r["archived"],
            }
        )

    return jsonify({"jobs": jobs})


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def api_archive_job(job_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE jobs SET archived = TRUE WHERE id = %s RETURNING id", (job_id,)
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "not_found"}), 404

    return jsonify({"status": "ok"})


# ---------------- Allowed users ----------------

@app.route("/api/allowed_users", methods=["GET"])
def api_list_allowed_users():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, user_id, username, created_at FROM allowed_users ORDER BY id DESC"
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    users = []
    for r in rows:
        users.append(
            {
                "id": r["id"],
                "user_id": r["user_id"],
                "username": r["username"],
                "created_at": r["created_at"].isoformat()
                if r["created_at"]
                else None,
            }
        )

    return jsonify({"users": users})


@app.route("/api/allowed_users", methods=["POST"])
def api_add_allowed_user():
    data = request.get_json(silent=True) or {}
    username = _username_norm(data.get("username"))
    user_id = data.get("user_id")

    if not username:
        return jsonify({"error": "username_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO allowed_users (user_id, username, created_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (username) DO NOTHING
            RETURNING id
            """,
            (user_id, username),
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    if row:
        return jsonify({"status": "ok", "id": row["id"]})
    return jsonify({"status": "ok", "exists": True})


@app.route("/api/allowed_users/<int:user_id>", methods=["DELETE"])
def api_delete_allowed_user(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM allowed_users WHERE id = %s", (user_id,))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "ok"})


# ---------------- Parser secrets (FB cookies, TG session) ----------------

@app.route("/api/parser_secrets", methods=["GET"])
def api_list_parser_secrets():
    if not _is_admin_request():
        return jsonify({"error": "admin_forbidden"}), 403

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT key, value, updated_at
            FROM parser_secrets
            ORDER BY key
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    res = []
    for r in rows:
        res.append(
            {
                "key": r["key"],
                "value": r["value"],
                "updated_at": r["updated_at"].isoformat()
                if r["updated_at"]
                else None,
            }
        )

    return jsonify({"secrets": res})


@app.route("/api/parser_secrets/<key>", methods=["GET"])
def api_get_parser_secret(key: str):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT key, value, updated_at FROM parser_secrets WHERE key = %s",
            (key,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"key": key, "value": None, "updated_at": None})

    return jsonify(
        {
            "key": row["key"],
            "value": row["value"],
            "updated_at": row["updated_at"].isoformat()
            if row["updated_at"]
            else None,
        }
    )


@app.route("/api/parser_secrets/<key>", methods=["POST"])
def api_set_parser_secret(key: str):
    if not _is_admin_request():
        return jsonify({"error": "admin_forbidden"}), 403

    data = request.get_json(silent=True) or {}
    value = data.get("value")
    if value is None:
        return jsonify({"error": "value_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO parser_secrets (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "ok"})


def _is_admin_request() -> bool:
    """
    Проверка, что запрос идёт от админа:
      - либо по init_data (который прошёл check_access как admin)
      - либо по заголовку X-ADMIN-USERNAME, совпадающему с admin username
    """
    init_data = request.headers.get("X-TG-INIT-DATA")
    if init_data:
        verified = verify_telegram_webapp(init_data)
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
                        conn = get_conn()
                        cur = conn.cursor()
                        cur.execute(
                            """
                            INSERT INTO allowed_users (user_id, username, created_at)
                            VALUES (%s, %s, NOW())
                            ON CONFLICT (username) DO NOTHING
                            """,
                            (user_id, username_norm),
                        )
                        conn.commit()
                    except Exception:
                        pass
                    finally:
                        conn.close()

                    return True

    admin_username = request.headers.get("X-ADMIN-USERNAME")
    if admin_username:
        if is_admin(_username_norm(admin_username)):
            return True

    logger.warning("init_data verification failed, falling back to X-ADMIN-USERNAME")
    return False


# ---------------- Parser status (для алертов) ----------------

def _get_last_alert_time(key: str) -> Optional[datetime]:
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT value, updated_at FROM parser_secrets WHERE key = %s",
            (key,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return None
    try:
        return datetime.fromisoformat(row["value"])
    except Exception:
        return None


def _set_last_alert_time(key: str, dt: datetime):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO parser_secrets (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            (key, dt.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


@app.route("/api/parser_status/<key>", methods=["POST"])
def api_parser_status(key: str):
    """
    Сюда парсеры могут слать статусы, например:
      - fb_last_ok / tg_last_ok — время последнего успешного прохода
      - tg_auth_required — "true"/"false"
    """
    data = request.get_json(silent=True) or {}
    value = data.get("value")
    if value is None:
        return jsonify({"error": "value_required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO parser_status (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "ok"})


@app.route("/api/parser_status", methods=["GET"])
def api_get_parser_status():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT key, value, updated_at FROM parser_status")
        rows = cur.fetchall()
    finally:
        conn.close()

    res = []
    for r in rows:
        res.append(
            {
                "key": r["key"],
                "value": r["value"],
                "updated_at": r["updated_at"].isoformat()
                if r["updated_at"]
                else None,
            }
        )
    return jsonify({"status": "ok", "items": res})


# ---------------- TG auth через внешний сервис ----------------

TG_AUTH_SERVICE_URL = os.getenv("TG_AUTH_SERVICE_URL", "").rstrip("/")
TG_AUTH_SERVICE_TOKEN = os.getenv("TG_AUTH_SERVICE_TOKEN", "")


def set_secret(key: str, value: str):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO parser_secrets (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()


@app.route("/api/admin/secrets", methods=["GET"])
def api_admin_get_secrets():
    if not _is_admin_request():
        return jsonify({"error": "admin_forbidden"}), 403

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT key, value, updated_at
            FROM parser_secrets
            WHERE key IN ('fb_cookies_json', 'tg_session', 'tg_session_updated_at')
            ORDER BY key
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    res = {}
    for r in rows:
        res[r["key"]] = {
            "value": r["value"],
            "updated_at": r["updated_at"].isoformat()
            if r["updated_at"]
            else None,
        }

    return jsonify({"status": "ok", "secrets": res})


@app.route("/api/admin/fb_cookies", methods=["POST"])
def api_admin_fb_cookies():
    if not _is_admin_request():
        return jsonify({"error": "admin_forbidden"}), 403

    data = request.get_json(silent=True) or {}
    value = data.get("value")
    if value is None:
        return jsonify({"error": "value_required"}), 400

    set_secret("fb_cookies_json", value)
    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_auth/start", methods=["POST"])
def api_admin_tg_auth_start():
    if not _is_admin_request():
        return jsonify({"error": "admin_forbidden"}), 403

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        logger.error(
            "tg_auth_start: TG_AUTH_SERVICE_URL / TG_AUTH_SERVICE_TOKEN not configured"
        )
        return jsonify({"error": "tg_auth_service_not_configured"}), 500

    logger.info("tg_auth_start requested for phone=%s", phone)

    try:
        resp = requests.post(
            f"{TG_AUTH_SERVICE_URL}/auth/start",
            headers={"X-API-KEY": TG_AUTH_SERVICE_TOKEN},
            json={"phone": phone},
            timeout=30,
        )
    except Exception as e:
        logger.error("tg_auth_start: http error: %s", e)
        return jsonify({"error": "tg_auth_http_error"}), 500

    if resp.status_code != 200:
        logger.error(
            "tg_auth_start: service error http=%s, body=%s",
            resp.status_code,
            resp.text,
        )
        try:
            data = resp.json()
            err = data.get("error")
        except Exception:
            err = "tg_auth_service_error"
        return jsonify({"error": err}), 400

    try:
        data = resp.json()
    except Exception:
        logger.error("tg_auth_start: invalid json from service: %s", resp.text)
        return jsonify({"error": "tg_auth_service_invalid_json"}), 500

    status = data.get("status")
    if status != "ok":
        err = data.get("error") or "tg_auth_service_error"
        logger.error("tg_auth_start: service error: %s", data)
        return jsonify({"error": err}), 400

    logger.info("tg_auth_start: code sent OK")
    return jsonify({"status": "ok"})


@app.route("/api/admin/tg_auth/confirm", methods=["POST"])
def api_admin_tg_auth_confirm():
    if not _is_admin_request():
        return jsonify({"error": "admin_forbidden"}), 403

    data_in = request.get_json(silent=True) or {}
    phone = (data_in.get("phone") or "").strip()
    code = (data_in.get("code") or "").strip()
    password = (data_in.get("password") or "").strip()

    if not phone or not code:
        return jsonify({"error": "phone_and_code_required"}), 400

    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        return jsonify({"error": "tg_auth_service_not_configured"}), 500

    logger.info("tg_auth_confirm requested for phone=%s", phone)

    try:
        resp = requests.post(
            f"{TG_AUTH_SERVICE_URL}/auth/confirm",
            headers={"X-API-KEY": TG_AUTH_SERVICE_TOKEN},
            json={"phone": phone, "code": code, "password": password or None},
            timeout=60,
        )
    except Exception as e:
        logger.error("tg_auth_confirm: http error: %s", e)
        return jsonify({"error": "tg_auth_http_error"}), 500

    if resp.status_code != 200:
        logger.error(
            "tg_auth_confirm: service error http=%s, body=%s",
            resp.status_code,
            resp.text,
        )
        try:
            data = resp.json()
            err = data.get("error")
        except Exception:
            err = "tg_auth_service_error"
        return jsonify({"error": err}), 400

    try:
        data = resp.json()
    except Exception:
        logger.error("tg_auth_confirm: invalid json from service: %s", resp.text)
        return jsonify({"error": "tg_auth_service_invalid_json"}), 500

    status = data.get("status")
    if status != "ok":
        err = data.get("error") or "tg_auth_service_error"
        logger.error("tg_auth_confirm: service error: %s", data)
        return jsonify({"error": err}), 400

    session_str = data.get("session")
    if not session_str:
        logger.error("tg_auth_confirm: no session in service response: %s", data)
        return jsonify({"error": "tg_auth_no_session_in_response"}), 500

    # сохраняем сессию и время обновления
    set_secret("tg_session", session_str)
    set_secret("tg_session_updated_at", datetime.now(timezone.utc).isoformat())

    logger.info("tg_auth_confirm: session saved to parser_secrets[tg_session]")

    return jsonify({"status": "ok"})


# ---------------- Main ----------------

if __name__ == "__main__":
    port = int(os.getenv("PORT") or 8080)
    logger.info("Запуск Flask на порту %s", port)
    app.run(host="0.0.0.0", port=port)
