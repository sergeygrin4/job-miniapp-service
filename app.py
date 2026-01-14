import os
import json
import hmac
import hashlib
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote

import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import httpx
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import RPCError

from db import init_db, get_conn


# ---------- ЛОГГЕР ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - miniapp - %(levelname)s - %(message)s",
)
logger = logging.getLogger("miniapp")


# ---------- FLASK ----------
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app, resources={r"/*": {"origins": "*"}})

PORT = int(os.getenv("PORT", "8080"))

# ---------- TELEGRAM / MINIAPP CONFIG ----------
TG_API_ID_DEFAULT = int(os.getenv("TG_API_ID_DEFAULT") or "0")
TG_API_HASH_DEFAULT = os.getenv("TG_API_HASH_DEFAULT") or ""
TG_BOT_TOKEN_DEFAULT = os.getenv("TG_BOT_TOKEN_DEFAULT") or ""

BOT_TOKEN_DEFAULT = ""
ADMIN_CHAT_ID_DEFAULT = ""

BOT_TOKEN = (
    os.getenv("TELEGRAM_BOT_TOKEN")
    or os.getenv("BOT_TOKEN")
    or BOT_TOKEN_DEFAULT
)
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID") or ADMIN_CHAT_ID_DEFAULT

# Если задано NOTIFY_CHAT_IDS, уведомления о новых постах уйдут только в эти чаты (через запятую).
NOTIFY_CHAT_IDS_RAW = os.getenv("NOTIFY_CHAT_IDS", "").strip()
# Лимит уведомлений на один chat_id в минуту (защита от спама/взлома)
NOTIFY_PER_CHAT_PER_MINUTE = int(os.getenv("NOTIFY_PER_CHAT_PER_MINUTE") or "20")

ADMINS_RAW = os.getenv("ADMINS", "")

API_SECRET = os.getenv("API_SECRET", "")


def _get_parser_key_from_request() -> str | None:
    """
    Parser auth: either X-API-KEY: <secret> or Authorization: Bearer <secret>.
    Returns the provided key or None if no auth headers present.
    """
    x = request.headers.get("X-API-KEY")
    if x is not None:
        return x
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def _require_parser_key():
    """
    If API_SECRET is set, require a correct parser key.
    Returns (ok: bool, flask_response_or_none)
    """
    provided = _get_parser_key_from_request()
    if API_SECRET:
        if provided is None or provided != API_SECRET:
            return False, (jsonify({"error": "forbidden"}), 403)
    return True, None


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ==== rate-limit для алертов (по умолчанию 1 раз в час) ====
ALERT_RATE_LIMIT_SECONDS = int(os.getenv("ALERT_RATE_LIMIT_SECONDS") or "3600")
_last_alert_sent_at: dict[str, datetime] = {}

# ---- Anti-spam для уведомлений о новых постах ----
_notify_window: dict[int, dict[str, object]] = {}  # chat_id -> {"reset_at": datetime, "count": int}


def _parse_notify_chat_ids() -> list[int]:
    """Parse NOTIFY_CHAT_IDS env ('123,456')."""
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


def _can_send_notify(chat_id: int) -> bool:
    """Simple per-chat rolling window: N per minute."""
    now = datetime.now(timezone.utc)
    rec = _notify_window.get(chat_id)
    if not rec or not isinstance(rec.get("reset_at"), datetime):
        _notify_window[chat_id] = {"reset_at": now + timedelta(minutes=1), "count": 1}
        return True
    reset_at = rec["reset_at"]
    if now >= reset_at:
        _notify_window[chat_id] = {"reset_at": now + timedelta(minutes=1), "count": 1}
        return True
    cnt = int(rec.get("count") or 0)
    if cnt >= NOTIFY_PER_CHAT_PER_MINUTE:
        return False
    rec["count"] = cnt + 1
    return True


def _build_job_message(data: dict) -> tuple[str, dict | None]:
    """
    Build Telegram message text + inline_keyboard payload.
    Returns: (text, reply_markup_json_or_none)
    """
    source_name = (data.get("source_name") or data.get("source") or "").strip()
    url = (data.get("url") or "").strip()
    text = (data.get("text") or "").strip()

    # Короткий превью (безопасно по длине)
    preview = text.strip()
    if len(preview) > 700:
        preview = preview[:700].rstrip() + "…"

    msg_lines = []
    if source_name and url:
        msg_lines.append("📣 Получена вакансия из группы:")
        msg_lines.append(url)
    elif url:
        msg_lines.append("📣 Получена вакансия:")
        msg_lines.append(url)
    else:
        msg_lines.append("📣 Получена вакансия:")

    msg_lines.append("")
    msg_lines.append("📝 Краткое описание:")
    msg_lines.append(preview if preview else "(без текста)")

    message_text = "\n".join(msg_lines)

    # Кнопки
    buttons = []
    if url:
        buttons.append([{"text": "🔗 Открыть пост", "url": url}])

    sender_username = (data.get("sender_username") or "").strip()
    # Если sender_username уже является ссылкой — используем её. Если это @username — сделаем t.me ссылку.
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
    """Send 'new post found' notification to Telegram chats."""
    if not BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN is not set; job notification skipped")
        return

    # 1) If NOTIFY_CHAT_IDS specified -> only these.
    chat_ids = _parse_notify_chat_ids()

    # 2) Otherwise -> all allowed_users.user_id + optional ADMIN_CHAT_ID
    if not chat_ids:
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
            logger.error("Failed to load allowed_users for notifications: %s", e)

        if ADMIN_CHAT_ID:
            try:
                chat_ids.append(int(ADMIN_CHAT_ID))
            except Exception:
                pass

    # unique
    chat_ids = list(dict.fromkeys(chat_ids))
    if not chat_ids:
        logger.info("No chat_ids to notify (allowed_users empty and NOTIFY_CHAT_IDS not set)")
        return

    message_text, reply_markup = _build_job_message(data)

    for chat_id in chat_ids:
        if not _can_send_notify(chat_id):
            logger.warning("Notify rate-limit hit for chat_id=%s; skipped", chat_id)
            continue
        try:
            payload = {
                "chat_id": chat_id,
                "text": message_text,
                "disable_web_page_preview": True,
            }
            if reply_markup:
                payload["reply_markup"] = reply_markup
            resp = requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                logger.error(
                    "Failed to send notify to %s: HTTP %s body=%s",
                    chat_id,
                    resp.status_code,
                    resp.text[:500],
                )
        except Exception as e:
            logger.error("Failed to send notify to %s: %s", chat_id, e)


def _now_iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


# ---- Статическая страница ----


@app.route("/")
def index_page():
    return send_from_directory(app.static_folder, "index.html")


# ---- Helpers for auth ----

def _username_norm(u: str | None) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    u = u.lower()
    if u.startswith("@"):
        u = u[1:]
    return u


def _admins_set() -> set[str]:
    raw = ADMINS_RAW or ""
    parts = [p.strip().lower().lstrip("@") for p in raw.split(",") if p.strip()]
    return set(parts)


def is_admin(username_norm: str) -> bool:
    return bool(username_norm) and username_norm in _admins_set()


def _require_admin():
    """
    Admin auth via headers:
      - X-Admin-Username: <telegram_username>
      - X-Admin-Password: <password>  (optional, for compatibility)
    or query param 'admin' (legacy).
    """
    header_username = request.headers.get("X-Admin-Username") or ""
    header_username = _username_norm(header_username)

    # legacy query param
    username = request.args.get("admin") or request.args.get("username") or ""
    username = _username_norm(username)

    if header_username:
        username_norm = header_username
    else:
        username_norm = username

    if not username_norm:
        return False, (jsonify({"error": "admin_required"}), 401)

    if not is_admin(username_norm):
        return False, (jsonify({"error": "forbidden"}), 403)

    return True, None


# ---- API: access check ----

@app.route("/check_access", methods=["POST"])
def check_access():
    data = request.get_json(silent=True) or {}
    header_username = request.headers.get("X-Username") or ""
    username = data.get("username") or data.get("user") or header_username

    logger.info(
        "check_access payload=%s header_username=%s username=%s",
        data,
        header_username,
        username,
    )

    username_norm = _username_norm(username)

    # Админов пускаем сразу
    if is_admin(username_norm):
        logger.info("check_access: %s is admin -> access granted", username_norm)
        return jsonify({"access_granted": True, "is_admin": True})

    if not username_norm:
        logger.info("check_access: username missing -> access denied")
        return jsonify({"access_granted": False, "is_admin": False})

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, user_id FROM allowed_users WHERE username = %s",
        (username_norm,),
    )
    row = cur.fetchone()

    if row:
        # аккуратно обновляем user_id, если его ещё нет
        db_user_id = row.get("user_id")
        try:
            db_user_id = int(db_user_id) if db_user_id is not None else None
        except Exception:
            db_user_id = None

        incoming_user_id = data.get("user_id") or data.get("tg_user_id") or data.get("telegram_user_id")
        try:
            incoming_user_id = int(incoming_user_id) if incoming_user_id is not None else None
        except Exception:
            incoming_user_id = None

        if db_user_id is None and incoming_user_id is not None:
            try:
                cur.execute(
                    "UPDATE allowed_users SET user_id = %s WHERE id = %s",
                    (incoming_user_id, row.get("id")),
                )
                conn.commit()
                logger.info("Updated allowed_users.user_id for %s -> %s", username_norm, incoming_user_id)
            except Exception as e:
                logger.error("Failed to update allowed_users.user_id: %s", e)

        conn.close()
        logger.info(
            "check_access: %s found in allowed_users -> access granted", username_norm
        )
        return jsonify({"access_granted": True, "is_admin": False})

    conn.close()
    logger.info("check_access: %s not found -> access denied", username_norm)
    return jsonify({"access_granted": False, "is_admin": False})


@app.route("/api/allowed_users", methods=["GET"])
def api_allowed_users():
    admin, err = _require_admin()
    if err:
        return err

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, user_id, created_at FROM allowed_users ORDER BY created_at DESC")
    rows = cur.fetchall() or []
    conn.close()

    return jsonify({"items": rows})


@app.route("/api/allowed_users", methods=["POST"])
def api_add_allowed_user():
    admin, err = _require_admin()
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
        INSERT INTO allowed_users (username)
        VALUES (%s)
        ON CONFLICT (username) DO NOTHING
        RET
