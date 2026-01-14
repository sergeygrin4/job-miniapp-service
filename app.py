import os
import json
import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta

import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from db import init_db, get_conn, get_secret, set_status, get_status

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

# ---------- TELEGRAM / CONFIG ----------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN") or ""
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID") or ""

ADMINS_RAW = os.getenv("ADMINS", "")

# Защита ingestion-эндпоинтов от внешних запросов
API_SECRET = os.getenv("API_SECRET", "").strip()

# ===== АЛЕРТЫ: повторы раз в час (по умолчанию) =====
ALERT_RATE_LIMIT_SECONDS = int(os.getenv("ALERT_RATE_LIMIT_SECONDS") or "3600")
_last_alert_sent_at: dict[str, datetime] = {}

# ===== УВЕДОМЛЕНИЯ О ВАКАНСИЯХ =====
NOTIFY_CHAT_IDS_RAW = (os.getenv("NOTIFY_CHAT_IDS") or "").strip()

# per-minute лимит можно полностью выключить, поставив 0
NOTIFY_PER_CHAT_PER_MINUTE = int(os.getenv("NOTIFY_PER_CHAT_PER_MINUTE") or "0")

# Жёсткая защита от взломного флуда (circuit breaker)
NOTIFY_BURST_WINDOW_SECONDS = int(os.getenv("NOTIFY_BURST_WINDOW_SECONDS") or "60")
NOTIFY_BURST_LIMIT = int(os.getenv("NOTIFY_BURST_LIMIT") or "200")
NOTIFY_BURST_COOLDOWN_SECONDS = int(os.getenv("NOTIFY_BURST_COOLDOWN_SECONDS") or "1800")

_notify_window: dict[int, dict[str, object]] = {}     # per-minute limiter
_notify_state: dict[int, dict[str, object]] = {}      # burst breaker


# ---------- helpers: auth ----------
def _get_parser_key_from_request() -> str | None:
    x = request.headers.get("X-API-KEY")
    if x is not None:
        return x
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def _require_parser_key():
    """
    Если API_SECRET задан — требуем ключ в X-API-KEY или Authorization: Bearer.
    """
    if not API_SECRET:
        return True, None
    provided = _get_parser_key_from_request()
    if provided is None or provided != API_SECRET:
        return False, (jsonify({"error": "forbidden"}), 403)
    return True, None


def _username_norm(u: str | None) -> str:
    u = (u or "").strip().lower()
    if u.startswith("@"):
        u = u[1:]
    return u


def _admins_set() -> set[str]:
    parts = [p.strip().lower().lstrip("@") for p in (ADMINS_RAW or "").split(",") if p.strip()]
    return set(parts)


def _is_admin(username_norm: str) -> bool:
    return bool(username_norm) and username_norm in _admins_set()


def _require_admin():
    header_username = request.headers.get("X-Admin-Username") or ""
    username_norm = _username_norm(header_username) or _username_norm(request.args.get("admin") or "")

    if not username_norm:
        return False, (jsonify({"error": "admin_required"}), 401)

    if not _is_admin(username_norm):
        return False, (jsonify({"error": "forbidden"}), 403)

    return True, None


# ---------- Static ----------
@app.route("/")
def index_page():
    return send_from_directory(app.static_folder, "index.html")


# ---------- notify helpers ----------
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
    """
    Если NOTIFY_PER_CHAT_PER_MINUTE <= 0 -> лимит отключён.
    """
    if NOTIFY_PER_CHAT_PER_MINUTE <= 0:
        return True

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


def _burst_allowed(chat_id: int) -> bool:
    """
    Circuit breaker: если в окно времени слишком много "новых" постов —
    отключаем уведомления на cooldown, чтобы бот не улетел в бан.
    """
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

    window_reset_at = st.get("window_reset_at")
    if not isinstance(window_reset_at, datetime) or now >= window_reset_at:
        st["window_reset_at"] = now + timedelta(seconds=NOTIFY_BURST_WINDOW_SECONDS)
        st["count"] = 0

    st["count"] = int(st.get("count") or 0) + 1

    if int(st["count"]) > NOTIFY_BURST_LIMIT:
        st["disabled_until"] = now + timedelta(seconds=NOTIFY_BURST_COOLDOWN_SECONDS)
        try:
            send_alert_human(
                f"🚨 Flood protection: слишком много новых постов. "
                f"Отключаю уведомления для chat_id={chat_id} на {NOTIFY_BURST_COOLDOWN_SECONDS} сек."
            )
        except Exception:
            pass
        return False

    return True


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
    """
    Вакансии:
    - улетают сразу, как только новый пост попал из парсера
    - строго 1 раз на новый post (потому что вызывается только после INSERT нового external_id)
    """
    if not BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set; job notification skipped")
        return

    chat_ids = _parse_notify_chat_ids()

    if not chat_ids:
        # allowed_users.user_id
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

    chat_ids = list(dict.fromkeys(chat_ids))
    if not chat_ids:
        logger.info("No chat_ids to notify")
        return

    message_text, reply_markup = _build_job_message(data)

    for chat_id in chat_ids:
        # per-minute лимит по умолчанию выключен (0)
        if not _can_send_per_minute(chat_id):
            logger.warning("Per-minute notify limit hit for chat_id=%s; skipped", chat_id)
            continue
        # burst breaker для защиты от взломного флуда
        if not _burst_allowed(chat_id):
            logger.warning("Burst breaker disabled notify for chat_id=%s; skipped", chat_id)
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
                logger.error(
                    "Failed to send notify to %s: HTTP %s body=%s",
                    chat_id, resp.status_code, resp.text[:500]
                )
        except Exception as e:
            logger.error("Failed to send notify to %s: %s", chat_id, e)


# ---------- alerts ----------
def _normalize_alert_key(text: str) -> str:
    """
    Чтобы "сразу, потом раз в час" работало даже если в тексте есть числа/таймстемпы.
    """
    t = (text or "").strip()
    if not t:
        return ""
    first = t.splitlines()[0].strip()
    first = first[:200]
    first = re.sub(r"\d{2,}", "#", first)
    return first


def send_alert_human(text: str):
    """
    Ошибки:
      - первый раз отправляем сразу
      - повторения (по нормализованному ключу) не чаще 1 раза в ALERT_RATE_LIMIT_SECONDS (обычно 3600)
    """
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        logger.warning("No bot/admin chat configured, alert skipped: %s", text)
        return

    now = datetime.now(timezone.utc)
    key = _normalize_alert_key(text)

    last = _last_alert_sent_at.get(key)
    if last is not None and now - last < timedelta(seconds=ALERT_RATE_LIMIT_SECONDS):
        logger.info("Alert skipped due to rate limit: key=%r", key)
        return

    _last_alert_sent_at[key] = now

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": ADMIN_CHAT_ID, "text": text},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.error("Failed to send alert: HTTP %s body=%s", resp.status_code, resp.text[:500])
    except Exception as e:
        logger.error("Failed to send alert: %s", e)


@app.route("/api/alert", methods=["POST"])
def api_alert():
    ok, err = _require_parser_key()
    if not ok:
        return err

    data = request.get_json(silent=True) or {}
    text = data.get("text") or data.get("message")
    if not text:
        return jsonify({"error": "text_required"}), 400

    send_alert_human(text)
    return jsonify({"status": "ok"})


# ---------- API: access check ----------
@app.route("/check_access", methods=["POST"])
def check_access():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or data.get("user") or request.headers.get("X-Username") or ""
    username_norm = _username_norm(username)

    if _is_admin(username_norm):
        return jsonify({"access_granted": True, "is_admin": True})

    if not username_norm:
        return jsonify({"access_granted": False, "is_admin": False})

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, user_id FROM allowed_users WHERE username = %s", (username_norm,))
    row = cur.fetchone()

    if row:
        incoming_user_id = data.get("user_id") or data.get("tg_user_id") or data.get("telegram_user_id")
        try:
            incoming_user_id = int(incoming_user_id) if incoming_user_id is not None else None
        except Exception:
            incoming_user_id = None

        db_user_id = row.get("user_id")
        try:
            db_user_id = int(db_user_id) if db_user_id is not None else None
        except Exception:
            db_user_id = None

        if db_user_id is None and incoming_user_id is not None:
            try:
                cur.execute("UPDATE allowed_users SET user_id = %s WHERE id = %s", (incoming_user_id, row.get("id")))
                conn.commit()
            except Exception as e:
                logger.error("Failed to update allowed_users.user_id: %s", e)

        conn.close()
        return jsonify({"access_granted": True, "is_admin": False})

    conn.close()
    return jsonify({"access_granted": False, "is_admin": False})


# ---------- Admin endpoints ----------
@app.route("/api/sources", methods=["GET"])
def get_sources():
    admin, err = _require_admin()
    if err:
        return err
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, title, link, created_at FROM sources ORDER BY created_at DESC")
    rows = cur.fetchall() or []
    conn.close()
    return jsonify({"items": rows})


@app.route("/api/fb_groups", methods=["GET"])
def get_fb_groups():
    admin, err = _require_admin()
    if err:
        return err
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, title, link, created_at FROM fb_groups ORDER BY created_at DESC")
    rows = cur.fetchall() or []
    conn.close()
    return jsonify({"items": rows})


# ---------- Parser-safe endpoints ----------
@app.route("/api/groups", methods=["GET"])
def api_groups():
    """
    Единый список источников для парсеров.
    Формат под tg_parser.py / fb_parser.py:
      {"groups":[{"group_id": "...", "group_url": "...", "enabled": true, "type": "telegram|facebook"}, ...]}
    """
    ok, err = _require_parser_key()
    if not ok:
        return err

    groups = []

    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT title, link FROM sources ORDER BY created_at DESC")
        for r in (cur.fetchall() or []):
            link = (r.get("link") or "").strip()
            if not link:
                continue
            groups.append({
                "group_id": link,
                "group_url": link,
                "title": r.get("title") or "",
                "enabled": True,
                "type": "telegram",
            })

        cur.execute("SELECT title, link FROM fb_groups ORDER BY created_at DESC")
        for r in (cur.fetchall() or []):
            link = (r.get("link") or "").strip()
            if not link:
                continue
            groups.append({
                "group_id": link,
                "group_url": link,
                "title": r.get("title") or "",
                "enabled": True,
                "type": "facebook",
            })

        conn.close()
    except Exception as e:
        logger.error("api_groups failed: %s", e)

    return jsonify({"groups": groups})


@app.route("/api/parser_secrets/<key>", methods=["GET"])
def api_get_parser_secret(key: str):
    ok, err = _require_parser_key()
    if not ok:
        return err

    key = (key or "").strip()
    if not key:
        return jsonify({"error": "key_required"}), 400

    row = get_secret(key)
    if not row:
        value = os.getenv(key)
        if value is None:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"key": key, "value": value})

    return jsonify({"key": row.get("key"), "value": row.get("value"), "updated_at": row.get("updated_at")})


@app.route("/api/parser_status/<key>", methods=["POST"])
def api_set_parser_status(key: str):
    ok, err = _require_parser_key()
    if not ok:
        return err

    data = request.get_json(silent=True) or {}
    value = (data.get("value") or "").strip()
    if not value:
        return jsonify({"error": "value_required"}), 400

    try:
        set_status(key, value)
    except Exception as e:
        logger.error("set_status failed: %s", e)
        return jsonify({"error": "db_error"}), 500

    return jsonify({"status": "ok"})


@app.route("/api/parser_status/<key>", methods=["GET"])
def api_get_parser_status(key: str):
    admin, err = _require_admin()
    if err:
        return err

    row = get_status(key)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(row)


# ---------- Jobs ingestion ----------
@app.route("/post", methods=["POST"])
def add_job():
    ok, err = _require_parser_key()
    if not ok:
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
        # Новый пост — шлём уведомление сразу (и строго 1 раз на новый insert)
        try:
            send_job_notification(data)
        except Exception as e:
            logger.error("send_job_notification failed: %s", e)

        return jsonify({"status": "ok", "id": row["id"]})

    return jsonify({"status": "ok", "id": None})


if __name__ == "__main__":
    logger.info("Инициализация БД...")
    init_db()
    logger.info("Запуск Flask на порту %s", PORT)
    logger.info("BOT_TOKEN set=%s, ADMIN_CHAT_ID=%s, API_SECRET set=%s", bool(BOT_TOKEN), ADMIN_CHAT_ID, bool(API_SECRET))
    app.run(host="0.0.0.0", port=PORT)
