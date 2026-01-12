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
import requests
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

# ---- Telegram / боты / админы ----

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
_last_alert_sent_at = {}
# ==========================================================

TELEGRAM_BOT_TOKEN = BOT_TOKEN

# Внешний сервис для авторизации в Telegram
TG_AUTH_SERVICE_URL = os.getenv("TG_AUTH_SERVICE_URL", "").rstrip("/")
TG_AUTH_SERVICE_TOKEN = os.getenv("TG_AUTH_SERVICE_TOKEN", "")

bot: Optional[Bot] = None
if BOT_TOKEN:
    bot = Bot(token=BOT_TOKEN)

# ---- access helpers ----


def _username_norm(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    u = username.strip()
    if u.startswith("@"):
        u = u[1:]
    return u.lower() or None


def _parse_admins() -> set[str]:
    parts = [p.strip() for p in ADMINS_RAW.replace(";", ",").split(",") if p.strip()]
    return {_username_norm(p) for p in parts if _username_norm(p)}


ADMINS = _parse_admins()


def is_admin(username: Optional[str]) -> bool:
    u = _username_norm(username)
    if not u:
        return False
    return u in ADMINS


def _require_admin():
    """
    Простейшая проверка: для миниаппа мы доверяем полю "admin_username" в запросе.
    Если когда-нибудь захочется, можно сделать сюда полноценную верификацию initData.
    """
    username = request.headers.get("X-ADMIN-USERNAME")
    if not username:
        return None, (jsonify({"error": "admin_forbidden"}), 403)

    if not is_admin(username):
        return None, (jsonify({"error": "admin_forbidden"}), 403)

    return username, None


def _iso(dt: Optional[datetime]) -> Optional[str]:
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


# ---- access / allowed_users ----


@app.route("/check_access", methods=["POST"])
def check_access():
    """
    Миниапп при заходе дергает этот эндпоинт и передаёт init_data из Telegram WebApp.
    Здесь можно проверить подпись, username и т.д. Сейчас — максимально простой вариант:
    - если username в ADMINS или в таблице allowed_users — даём доступ
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    user_id = data.get("user_id")

    u_norm = _username_norm(username)

    allowed = False
    is_admin_flag = is_admin(username)

    with get_conn() as conn:
        cur = conn.cursor()
        if u_norm:
            cur.execute(
                """
                SELECT 1 FROM allowed_users
                WHERE username = %s
                LIMIT 1
                """,
                (u_norm,),
            )
            if cur.fetchone():
                allowed = True

        if not allowed and is_admin_flag:
            # админа добавляем автоматически
            cur.execute(
                """
                INSERT INTO allowed_users (username, user_id)
                VALUES (%s, %s)
                ON CONFLICT (username) DO NOTHING
                """,
                (u_norm, user_id),
            )
            conn.commit()
            allowed = True

    return jsonify(
        {
            "allowed": bool(allowed or is_admin_flag),
            "is_admin": bool(is_admin_flag),
            "username": username,
            "user_id": user_id,
        }
    )


@app.route("/api/allowed_users", methods=["GET", "POST", "DELETE"])
def api_allowed_users():
    admin, err = _require_admin()
    if err:
        return err

    if request.method == "GET":
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, username, user_id, created_at
                FROM allowed_users
                ORDER BY created_at ASC
                """
            )
            rows = cur.fetchall()
        items = []
        for r in rows:
            items.append(
                {
                    "id": r[0],
                    "username": r[1],
                    "user_id": r[2],
                    "created_at": _iso(r[3]),
                }
            )
        return jsonify({"items": items})

    data = request.get_json(silent=True) or {}

    if request.method == "POST":
        username = _username_norm(data.get("username"))
        user_id = data.get("user_id")
        if not username:
            return jsonify({"error": "username_required"}), 400

        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO allowed_users (username, user_id)
                VALUES (%s, %s)
                ON CONFLICT (username) DO NOTHING
                RETURNING id, username, user_id, created_at
                """,
                (username, user_id),
            )
            row = cur.fetchone()
            conn.commit()

        if not row:
            return jsonify({"status": "exists"})
        return jsonify(
            {
                "status": "ok",
                "item": {
                    "id": row[0],
                    "username": row[1],
                    "user_id": row[2],
                    "created_at": _iso(row[3]),
                },
            }
        )

    # DELETE
    user_id = data.get("id")
    if not user_id:
        return jsonify({"error": "id_required"}), 400

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM allowed_users WHERE id = %s", (user_id,))
        conn.commit()

    return jsonify({"status": "ok"})


# ---- Jobs (вакансии) ----


def _job_to_dict(row):
    return {
        "id": row["id"],
        "source": row["source"],
        "source_name": row["source_name"],
        "external_id": row["external_id"],
        "url": row["url"],
        "text": row["text"],
        "sender_username": row["sender_username"],
        "created_at": _iso(row["created_at"]),
        "received_at": _iso(row["received_at"]),
        "archived": bool(row["archived"]),
    }


@app.route("/api/jobs", methods=["GET"])
def get_jobs():
    limit = int(request.args.get("limit") or "50")
    archived = request.args.get("archived")
    if archived is None:
        archived = False
    else:
        archived = archived.lower() == "true"

    search = (request.args.get("q") or "").strip()
    source_filter = (request.args.get("source") or "").strip()

    with get_conn() as conn:
        cur = conn.cursor()
        params = [archived]
        where = ["archived = %s"]

        if search:
            where.append("text ILIKE %s")
            params.append(f"%{search}%")

        if source_filter:
            where.append("source = %s")
            params.append(source_filter)

        where_sql = " AND ".join(where)
        cur.execute(
            f"""
            SELECT id, source, source_name, external_id, url, text, sender_username,
                   created_at, received_at, archived
            FROM jobs
            WHERE {where_sql}
            ORDER BY created_at DESC
            LIMIT %s
            """,
            params + [limit],
        )
        rows = cur.fetchall()

    jobs = [
        {
            "id": r[0],
            "source": r[1],
            "source_name": r[2],
            "external_id": r[3],
            "url": r[4],
            "text": r[5],
            "sender_username": r[6],
            "created_at": _iso(r[7]),
            "received_at": _iso(r[8]),
            "archived": bool(r[9]),
        }
        for r in rows
    ]

    return jsonify({"jobs": jobs})


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def archive_job(job_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE jobs
            SET archived = TRUE
            WHERE id = %s
            """,
            (job_id,),
        )
        conn.commit()
    return jsonify({"status": "ok"})


@app.route("/post", methods=["POST"])
def receive_post():
    """
    Endpoint, куда шлют FB и TG парсеры.
    Тело:
    {
      "source": "...",
      "source_name": "...",
      "external_id": "...",
      "url": "...",
      "text": "...",
      "sender_username": "..."
    }
    """
    data = request.get_json(silent=True) or {}

    source = (data.get("source") or "").strip()
    source_name = (data.get("source_name") or "").strip()
    external_id = (data.get("external_id") or "").strip()
    url = (data.get("url") or "").strip()
    text = (data.get("text") or "").strip()
    sender_username = (data.get("sender_username") or "").strip()

    if not source or not external_id:
        return jsonify({"error": "source_and_external_id_required"}), 400

    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO jobs (
                source,
                source_name,
                external_id,
                url,
                text,
                sender_username,
                created_at,
                received_at,
                archived
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,FALSE)
            ON CONFLICT (source, external_id) DO UPDATE
            SET
                text = EXCLUDED.text,
                url = EXCLUDED.url,
                sender_username = EXCLUDED.sender_username,
                received_at = EXCLUDED.received_at
            RETURNING id
            """,
            (
                source,
                source_name,
                external_id,
                url,
                text,
                sender_username,
                now,
                now,
            ),
        )
        row = cur.fetchone()
        conn.commit()

    return jsonify({"status": "ok", "id": row[0] if row else None})


# ---- Alerts ----


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

    try:
        # через requests напрямую в Telegram API (оставлено для совместимости)
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": ADMIN_CHAT_ID, "text": text},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as e:
        logger.error("Failed to send alert: %s", e)

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
    text = data.get("text")
    if not text:
        return jsonify({"error": "text_required"}), 400

    send_alert_human(text)
    return jsonify({"status": "ok"})


# ---- Parser secrets / statuses (FB cookies, TG session и т.п.) ----


@app.route("/api/parser_secrets/<key>", methods=["GET"])
def get_parser_secret(key: str):
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    row = get_secret(key)
    if not row:
        return jsonify({"key": key, "value": None, "updated_at": None})

    return jsonify(
        {
            "key": key,
            "value": row.get("value"),
            "updated_at": _iso(row.get("updated_at")),
        }
    )


@app.route("/api/parser_status/<key>", methods=["POST"])
def set_parser_status(key: str):
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    value = data.get("value")
    set_status(key, value)

    # специальные статусы от парсеров:
    if key == "fb_last_ok":
        pass
    elif key == "tg_last_ok":
        pass
    elif key == "tg_auth_required":
        # парсер говорит, что сессия отвалилась, нужно перелогиниться
        send_alert_human(
            "🔔 tg_parser:\nTelegram парсер: сессия не авторизована.\n"
            "Открой миниапп → ⚙️ Настройки → Аккаунты → Telegram сессия и пересоздай её."
        )

    return jsonify({"status": "ok"})


# ---- Admin: получение статусов / секретов ----


@app.route("/api/admin/secrets", methods=["GET"])
def api_admin_get_secrets():
    admin, err = _require_admin()
    if err:
        return err

    fb = get_secret("fb_cookies_json")
    tg = get_secret("tg_session")
    pending = get_status("tg_auth_pending")
    tg_last_ok = get_status("tg_last_ok")
    fb_last_ok = get_status("fb_last_ok")

    return jsonify(
        {
            "fb_cookies_json": {
                "value": fb.get("value") if fb else None,
                "updated_at": _iso(fb.get("updated_at")) if fb else None,
            },
            "tg_session": {
                "value": tg.get("value") if tg else None,
                "updated_at": _iso(tg.get("updated_at")) if tg else None,
            },
            "tg_auth_pending": pending.get("value") if pending else None,
            "tg_last_ok": tg_last_ok.get("value") if tg_last_ok else None,
            "fb_last_ok": fb_last_ok.get("value") if fb_last_ok else None,
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
    if not cookies_json and not cookies:
        return jsonify({"error": "cookies_required"}), 400

    if cookies_json:
        # сохраняем как строку
        set_secret("fb_cookies_json", str(cookies_json))
        return jsonify({"status": "ok", "mode": "json"})

    # иначе ожидаем массив объектов cookies (Apify формат)
    try:
        cookies_list = json.loads(cookies)
        if not isinstance(cookies_list, list):
            raise ValueError
    except Exception:
        return jsonify({"error": "invalid_cookies_format"}), 400

    set_secret("fb_cookies_json", json.dumps(cookies_list, ensure_ascii=False))
    return jsonify({"status": "ok", "mode": "list"})


@app.route("/api/admin/fb_cookies_dynamic", methods=["POST"])
def api_admin_set_fb_cookies_dynamic():
    """
    Обновление только динамичных значений (например, c_user, xs, fr).
    Принимаем строку вида:
    c_user=...; xs=...; fr=...
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
        if not isinstance(cookies, list):
            raise ValueError
    except Exception:
        return jsonify({"error": "invalid_base_cookies_json"}), 500

    updated = 0
    for c in cookies:
        if not isinstance(c, dict):
            continue
        name = c.get("key") or c.get("name")
        if name in mapping:
            c["value"] = mapping[name]
            updated += 1

    if not updated:
        return jsonify({"error": "no_keys_matched"}), 400

    set_secret("fb_cookies_json", json.dumps(cookies, ensure_ascii=False))
    return jsonify({"status": "ok", "updated": updated})


# ---- Admin: Telegram StringSession (ручной ввод) ----


@app.route("/api/admin/tg_session/manual", methods=["POST"])
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
    row = get_secret("tg_session")
    if not row or not row.get("value"):
        return {"ok": False, "reason": "no_session", "me": None}

    session_str = row["value"]

    api_id, api_hash = _tg_api_creds()
    client = TelegramClient(
        StringSession(session_str),
        api_id,
        api_hash,
    )

    try:
        await client.connect()
        if not await client.is_user_authorized():
            result = {"ok": False, "reason": "not_authorized", "me": None}
        else:
            me = await client.get_me()
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


@app.route("/api/admin/tg_auth/start", methods=["POST"])
def api_admin_tg_auth_start():
    """
    Шаг 1: отправить код через внешний tg_auth_service.
    Тело: {"phone": "+7999..."}
    """
    admin, err = _require_admin()
    if err:
        return err

    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        return (
            jsonify(
                {
                    "error": "tg_auth_service_not_configured",
                    "details": "TG_AUTH_SERVICE_URL / TG_AUTH_SERVICE_TOKEN not configured",
                }
            ),
            500,
        )

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    logger.info("tg_auth_start requested by %s for phone=%s", admin, phone)

    try:
        resp = httpx.post(
            f"{TG_AUTH_SERVICE_URL}/auth/start",
            json={"phone": phone, "token": TG_AUTH_SERVICE_TOKEN},
            timeout=15.0,
        )
    except Exception as e:
        logger.error("tg_auth_start: http error: %s", e)
        return jsonify({"error": str(e)}), 500

    try:
        j = resp.json()
    except Exception:
        j = None

    if resp.status_code != 200:
        msg = (j and j.get("error")) or ("HTTP " + str(resp.status_code))
        logger.error("tg_auth_start: service error: %s", msg)
        return jsonify({"error": msg}), 500

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

    if not TG_AUTH_SERVICE_URL or not TG_AUTH_SERVICE_TOKEN:
        return (
            jsonify(
                {
                    "error": "tg_auth_service_not_configured",
                    "details": "TG_AUTH_SERVICE_URL / TG_AUTH_SERVICE_TOKEN not configured",
                }
            ),
            500,
        )

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip() or None

    if not phone or not code:
        return jsonify({"error": "phone_and_code_required"}), 400

    logger.info("tg_auth_confirm requested by %s for phone=%s", admin, phone)

    try:
        resp = httpx.post(
            f"{TG_AUTH_SERVICE_URL}/auth/confirm",
            json={
                "phone": phone,
                "code": code,
                "password": password,
                "token": TG_AUTH_SERVICE_TOKEN,
            },
            timeout=30.0,
        )
    except Exception as e:
        logger.error("tg_auth_confirm: http error: %s", e)
        return jsonify({"error": str(e)}), 500

    try:
        j = resp.json()
    except Exception:
        j = None

    if resp.status_code != 200 or not j or j.get("status") != "ok":
        msg = (j and (j.get("error") or j.get("message"))) or ("HTTP " + str(resp.status_code))
        logger.error("tg_auth_confirm: service error: %s", msg)
        return jsonify({"error": msg}), 500

    session_str = j.get("session")
    if not session_str:
        return jsonify({"error": "no_session_returned"}), 500

    set_secret("tg_session", session_str)
    set_status("tg_auth_pending", "")

    return jsonify({"status": "ok"})


# ---- Cron / напоминания ----

CRON_SECRET = os.getenv("CRON_SECRET", "")


@app.route("/cron/fb_cookies_reminder", methods=["POST", "GET"])
def cron_fb_cookies_reminder():
    if CRON_SECRET:
        provided = request.args.get("secret") or request.headers.get("X-CRON-KEY")
        if provided != CRON_SECRET:
            return jsonify({"error": "forbidden"}), 403

    now = datetime.now(timezone.utc)

    fb = get_secret("fb_cookies_json")
    fb_updated_at = None
    if fb and fb.get("updated_at"):
        fb_updated_at = fb["updated_at"]
        if isinstance(fb_updated_at, str):
            try:
                fb_updated_at = datetime.fromisoformat(fb_updated_at.replace("Z", "+00:00"))
            except Exception:
                fb_updated_at = None

    days = None
    if fb_updated_at and isinstance(fb_updated_at, datetime):
        days = (now - fb_updated_at).days

    if days is None or days >= 7:
        send_alert_human(
            "🔔 fb_parser:\n"
            "Напоминание: обнови Facebook cookies (Apify) в миниаппе.\n"
            "Раздел ⚙️ Настройки → Аккаунты → Facebook cookies (Apify)."
        )

    return jsonify({"status": "ok", "fb_cookies_age_days": days})


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
        alerts.append("Telegram парсер давно не присылал статус (tg_last_ok).")

    if tg_auth_required and tg_auth_required.get("value"):
        alerts.append("Telegram парсер сообщает, что требуется переавторизация (tg_auth_required).")

    if alerts:
        send_alert_human("🔔 parsers_watchdog:\n" + "\n".join(f"- {a}" for a in alerts))

    return jsonify({"status": "ok", "alerts": alerts})


# ---- Groups (FB + TG источники) ----

@app.route("/api/groups", methods=["GET"])
def get_groups():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, added_at
            FROM fb_groups
            ORDER BY id DESC
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
                "enabled": bool(r[3]),
                "added_at": _iso(r[4]),
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
            INSERT INTO fb_groups (group_id, group_name, enabled)
            VALUES (%s, %s, TRUE)
            ON CONFLICT (group_id) DO UPDATE
            SET group_name = EXCLUDED.group_name,
                enabled   = TRUE
            RETURNING id
            """,
            (group_id, group_name),
        )
        row = cur.fetchone()
        conn.commit()

    return jsonify({"status": "ok", "id": row[0] if row else None})


@app.route("/api/groups/<int:gid>", methods=["DELETE"])
def delete_group(gid: int):
    admin, err = _require_admin()
    if err:
        return err

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM fb_groups WHERE id = %s", (gid,))
        conn.commit()

    return jsonify({"status": "ok"})


@app.route("/api/groups/<int:gid>/toggle", methods=["POST"])
def toggle_group(gid: int):
    admin, err = _require_admin()
    if err:
        return err

    data = get_json()
    enabled = bool(data.get("enabled", True))

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE fb_groups SET enabled = %s WHERE id = %s",
            (enabled, gid),
        )
        conn.commit()

    return jsonify({"status": "ok"})



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
