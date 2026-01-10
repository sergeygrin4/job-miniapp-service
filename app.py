import os
import logging
from datetime import datetime
from typing import Optional, List

from flask import Flask, request, jsonify, send_from_directory

from db import get_conn, init_db

# ---------------- Логирование ----------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("mini_app_bot")


# ---------------- Конфиг из окружения ----------------

PORT = int(os.getenv("PORT", "8080"))

# Секрет для авторизации парсеров (tg_parser, fb_parser)
API_SECRET = os.getenv("API_SECRET", "")

# Мини-админы (username в Telegram, без @), которым всегда разрешён доступ и которые считаются администраторами
# через ENV, например: "opsifd,another_admin"
ADMINS_RAW = os.getenv("ADMINS", "")
ADMINS = {u.strip().lower().lstrip("@") for u in ADMINS_RAW.split(",") if u.strip()}

# Модель OpenAI (если включён AI-фильтр)
AI_MODEL = os.getenv("AI_MODEL", "gpt-4.1-mini")

# Нужен ли AI-фильтр для вакансий
USE_AI_FILTER = os.getenv("USE_AI_FILTER", "true").lower() in ("1", "true", "yes")


# ---------------- Flask-приложение ----------------

app = Flask(__name__, static_folder="static", static_url_path="")


# ---------------- Утилиты ----------------

def _iso(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.isoformat()


def _username_norm(username: Optional[str]) -> Optional[str]:
    """
    Нормализуем username:
    - срезаем пробелы
    - убираем @ в начале
    - приводим к lower
    """
    if not username:
        return None
    return username.strip().lstrip("@").lower() or None


def is_admin(username_norm: Optional[str]) -> bool:
    """
    Проверка, является ли пользователь админом по username (из ENV).
    """
    if not username_norm:
        return False
    return username_norm in ADMINS


def is_user_in_db(username_norm: Optional[str]) -> bool:
    """
    Проверка, есть ли пользователь в allowed_users.
    """
    if not username_norm:
        return False
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT 1 FROM allowed_users
            WHERE username = %s
            LIMIT 1
            """,
            (username_norm,),
        )
        row = cur.fetchone()
        return row is not None
    except Exception as e:
        logger.error("Ошибка проверки allowed_user: %s", e)
        return False
    finally:
        conn.close()


def is_user_allowed(username_norm: Optional[str]) -> bool:
    """
    Пользователь допускается в миниапп, если он:
    - админ, или
    - есть в allowed_users.
    """
    if not username_norm:
        return False
    if username_norm in ADMINS:
        return True
    return is_user_in_db(username_norm)


def upsert_allowed_user(username_norm: str, user_id: Optional[int]):
    """
    Сохраняем/обновляем пользователя в таблице allowed_users,
    когда он открывает миниапп или когда он уже есть в админке.
    """
    if not username_norm:
        return

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO allowed_users (username, user_id, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (username) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                updated_at = EXCLUDED.updated_at
            """,
            (username_norm, user_id),
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Ошибка upsert allowed_user: %s", e)
    finally:
        conn.close()


def load_allowed_user_ids_from_db() -> List[int]:
    """
    Читаем user_id из таблицы allowed_users.
    Это те пользователи, которые:
    1) выданы через админку (allowed_users)
    2) хотя бы раз открыли миниапп (мы сохранили их user_id)
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT DISTINCT user_id
            FROM allowed_users
            WHERE user_id IS NOT NULL
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Не удалось загрузить allowed_users из БД: %s", e)
        return []

    ids: List[int] = []
    for row in rows:
        uid = row.get("user_id")
        if uid is None:
            continue
        try:
            ids.append(int(uid))
        except (TypeError, ValueError):
            continue
    return ids


# ---------------- AI-фильтр (OpenAI) ----------------

def is_relevant_job(text: str) -> bool:
    """
    AI-фильтр: определяет, является ли текст вакансией / предложением работы.
    Если USE_AI_FILTER=False, всегда возвращает True.
    Здесь ты уже подключаешь openai.ChatCompletion и т.п. (не приводится целиком, т.к. логика была настроена ранее).
    """
    if not USE_AI_FILTER:
        return True

    # Здесь должна быть твоя актуальная реализация с openai.
    # Я оставляю заглушку, чтобы не ломать существующую интеграцию.
    try:
        from openai import OpenAI
        client = OpenAI()

        prompt = (
            "You are a filter that checks if a text describes a job vacancy or job offer. "
            "Answer ONLY 'YES' or 'NO'."
        )

        resp = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": text[:4000]},
            ],
            max_tokens=1,
            temperature=0,
        )
        answer = (resp.choices[0].message.content or "").strip().upper()
        relevant = answer.startswith("YES") or answer.startswith("Y")
        logger.info("AI-фильтр: %s -> %s", answer, "relevant" if relevant else "irrelevant")
        return relevant
    except Exception as e:
        logger.error("Ошибка AI-фильтра: %s", e)
        # В случае ошибки не блокируем вакансии
        return True


# ---------------- Healthcheck ----------------


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


# ---------------- Системные алерты от парсеров (TG/FB) ----------------


@app.route("/api/alert", methods=["POST"])
def api_alert():
    """
    Эндпоинт для системных уведомлений от парсеров.

    Авторизация:
      - Заголовок X-API-KEY == API_SECRET (если API_SECRET задан)
      - Для обратной совместимости также принимаем X-API-SECRET

    Тело JSON:
    {
      "source": "tg_parser" | "fb_parser" | "...",
      "message": "..."
    }
    """
    if API_SECRET:
        key = request.headers.get("X-API-KEY")
        legacy = request.headers.get("X-API-SECRET")
        if key != API_SECRET and legacy != API_SECRET:
            return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "unknown").strip()
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message_required"}), 400

    text = f"Источник: {source}\n\n{message}"
    logger.warning("ALERT from %s: %s", source, message)

    try:
        send_alert_human(text)
    except Exception as e:
        logger.error("Ошибка отправки алерта в Telegram: %s", e)

    return jsonify({"status": "ok"})



# ---------------- Проверка доступа к миниаппу ----------------


@app.route("/api/check_access", methods=["POST"])
def check_access():
    """
    Принимает user_id и username из Telegram WebApp и говорит, можно ли пускать пользователя.
    Ожидаем тело:
    {
      "user_id": 123456789,
      "username": "DemySkWear"
    }
    """
    data = request.get_json(silent=True) or {}
    user_id_raw = data.get("user_id")
    username_raw = data.get("username")  # может быть None

    username_norm = _username_norm(username_raw)
    allowed = is_user_allowed(username_norm)
    admin_flag = is_admin(username_norm)

    logger.info(
        "check_access: username_raw=%r norm=%r allowed=%s admin=%s ADMINS=%r",
        username_raw,
        username_norm,
        allowed,
        admin_flag,
        ADMINS,
    )

    # Аккуратно приводим user_id к int (если он есть)
    user_id_int: Optional[int] = None
    try:
        if user_id_raw is not None:
            user_id_int = int(user_id_raw)
    except (TypeError, ValueError):
        user_id_int = None

    # Если юзер допущен и есть нормальный username — сохраняем/обновляем его в allowed_users
    if allowed and username_norm:
        upsert_allowed_user(username_norm, user_id_int)

    return jsonify(
        {
            "allowed": allowed,
            "is_admin": admin_flag,
            "username": username_raw,
            "normalized_username": username_norm,
            "user_id": user_id_raw,
        }
    )




# ---------------- Telegram уведомления (для парсеров) ----------------

def send_notifications_to_users(text: str, link: Optional[str], chat_title: Optional[str], sender_username: Optional[str]):
    """
    Функция, которую можно вызывать после сохранения вакансии,
    чтобы разослать уведомления пользователям через Telegram-бота.
    Здесь у тебя уже была своя реализация, использующая TELEGRAM_BOT_TOKEN, и т.п.
    Я оставляю существующий код (в репо он уже был), только оборачиваю.
    """
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    if not TELEGRAM_BOT_TOKEN:
        logger.info("TELEGRAM_BOT_TOKEN не задан, уведомления не отправляем")
        return

    user_ids = load_allowed_user_ids_from_db()
    if not user_ids:
        logger.info("Нет пользователей с user_id — уведомлять некого")
        return

    import requests

    chat_title = chat_title or "Telegram канала"
    short_text = (text or "").strip()

    # Обрезаем текст для превью
    if len(short_text) > 400:
        short_text = short_text[:400] + "…"

    # Основной текст уведомления
    msg = (
        f"📢 *Получена вакансия из группы:* _{chat_title}_\n\n"
        f"📝 *Краткое описание:*\n{short_text}\n"
    )

    # Inline-кнопки
    inline_keyboard = []

    # Кнопка "Открыть пост"
    if link:
        inline_keyboard.append(
            [
                {"text": "🔗 Открыть пост", "url": link}
            ]
        )

    # Кнопка "Написать автору" (для Telegram-источников)
    if sender_username:
        if not sender_username.startswith("@"):
            sender_username_display = f"@{sender_username}"
        else:
            sender_username_display = sender_username
        inline_keyboard.append(
            [
                {
                    "text": "✉️ Написать автору",
                    "url": f"https://t.me/{sender_username_display.lstrip('@')}",
                }
            ]
        )

    payload = {
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
        "reply_markup": {"inline_keyboard": inline_keyboard} if inline_keyboard else None,
    }

    for user_id in user_ids:
        try:
            data = {
                "chat_id": user_id,
                "text": msg,
                **payload,
            }
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json=data,
                timeout=10,
            )
        except Exception as e:
            logger.error("Ошибка отправки уведомления пользователю %s: %s", user_id, e)


def send_alert_human(text: str):
    """
    Дублирует системные ошибки в Telegram-чат
    """
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    if not TELEGRAM_BOT_TOKEN:
        logger.error("Нет TELEGRAM_BOT_TOKEN — алерт не отправлен")
        return

    user_ids = load_allowed_user_ids_from_db()
    if not user_ids:
        return

    for user_id in user_ids:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": user_id,
                    "text": f"🚨 СИСТЕМНОЕ УВЕДОМЛЕНИЕ\n\n{text}",
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
        except Exception as e:
            logger.error("Ошибка отправки алерта: %s", e)



# ---------------- Список каналов (Telegram) ----------------


@app.route("/api/channels", methods=["GET"])
def list_channels():
    """
    Отдаём только Telegram-источники из fb_groups:
    group_id ILIKE '%t.me/%' или group_id LIKE '@%'.
    Используется фронтом (вкладка TG-каналы).
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, added_at
            FROM fb_groups
            WHERE group_id ILIKE '%t.me/%'
               OR group_id LIKE '@%'
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки каналов: %s", e)
        return jsonify({"channels": []})

    def _iso(dt):
        if not dt:
            return None
        return dt.isoformat()

    channels = []
    for row in rows:
        channels.append(
            {
                "id": row["id"],
                "group_id": row["group_id"],
                "group_name": row.get("group_name") or row["group_id"],
                "enabled": row.get("enabled", True),
                "added_at": _iso(row.get("added_at")),
            }
        )

    return jsonify({"channels": channels})


# ---------------- Список FB-групп ----------------


@app.route("/api/fb_groups", methods=["GET"])
def list_fb_groups():
    """
    Отдаём только Facebook-группы из fb_groups:
    group_id ILIKE '%facebook.com%' или '%fb.com%'.
    Используется fb_parser и веб-интерфейс (вкладка Facebook).
    Пример ответа:
    {
      "groups": [
        {
          "id": 1,
          "group_url": "https://www.facebook.com/groups/....",
          "group_name": "Название группы",
          "enabled": true,
          "added_at": "2025-12-01T12:34:56Z"
        },
        ...
      ]
    }
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, added_at
            FROM fb_groups
            WHERE group_id ILIKE '%facebook.com%'
               OR group_id ILIKE '%fb.com%'
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки FB-групп: %s", e)
        return jsonify({"groups": []})

    def _iso(dt):
        if not dt:
            return None
        return dt.isoformat()

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


# ---------------- Совместимость для старых парсеров (/api/groups) ----------------


@app.route("/api/groups", methods=["GET"])
def list_groups_legacy():
    """
    Старый эндпоинт для парсеров.
    Возвращает те же данные, что и /api/channels, но в виде {"groups": [...]}.
    Используется tg_parser.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, added_at
            FROM fb_groups
            WHERE group_id ILIKE '%t.me/%'
               OR group_id LIKE '@%'
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки legacy groups: %s", e)
        return jsonify({"groups": []})

    def _iso(dt):
        if not dt:
            return None
        return dt.isoformat()

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


# ---------------- Управление источниками (TG/FB) ----------------


@app.route("/api/source", methods=["POST"])
def add_source():
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
        logger.error("Ошибка добавления источника: %s", e)
        return jsonify({"error": "db_error"}), 500

    conn.close()

    def _iso(dt):
        if not dt:
            return None
        return dt.isoformat()

    return jsonify(
        {
            "id": row["id"],
            "group_id": row["group_id"],
            "group_name": row.get("group_name") or row["group_id"],
            "enabled": row.get("enabled", True),
            "added_at": _iso(row.get("added_at")),
        }
    )


@app.route("/api/source/toggle", methods=["POST"])
def toggle_source():
    """
    Включение/выключение источника (TG/FB).
    Тело:
    {
      "group_id": "https://t.me/...",
      "enabled": true/false
    }
    """
    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()
    enabled = data.get("enabled")

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400
    if enabled is None:
        return jsonify({"error": "enabled is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE fb_groups
            SET enabled = %s
            WHERE group_id = %s
            """,
            (bool(enabled), group_id),
        )
        updated = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка toggle источника: %s", e)
        return jsonify({"error": "db_error"}), 500

    conn.close()
    if updated == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "ok"})


@app.route("/api/source/delete", methods=["POST"])
def delete_source():
    """
    Удаление источника.
    Тело:
    {
      "group_id": "https://t.me/..."
    }
    """
    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()

    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM fb_groups WHERE group_id = %s", (group_id,))
        deleted = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка удаления источника: %s", e)
        return jsonify({"error": "db_error"}), 500

    conn.close()
    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ---------------- Admin: allowed_users ----------------


@app.route("/api/allowed_users", methods=["GET"])
def list_allowed_users():
    """
    Список пользователей, которым выдан доступ через админку.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, username, user_id, updated_at
            FROM allowed_users
            ORDER BY username ASC
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки allowed_users: %s", e)
        return jsonify([])

    def _iso(dt):
        if not dt:
            return None
        return dt.isoformat()

    users = []
    for row in rows:
        users.append(
            {
                "id": row["id"],
                "username": row["username"],
                "user_id": row.get("user_id"),
                "updated_at": _iso(row.get("updated_at")),
            }
        )
    return jsonify(users)


@app.route("/api/allowed_users", methods=["POST"])
def add_allowed_user():
    """
    Добавление/обновление пользователя с доступом по username.
    user_id заполнится, когда он зайдёт в миниапп (через check_access).
    """
    data = request.get_json(silent=True) or {}
    username_raw = (data.get("username") or "").strip()
    username_norm = _username_norm(username_raw)

    if not username_norm:
        return jsonify({"error": "username is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO allowed_users (username, user_id, updated_at)
            VALUES (%s, NULL, NOW())
            ON CONFLICT (username) DO UPDATE SET
                updated_at = EXCLUDED.updated_at
            RETURNING id, username, user_id, updated_at
            """,
            (username_norm,),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка добавления allowed_user: %s", e)
        return jsonify({"error": "db_error"}), 500

    conn.close()
    return jsonify(
        {
            "id": row["id"],
            "username": row["username"],
            "user_id": row.get("user_id"),
            "updated_at": _iso(row.get("updated_at")),
        }
    )


@app.route("/api/allowed_users/<int:allowed_id>", methods=["DELETE"])
def delete_allowed_user(allowed_id: int):
    """
    Удаление пользователя из allowed_users.
    (админов из ENV это не касается)
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM allowed_users WHERE id = %s", (allowed_id,))
        deleted = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка удаления allowed_user: %s", e)
        return jsonify({"error": "db_error"}), 500

    conn.close()
    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ---------------- Вакансии (основной список) ----------------


@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    """
    Возвращает последние N НЕархивных вакансий.
    Параметры:
      - limit (int, по умолчанию 50)
    """
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50
    if limit <= 0 or limit > 500:
        limit = 50

    try:
        conn = get_conn()
        # cursor_factory уже DictCursor в get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id,
                   source,
                   source_name,
                   external_id,
                   url,
                   text,
                   sender_username,
                   created_at,
                   received_at,
                   archived,
                   archived_at
            FROM jobs
            WHERE archived = FALSE
            ORDER BY received_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки jobs: %s", e)
        return jsonify({"jobs": []})

    jobs = []
    for row in rows:
        jobs.append(
            {
                "id": row["id"],
                "source": row["source"],
                "source_name": row.get("source_name"),
                "external_id": row["external_id"],
                "url": row.get("url"),
                "text": row.get("text"),
                "sender_username": row.get("sender_username"),
                "created_at": _iso(row.get("created_at")),
                "received_at": _iso(row.get("received_at")),
                "archived": row.get("archived", False),
                "archived_at": _iso(row.get("archived_at")),
            }
        )

    return jsonify({"jobs": jobs})



@app.route("/api/jobs/archive", methods=["GET"])
def list_archived_jobs():
    """
    Возвращает архивированные вакансии.
    ?limit=50
    """
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50
    if limit <= 0 or limit > 500:
        limit = 50

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, source, source_name, external_id, url, text, sender_username,
                   created_at, received_at, archived, archived_at
            FROM jobs
            WHERE archived = TRUE
            ORDER BY archived_at DESC NULLS LAST
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки архивных jobs: %s", e)
        return jsonify({"jobs": []})

    jobs = []
    for row in rows:
        jobs.append(
            {
                "id": row["id"],
                "source": row["source"],
                "source_name": row.get("source_name"),
                "external_id": row["external_id"],
                "url": row.get("url"),
                "text": row.get("text"),
                "sender_username": row.get("sender_username"),
                "created_at": _iso(row.get("created_at")),
                "received_at": _iso(row.get("received_at")),
                "archived": row.get("archived", False),
                "archived_at": _iso(row.get("archived_at")),
            }
        )
    return jsonify({"jobs": jobs})


# ---------------- Действия с вакансиями (архив / удаление) ----------------


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def archive_job(job_id: int):
    """
    Перемещает вакансию в архив.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE jobs
            SET archived = TRUE,
                archived_at = NOW()
            WHERE id = %s
            """,
            (job_id,),
        )
        updated = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Ошибка архивации job %s: %s", job_id, e)
        return jsonify({"error": "db_error"}), 500

    if updated == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "archived"})


@app.route("/api/jobs/<int:job_id>/unarchive", methods=["POST"])
def unarchive_job(job_id: int):
    """
    Возвращает вакансию из архива.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE jobs
            SET archived = FALSE,
                archived_at = NULL
            WHERE id = %s
            """,
            (job_id,),
        )
        updated = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Ошибка разархивации job %s: %s", job_id, e)
        return jsonify({"error": "db_error"}), 500

    if updated == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "unarchived"})


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])
def delete_job(job_id: int):
    """
    Полное удаление вакансии.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Ошибка удаления job %s: %s", job_id, e)
        return jsonify({"error": "db_error"}), 500

    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ---------------- Приём вакансий от парсеров (TG + FB) ----------------


@app.route("/post", methods=["POST"])
def receive_post():
    """
    Эндпоинт для tg-parser и fb-parser (через Apify).

    Заголовок: X-API-KEY == API_SECRET (если он задан), иначе 403.
    Тело JSON:
    {
      "source": str,          # "telegram" или "facebook" или что-то своё
      "source_name": str|null,# не обязателен, но лучше передавать имя канала/группы
      "external_id": str,     # уникальный ID поста в рамках source
      "url": str|null,        # ссылка на пост
      "text": str,
      "sender_username": str|null,  # username автора (для Telegram), для FB можно не заполнять
      "created_at": ISO-строка или null
    }
    """
    if API_SECRET and request.headers.get("X-API-KEY") != API_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}

    source = data.get("source")
    source_name = data.get("source_name")
    external_id = data.get("external_id")
    url = data.get("url")
    text = data.get("text") or ""
    sender_username = data.get("sender_username")
    created_at_raw = data.get("created_at")

    if not source or not external_id:
        return jsonify({"error": "source and external_id are required"}), 400

    created_at = None
    if created_at_raw:
        try:
            created_at = datetime.fromisoformat(str(created_at_raw).replace("Z", "+00:00"))
        except Exception:
            created_at = None

    # AI-фильтр
    if not is_relevant_job(text):
        logger.info("Пост %s/%s отфильтрован как нерелевантный", source, external_id)
        return jsonify({"status": "irrelevant"})

    # Сохранение в базу
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO jobs (source, source_name, external_id, url, text, sender_username, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (external_id, source) DO NOTHING
            RETURNING id, source, source_name, url, text, sender_username
            """,
            (source, source_name, external_id, url, text, sender_username, created_at),
        )
        row = cur.fetchone()
        if not row:
            conn.commit()
            conn.close()
            logger.info("Дубликат сообщения %s / %s", source, external_id)
            return jsonify({"status": "duplicate"})
        job_id = row["id"]
        saved_source = row["source"]
        saved_source_name = row.get("source_name")
        saved_url = row.get("url")
        saved_text = row.get("text") or ""
        saved_sender_username = row.get("sender_username")
        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка сохранения вакансии: %s", e)
        return jsonify({"error": "db_error"}), 500

    logger.info("Сохранена вакансия id=%s (%s / %s)", job_id, source, external_id)

    # Отправляем уведомления пользователям
    send_notifications_to_users(
        text=saved_text,
        link=saved_url,
        chat_title=saved_source_name,
        sender_username=saved_sender_username,
    )

    return jsonify({"status": "ok", "id": job_id})


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------- Точка входа ----------------

if __name__ == "__main__":
    logger.info("Инициализация БД...")
    init_db()
    logger.info("Запуск Flask на порту %s", PORT)
    app.run(host="0.0.0.0", port=PORT)
