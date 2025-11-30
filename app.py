import os
import logging
from datetime import datetime

import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from db import get_conn, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - mini_app - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

PORT = int(os.getenv("PORT", "8080"))
API_SECRET = os.getenv("API_SECRET") or ""

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or ""
ALLOWED_USER_IDS_ENV = os.getenv("ALLOWED_USER_IDS", "").strip()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or ""
AI_FILTER_ENABLED = os.getenv("AI_FILTER_ENABLED", "false").lower() in ("1", "true", "yes")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")

# Разбираем ALLOWED_USER_IDS в множество int
ALLOWED_USER_IDS = set()
if ALLOWED_USER_IDS_ENV:
    for part in ALLOWED_USER_IDS_ENV.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ALLOWED_USER_IDS.add(int(part))
        except ValueError:
            logger.warning("Некорректный user_id в ALLOWED_USER_IDS: %s", part)

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# Инициализируем БД при старте
init_db()


# ---------------- Утилиты ----------------

def _iso(dt):
    if not dt:
        return None
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def is_user_allowed(user_id: int | None) -> bool:
    """
    Если ALLOWED_USER_IDS пустой — доступ всем.
    Если не пустой — только тем ID, которые там есть.
    """
    if not ALLOWED_USER_IDS:
        return True
    if user_id is None:
        return False
    try:
        user_id_int = int(user_id)
    except (TypeError, ValueError):
        return False
    return user_id_int in ALLOWED_USER_IDS


def is_relevant_job(text: str | None) -> bool:
    """
    AI-фильтр нерелевантных вакансий.
    Возвращает True, если пост релевантен и его стоит сохранить.
    Если фильтр выключен/сломался — возвращаем True (fail-open).
    """
    if not AI_FILTER_ENABLED:
        return True
    if not OPENAI_API_KEY:
        logger.warning("AI_FILTER_ENABLED=true, но OPENAI_API_KEY не задан — фильтр отключён")
        return True
    if not text:
        return False

    try:
        from openai import OpenAI
    except ImportError:
        logger.warning("Библиотека 'openai' не установлена — AI-фильтр отключён")
        return True

    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = (
        "Ты фильтруешь сообщения и решаешь, является ли текст релевантной вакансией "
        "или предложением работы/сотрудничества. "
        "Ответь строго ОДНИМ словом: YES (если это вакансия/поиск исполнителя/работа/заказ) "
        "или NO (если это не про работу, рекрутинг, заказ, поиск исполнителя)."
    )

    try:
        resp = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": text[:4000]},
            ],
            max_tokens=1,
            temperature=0,
        )
        answer = resp.choices[0].message.content.strip().upper()
        relevant = answer.startswith("Y")
        logger.info("AI-фильтр: %s -> %s", answer, "relevant" if relevant else "irrelevant")
        return relevant
    except Exception as e:
        logger.error("Ошибка AI-фильтра: %s", e)
        # Если фильтр сломался — лучше не выкидывать пост
        return True


def notify_users_about_job(chat_title: str | None, text: str | None, link: str | None):
    """
    Шлём нотификации в Telegram тем юзерам, чьи ID указаны в ALLOWED_USER_IDS.
    Работает только если TELEGRAM_BOT_TOKEN и ALLOWED_USER_IDS заданы.
    """
    if not TELEGRAM_BOT_TOKEN:
        return
    if not ALLOWED_USER_IDS:
        return

    if not text:
        text = ""
    short_text = text.strip()
    if len(short_text) > 200:
        short_text = short_text[:200] + "…"

    title = chat_title or "канала"

    msg = f"Новая вакансия из {title}:\n\n{short_text}"
    if link:
        msg += f"\n\nСсылка: {link}"

    for user_id in ALLOWED_USER_IDS:
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": user_id,
                    "text": msg,
                    "disable_web_page_preview": True,
                },
                timeout=5,
            )
            if not resp.ok:
                logger.warning(
                    "Не удалось отправить уведомление %s: %s %s",
                    user_id,
                    resp.status_code,
                    resp.text,
                )
        except Exception as e:
            logger.error("Ошибка отправки уведомления пользователю %s: %s", user_id, e)


# ---------------- Проверка доступа к миниаппу ----------------

@app.route("/api/check_access", methods=["POST"])
def check_access():
    """
    Принимает user_id из Telegram WebApp и говорит, можно ли пускать пользователя.
    {
        "user_id": 123456789
    }
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")

    allowed = is_user_allowed(user_id)
    return jsonify({"allowed": allowed, "user_id": user_id})


# ---------------- TG-каналы (fb_groups) ----------------

@app.route("/api/channels", methods=["GET"])
def list_channels():
    """
    Отдаём только Telegram-источники из fb_groups:
    group_id ILIKE '%t.me/%' или group_id LIKE '@%'.
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, added_at
            FROM fb_groups
            WHERE group_id ILIKE '%%t.me/%%'
               OR group_id LIKE '@%%'
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки каналов: %s", e)
        return jsonify({"channels": []})

    channels = []
    for row in rows:
        channels.append(
            {
                "id": row["id"],
                "username": row["group_id"],
                "title": row.get("group_name") or row["group_id"],
                "enabled": row.get("enabled", True),
                "added_at": _iso(row.get("added_at")),
            }
        )
    return jsonify({"channels": channels})


@app.route("/api/channels", methods=["POST"])
def add_channel():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    if not username:
        return jsonify({"error": "username is required"}), 400

    group_id = username
    group_name = username

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
            (group_id, group_name),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка добавления канала: %s", e)
        return jsonify({"error": "db_error"}), 500

    conn.close()
    return jsonify(
        {
            "id": row["id"],
            "username": row["group_id"],
            "title": row["group_name"],
            "enabled": row["enabled"],
            "added_at": _iso(row["added_at"]),
        }
    )


@app.route("/api/channels/<int:channel_id>", methods=["DELETE"])
def delete_channel(channel_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM fb_groups WHERE id = %s", (channel_id,))
        deleted = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка удаления канала: %s", e)
        return jsonify({"error": "db_error"}), 500
    conn.close()
    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ---------------- Вакансии (основной список) ----------------

@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    """
    Активные (не в архиве) вакансии для вкладки «Вакансии».
    Плюс простая статистика.
    """
    limit_str = request.args.get("limit", "50")
    try:
        limit = int(limit_str)
    except (TypeError, ValueError):
        limit = 50

    try:
        conn = get_conn()
        cur = conn.cursor()

        # Список вакансий
        cur.execute(
            """
            SELECT id, source, source_name, url, text, sender_username, created_at, received_at
            FROM jobs
            WHERE archived = FALSE
            ORDER BY COALESCE(created_at, received_at) DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()

        # Статистика
        cur.execute("SELECT COUNT(*) AS cnt FROM jobs WHERE archived = FALSE")
        total_row = cur.fetchone() or {"cnt": 0}
        cur.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM jobs
            WHERE archived = FALSE
              AND received_at > NOW() - INTERVAL '1 day'
            """
        )
        last_row = cur.fetchone() or {"cnt": 0}

        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки вакансий: %s", e)
        return jsonify({"jobs": [], "total": 0, "stats": {}})

    jobs = []
    for row in rows:
        created = row.get("created_at") or row.get("received_at")
        jobs.append(
            {
                "id": row["id"],
                "chat_title": row.get("source_name") or row.get("source"),
                "created_at": _iso(created),
                "text": row.get("text") or "",
                "link": row.get("url"),
                "sender_username": row.get("sender_username"),
            }
        )

    stats = {
        "total": total_row.get("cnt", 0),
        "last_24h": last_row.get("cnt", 0),
    }

    return jsonify({"jobs": jobs, "total": len(jobs), "stats": stats})


# ---------------- Архив вакансий ----------------

@app.route("/api/jobs/archive", methods=["GET"])
def list_archived_jobs():
    """
    Архив для вкладки «Архив».
    Тут же авточистка — удаляем то, что в архиве старше 7 дней.
    """
    limit_str = request.args.get("limit", "50")
    try:
        limit = int(limit_str)
    except (TypeError, ValueError):
        limit = 50

    try:
        conn = get_conn()
        cur = conn.cursor()

        # Автоудаление старого архива
        try:
            cur.execute(
                """
                DELETE FROM jobs
                WHERE archived = TRUE
                  AND archived_at IS NOT NULL
                  AND archived_at < NOW() - INTERVAL '7 days'
                """
            )
        except Exception as cleanup_err:
            logger.error("Ошибка автоочистки архива: %s", cleanup_err)

        # Список архивных
        cur.execute(
            """
            SELECT id, source, source_name, url, text, sender_username,
                   created_at, received_at, archived_at
            FROM jobs
            WHERE archived = TRUE
            ORDER BY COALESCE(created_at, received_at) DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Ошибка загрузки архива: %s", e)
        return jsonify({"jobs": [], "total": 0})

    jobs = []
    for row in rows:
        created = row.get("created_at") or row.get("received_at")
        jobs.append(
            {
                "id": row["id"],
                "chat_title": row.get("source_name") or row.get("source"),
                "created_at": _iso(created),
                "text": row.get("text") or "",
                "link": row.get("url"),
                "archived_at": _iso(row.get("archived_at")),
                "sender_username": row.get("sender_username"),
            }
        )

    return jsonify({"jobs": jobs, "total": len(jobs)})


@app.route("/api/jobs/<int:job_id>/archive", methods=["POST"])
def archive_job(job_id: int):
    """Перенос вакансии в архив."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE jobs
            SET archived = TRUE,
                archived_at = NOW()
            WHERE id = %s AND archived = FALSE
            RETURNING id
            """,
            (job_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            conn.close()
            return jsonify({"error": "not_found"}), 404
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка архивации вакансии: %s", e)
        return jsonify({"error": "db_error"}), 500
    conn.close()
    return jsonify({"status": "archived"})


@app.route("/api/jobs/<int:job_id>/restore", methods=["POST"])
def restore_job(job_id: int):
    """Вернуть вакансию из архива в основной список."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE jobs
            SET archived = FALSE,
                archived_at = NULL
            WHERE id = %s AND archived = TRUE
            RETURNING id
            """,
            (job_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            conn.close()
            return jsonify({"error": "not_found"}), 404
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка восстановления вакансии: %s", e)
        return jsonify({"error": "db_error"}), 500
    conn.close()
    return jsonify({"status": "restored"})


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])
def delete_job(job_id: int):
    """Полное удаление вакансии."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
        deleted = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка удаления вакансии: %s", e)
        return jsonify({"error": "db_error"}), 500
    conn.close()
    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ---------------- Приём вакансий от tg-parser ----------------

@app.route("/post", methods=["POST"])
def receive_post():
    """
    Эндпоинт для tg-parser.

    Заголовок: X-API-KEY == API_SECRET (иначе 403).
    Тело JSON:
    {
        "source": str,
        "source_name": str | null,
        "external_id": str,
        "url": str | null,
        "text": str,
        "sender_username": str | null,  # username автора поста, можно с @
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
    text = data.get("text")
    sender_username = data.get("sender_username")
    created_at_str = data.get("created_at")

    if not source or not external_id or not text:
        return jsonify({"error": "source, external_id, text are required"}), 400

    # AI-фильтр: если нерелевантно — просто не сохраняем
    if not is_relevant_job(text):
        logger.info("Пост %s/%s отфильтрован как нерелевантный", source, external_id)
        return jsonify({"status": "filtered_out"})

    created_at = None
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        except Exception:
            created_at = None

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO jobs (source, source_name, external_id, url, text, sender_username, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (external_id, source) DO NOTHING
            RETURNING id, source, source_name, url, text
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
        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error("Ошибка сохранения вакансии: %s", e)
        return jsonify({"error": "db_error"}), 500

    # Нотификации авторизованным юзерам
    notify_users_about_job(saved_source_name or saved_source, saved_text, saved_url)

    return jsonify({"status": "ok", "id": job_id})


# ---------------- Статика ----------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    logger.info("Запуск Flask на порту %s", PORT)
    app.run(host="0.0.0.0", port=PORT)
