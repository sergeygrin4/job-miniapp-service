import os
import logging
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from telegram import Bot

from db import get_conn, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - mini_app - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

PORT = int(os.getenv("PORT", "8000"))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_SECRET = os.getenv("API_SECRET", "mvp-secret-key-2024")

bot = Bot(token=TELEGRAM_BOT_TOKEN) if TELEGRAM_BOT_TOKEN else None

app = Flask(__name__, static_folder="static", static_url_path="/")
CORS(app)


def require_secret(req: request) -> bool:
    header_secret = req.headers.get("X-API-KEY")
    return bool(header_secret and header_secret == API_SECRET)


def send_to_telegram(text: str, url: str | None = None) -> None:
    if not bot or not TELEGRAM_CHAT_ID:
        logger.warning(
            "TELEGRAM_BOT_TOKEN или TELEGRAM_CHAT_ID не заданы — не отправляю в Telegram"
        )
        return
    message = text
    if url:
        message += f"\n\n{url}"
    bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)


with app.app_context():
    init_db()
    logger.info("✅ DB initialized")


# ================== health ==================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ================== GROUPS (для fb_parser) ==================
@app.route("/api/groups", methods=["GET"])
def list_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, group_id, group_name, enabled, added_at
        FROM fb_groups
        ORDER BY id ASC
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
                "group_name": row["group_name"],
                "enabled": row["enabled"],
                "added_at": row["added_at"].isoformat() if row["added_at"] else None,
            }
        )
    return jsonify({"groups": groups})


@app.route("/api/groups", methods=["POST"])
def add_group():
    data = request.get_json() or {}
    group_id = data.get("group_id")
    group_name = data.get("group_name") or group_id
    if not group_id:
        return jsonify({"error": "group_id is required"}), 400

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO fb_groups (group_id, group_name, enabled)
            VALUES (%s, %s, TRUE)
            RETURNING id, group_id, group_name, enabled, added_at
            """,
            (group_id, group_name),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Ошибка добавления группы: {e}")
        return jsonify({"error": "db_error"}), 500
    conn.close()
    return jsonify(
        {
            "id": row["id"],
            "group_id": row["group_id"],
            "group_name": row["group_name"],
            "enabled": row["enabled"],
            "added_at": row["added_at"].isoformat() if row["added_at"] else None,
        }
    )


@app.route("/api/groups/<int:group_id>/toggle", methods=["POST"])
def toggle_group(group_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE fb_groups
            SET enabled = NOT enabled
            WHERE id = %s
            RETURNING id, group_id, group_name, enabled, added_at
            """,
            (group_id,),
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
        logger.error(f"Ошибка переключения группы: {e}")
        return jsonify({"error": "db_error"}), 500
    conn.close()
    return jsonify(
        {
            "id": row["id"],
            "group_id": row["group_id"],
            "group_name": row["group_name"],
            "enabled": row["enabled"],
            "added_at": row["added_at"].isoformat() if row["added_at"] else None,
        }
    )


@app.route("/api/groups/<int:group_id>", methods=["DELETE"])
def delete_group(group_id: int):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM fb_groups WHERE id = %s", (group_id,))
        deleted = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Ошибка удаления группы: {e}")
        return jsonify({"error": "db_error"}), 500
    conn.close()
    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ================== CHANNELS (под фронт «Каналы») ==================
@app.route("/api/channels", methods=["GET"])
def list_channels():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, group_id, group_name, enabled, added_at
            FROM fb_groups
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка загрузки каналов: {e}")
        return jsonify({"channels": []})

    channels = []
    for row in rows:
        channels.append(
            {
                "id": row["id"],
                "username": row["group_id"],
                "title": row["group_name"],
                "enabled": row["enabled"],
                "added_at": row["added_at"].isoformat() if row["added_at"] else None,
            }
        )
    return jsonify({"channels": channels})


@app.route("/api/channels", methods=["POST"])
def add_channel():
    data = request.get_json() or {}
    username = data.get("username")
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
            RETURNING id, group_id, group_name, enabled, added_at
            """,
            (group_id, group_name),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Ошибка добавления канала: {e}")
        return jsonify({"error": "Канал уже добавлен или ошибка БД"}), 400
    conn.close()
    return jsonify(
        {
            "id": row["id"],
            "username": row["group_id"],
            "title": row["group_name"],
            "enabled": row["enabled"],
            "added_at": row["added_at"].isoformat() if row["added_at"] else None,
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
        logger.error(f"Ошибка удаления канала: {e}")
        return jsonify({"error": "db_error"}), 500
    conn.close()
    if deleted == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": "deleted"})


# ================== JOBS (под вкладку «Вакансии») ==================
@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    try:
        limit_str = request.args.get("limit", "50")
        try:
            limit = int(limit_str)
        except (TypeError, ValueError):
            limit = 50

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, source, source_name, url, text, created_at, received_at
            FROM jobs
            ORDER BY COALESCE(created_at, received_at) DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка загрузки вакансий: {e}")
        return jsonify({"jobs": [], "total": 0})

    jobs = []
    for row in rows:
        created = row["created_at"] or row["received_at"]
        jobs.append(
            {
                "id": row["id"],
                "chat_title": row["source_name"] or row["source"],
                "created_at": created.isoformat() if created else None,
                "text": row["text"],
                "link": row["url"],
            }
        )
    return jsonify({"jobs": jobs, "total": len(jobs)})


# ================== Приём вакансий от парсеров ==================
@app.route("/post", methods=["POST"])
def receive_post():
    if not require_secret(request):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json() or {}
    source = data.get("source")
    source_name = data.get("source_name")
    external_id = data.get("external_id")
    url = data.get("url")
    text = data.get("text")
    created_at_str = data.get("created_at")

    if not source or not external_id or not text:
        return jsonify({"error": "source, external_id, text are required"}), 400

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
            INSERT INTO jobs (source, source_name, external_id, url, text, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (external_id, source) DO NOTHING
            RETURNING id;
            """,
            (source, source_name, external_id, url, text, created_at),
        )
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        logger.error(f"Ошибка записи вакансии: {e}")
        return jsonify({"error": "db_error"}), 500
    conn.close()

    if not row:
        return jsonify({"status": "duplicate"})

    try:
        send_to_telegram(text, url)
    except Exception as e:
        logger.error(f"Ошибка отправки в Telegram: {e}")

    return jsonify({"status": "ok", "id": row[0]})


# ================== Статика ==================
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    logger.info(f"Запуск Flask на порту {PORT}")
    app.run(host="0.0.0.0", port=PORT)
