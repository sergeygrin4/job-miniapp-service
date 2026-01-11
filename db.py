import os
import psycopg2
import psycopg2.extras

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")


def get_conn():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Источники (и TG, и FB)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS fb_groups (
            id SERIAL PRIMARY KEY,
            group_id TEXT NOT NULL UNIQUE,
            group_name TEXT,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )

    # Таблица постов / вакансий
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            source_name TEXT,
            external_id TEXT NOT NULL,
            url TEXT,
            text TEXT,
            sender_username TEXT,
            created_at TIMESTAMPTZ,
            received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            archived BOOLEAN NOT NULL DEFAULT FALSE,
            archived_at TIMESTAMPTZ,
            UNIQUE (external_id, source)
        );
        """
    )

    # Поддержка старых схем (безопасно, если колонки уже есть)
    cur.execute("""ALTER TABLE jobs ADD COLUMN IF NOT EXISTS sender_username TEXT;""")
    cur.execute("""ALTER TABLE jobs ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE;""")
    cur.execute("""ALTER TABLE jobs ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;""")

    # Пользователи
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS allowed_users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            user_id BIGINT,
            updated_at TIMESTAMPTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )

    # Хранилище секретов для парсеров (FB cookies, TG StringSession и т.п.)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS parser_secrets (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        """
    )

    # Статусы/события по парсерам (когда выбило, когда были ошибки)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS parser_status (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        """
    )

    conn.commit()
    conn.close()


# ---------- Secrets / Status helpers ----------

def get_secret(key: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key, value, updated_at FROM parser_secrets WHERE key = %s", (key,))
    row = cur.fetchone()
    conn.close()
    return row


def set_secret(key: str, value: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO parser_secrets (key, value, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (key) DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = EXCLUDED.updated_at
        """,
        (key, value),
    )
    conn.commit()
    conn.close()


def get_status(key: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key, value, updated_at FROM parser_status WHERE key = %s", (key,))
    row = cur.fetchone()
    conn.close()
    return row


def set_status(key: str, value: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO parser_status (key, value, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (key) DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = EXCLUDED.updated_at
        """,
        (key, value),
    )
    conn.commit()
    conn.close()
