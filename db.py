import os
import psycopg2
import psycopg2.extras

# Railway / DATABASE_URL
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

def get_conn():
    """Подключение к Postgres с RealDictCursor (строки как dict)."""
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )

def init_db():
    """Создание таблиц и добавление недостающих колонок."""
    conn = get_conn()
    cur = conn.cursor()

    # Источники (каналы/группы Telegram) — таблица уже была, но пусть создастся, если её нет
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

    # Вакансии
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            source_name TEXT,
            external_id TEXT NOT NULL,
            url TEXT,
            text TEXT,
            created_at TIMESTAMPTZ,
            received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            archived BOOLEAN NOT NULL DEFAULT FALSE,
            archived_at TIMESTAMPTZ,
            UNIQUE (external_id, source)
        );
        """
    )

    # На случай, если jobs уже существовала без новых колонок
    cur.execute(
        """
        ALTER TABLE jobs
        ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE;
        """
    )
    cur.execute(
        """
        ALTER TABLE jobs
        ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
        """
    )

    conn.commit()
    conn.close()
