# db.py
import os
import psycopg2
from psycopg2.extras import DictCursor

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("DATABASE_PUBLIC_URL")


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Таблица Facebook-групп (под фронтенд миниаппа)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS fb_groups (
            id SERIAL PRIMARY KEY,
            group_id TEXT UNIQUE NOT NULL,
            group_name TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )

    # Таблица вакансий (общая для FB и TG)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,              -- 'facebook' или 'telegram'
            source_name TEXT,
            external_id TEXT NOT NULL,         -- post_id / message_id + chat_id
            url TEXT,
            text TEXT,
            created_at TIMESTAMPTZ,
            received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (external_id, source)
        );
        """
    )

    conn.commit()
    conn.close()
