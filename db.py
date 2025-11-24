import os
import psycopg2
import psycopg2.extras

DATABASE_URL = os.getenv("DATABASE_URL")   # <-- только так!

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS fb_groups (
        id SERIAL PRIMARY KEY,
        group_id TEXT NOT NULL,
        group_name TEXT,
        enabled BOOLEAN DEFAULT TRUE,
        added_at TIMESTAMPTZ DEFAULT NOW()
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id SERIAL PRIMARY KEY,
        source TEXT NOT NULL,
        source_name TEXT,
        external_id TEXT NOT NULL,
        url TEXT,
        text TEXT,
        created_at TIMESTAMPTZ,
        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (external_id, source)
    );
    """)

    conn.commit()
    conn.close()
