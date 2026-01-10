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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fb_groups (
            id SERIAL PRIMARY KEY,
            group_id TEXT NOT NULL UNIQUE,
            group_name TEXT,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    # Таблица постов / вакансий
    cur.execute("""
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
    """)

    cur.execute("""
        ALTER TABLE jobs
        ADD COLUMN IF NOT EXISTS sender_username TEXT;
    """)

    cur.execute("""
        ALTER TABLE jobs
        ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE;
    """)

    cur.execute("""
        ALTER TABLE jobs
        ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
    """)

    # Пользователи
    cur.execute("""
        CREATE TABLE IF NOT EXISTS allowed_users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            user_id BIGINT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)


        cur.execute("""
        CREATE TABLE IF NOT EXISTS parser_secrets (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # Статусы/события по парсерам (когда выбило, когда были ошибки)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS parser_status (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    conn.commit()
    conn.close()


# ---------- Методы для TG и FB групп ----------

def get_all_groups():
    """Отдаёт всё — и FB, и TG. TG определяется по t.me."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM fb_groups ORDER BY id;")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_tg_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM fb_groups
        WHERE group_id LIKE 'http%%t.me%%' OR group_id LIKE 't.me%%'
        ORDER BY id;
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_fb_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM fb_groups
        WHERE group_id LIKE 'http%%facebook.com%%'
           OR group_id LIKE 'https://www.facebook.com%%'
           OR group_id LIKE '%facebook.com/groups/%'
        ORDER BY id;
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def add_group(group_id, group_name):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO fb_groups (group_id, group_name)
        VALUES (%s, %s)
        ON CONFLICT (group_id) DO UPDATE SET
            group_name = EXCLUDED.group_name;
    """, (group_id, group_name))
    conn.commit()
    conn.close()


def disable_group(group_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE fb_groups SET enabled = FALSE WHERE group_id = %s;
    """, (group_id,))
    conn.commit()
    conn.close()


def enable_group(group_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE fb_groups SET enabled = TRUE WHERE group_id = %s;
    """, (group_id,))
    conn.commit()
    conn.close()


def delete_group(group_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM fb_groups WHERE group_id = %s;", (group_id,))
    conn.commit()
    conn.close()
