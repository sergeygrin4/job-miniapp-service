# db.py
import psycopg2
from psycopg2.extras import RealDictCursor
import os

DATABASE_URL = os.getenv("DATABASE_URL")

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # таблица пользователей (для админки)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        tg_id BIGINT UNIQUE NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE
    );
    """)

    # Telegram источники
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tg_groups (
        id SERIAL PRIMARY KEY,
        group_link TEXT UNIQUE NOT NULL,
        enabled BOOLEAN DEFAULT TRUE
    );
    """)

    # Facebook источники
    cur.execute("""
    CREATE TABLE IF NOT EXISTS fb_groups (
        id SERIAL PRIMARY KEY,
        group_link TEXT UNIQUE NOT NULL,
        enabled BOOLEAN DEFAULT TRUE
    );
    """)

    # Лог отправленных вакансий
    cur.execute("""
    CREATE TABLE IF NOT EXISTS posts_sent (
        id SERIAL PRIMARY KEY,
        post_id TEXT UNIQUE NOT NULL,
        source TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)

    conn.commit()
    conn.close()


def add_tg_group(link):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tg_groups (group_link)
        VALUES (%s)
        ON CONFLICT (group_link) DO NOTHING;
    """, (link,))
    conn.commit()
    conn.close()


def add_fb_group(link):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO fb_groups (group_link)
        VALUES (%s)
        ON CONFLICT (group_link) DO NOTHING;
    """, (link,))
    conn.commit()
    conn.close()


def get_enabled_tg_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT group_link FROM tg_groups WHERE enabled = TRUE;")
    rows = cur.fetchall()
    conn.close()
    return [r["group_link"] for r in rows]


def get_enabled_fb_groups():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT group_link FROM fb_groups WHERE enabled = TRUE;")
    rows = cur.fetchall()
    conn.close()
    return [r["group_link"] for r in rows]


def add_sent_post(post_id, source):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO posts_sent (post_id, source)
        VALUES (%s, %s)
        ON CONFLICT (post_id) DO NOTHING;
    """, (post_id, source))
    conn.commit()
    conn.close()


def check_post_sent(post_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM posts_sent WHERE post_id = %s", (post_id,))
    row = cur.fetchone()
    conn.close()
    return row is not None
