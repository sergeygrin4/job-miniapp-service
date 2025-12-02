import os
import psycopg2
import psycopg2.extras

# URL подключения к Postgres.
# В Railway это переменная окружения DATABASE_URL.
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
    """
    Создание таблиц и добавление недостающих колонок.

    Здесь лежит всё, что нужно миниаппу:
    - fb_groups: источники (и Telegram, и Facebook — просто «группы/каналы»)
    - jobs: вакансии / посты
    - allowed_users: пользователи с доступом к миниаппу
    """
    conn = get_conn()
    cur = conn.cursor()

    # Таблица источников (каналы/группы Telegram и Facebook)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS fb_groups (
            id SERIAL PRIMARY KEY,
            group_id TEXT NOT NULL UNIQUE,   -- ссылка или @username
            group_name TEXT,                 -- красивое имя
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )

    # Таблица вакансий / постов
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,          -- откуда пришёл пост (tg_channel, fb_group и т.п.)
            source_name TEXT,              -- человекочитаемое имя источника
            external_id TEXT NOT NULL,     -- внешний ID поста (message_id в TG, id поста в FB)
            url TEXT,                      -- ссылка на пост
            text TEXT,                     -- текст поста
            sender_username TEXT,          -- автор (username в TG, можно NULL)
            created_at TIMESTAMPTZ,        -- время создания поста в источнике
            received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- когда мы его записали
            archived BOOLEAN NOT NULL DEFAULT FALSE,
            archived_at TIMESTAMPTZ,
            UNIQUE (external_id, source)
        );
        """
    )

    # На случай, если jobs уже существовала, но без новых колонок — аккуратные ALTER'ы
    cur.execute(
        """
        ALTER TABLE jobs
        ADD COLUMN IF NOT EXISTS sender_username TEXT;
        """
    )
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

    # Таблица разрешённых пользователей (по username)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS allowed_users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,          -- нормализованный username (без @, в нижнем регистре)
            user_id BIGINT,                         -- Telegram user_id, если знаем
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )

    conn.commit()
    conn.close()
