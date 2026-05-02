import sqlite3

from database import get_db_connection


def create_user(username, password_hash, role="user"):
    try:
        with get_db_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, role),
            )
            connection.commit()
            return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(username):
    with get_db_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_user_by_id(user_id):
    with get_db_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def delete_user(user_id):
    with get_db_connection() as connection:
        cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        connection.commit()
        return cursor.rowcount > 0
