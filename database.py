import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = "security_app.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create demo admin account
    admin = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if not admin:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (
                "admin",
                generate_password_hash("Admin@12345"),
                "admin"
            )
        )

    connection.commit()
    connection.close()


def create_user(username, password):
    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                "user"
            )
        )

        connection.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        connection.close()


def get_user(username):
    connection = get_connection()

    user = connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    connection.close()

    return user


def get_all_users():
    connection = get_connection()

    users = connection.execute(
        """
        SELECT id, username, role, created_at
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return users


def add_log(username, action, ip_address):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO activity_logs
        (username, action, ip_address)
        VALUES (?, ?, ?)
        """,
        (username, action, ip_address)
    )

    connection.commit()
    connection.close()


def get_recent_logs(limit=20):
    connection = get_connection()

    logs = connection.execute(
        """
        SELECT *
        FROM activity_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    return logs


def get_security_statistics():
    connection = get_connection()

    total_users = connection.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    total_logs = connection.execute(
        "SELECT COUNT(*) FROM activity_logs"
    ).fetchone()[0]

    admin_users = connection.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    ).fetchone()[0]

    connection.close()

    return {
        "total_users": total_users,
        "total_logs": total_logs,
        "admin_users": admin_users
    }