import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(__file__), "techhubtr_users.db")

def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def add_column_if_missing(cursor, table_name, column_sql, column_name):
    if not column_exists(cursor, table_name, column_name):
        print(f"Kolon ekleniyor: {column_name}")
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")
    else:
        print(f"Zaten var: {column_name}")

def main():
    if not os.path.exists(DB_FILE):
        print("Veritabanı bulunamadı.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # USER TABLOSU YENİ ALANLAR
    add_column_if_missing(cursor, "user", "email_verification_token TEXT", "email_verification_token")
    add_column_if_missing(cursor, "user", "password_reset_token TEXT", "password_reset_token")
    add_column_if_missing(cursor, "user", "password_reset_expires_at DATETIME", "password_reset_expires_at")

    conn.commit()
    conn.close()
    print("Migration tamamlandı. Artık app.py çalıştırabilirsin.")

if __name__ == "__main__":
    main()