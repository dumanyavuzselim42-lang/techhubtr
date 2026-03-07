import json
import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "techhubtr_users.db")
OUT_PATH = os.path.join(BASE_DIR, "lessons_seed.json")

def main():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"DB bulunamadı: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT
            title, slug, main_category, sub_category, content,
            created_at, level, lesson_count, description
        FROM lesson
        ORDER BY created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()

    lessons = []
    for r in rows:
        lessons.append({
            "title": r["title"],
            "slug": r["slug"],
            "main_category": r["main_category"],
            "sub_category": r["sub_category"],
            "content": r["content"],
            "created_at": r["created_at"],
            "level": r["level"],
            "lesson_count": r["lesson_count"],
            "description": r["description"],
        })

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(lessons, f, ensure_ascii=False, indent=2)

    print(f"OK: {len(lessons)} ders export edildi -> {OUT_PATH}")

if __name__ == "__main__":
    main()