import sqlite3

DB_PATH = "shop.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# email_verified 컬럼 추가 (이미 있으면 에러 무시)
try:
    cur.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;")
    print("email_verified 컬럼 추가됨")
except:
    print("email_verified 이미 존재함")

# verification_token 컬럼 추가 (이미 있으면 에러 무시)
try:
    cur.execute("ALTER TABLE users ADD COLUMN verification_token TEXT;")
    print("verification_token 컬럼 추가됨")
except:
    print("verification_token 이미 존재함")

conn.commit()
conn.close()

print("DB migration 완료")