import os
import json
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    g,
    flash,
    abort,
    jsonify,
    Response,
)

from werkzeug.security import generate_password_hash, check_password_hash

KST = timezone(timedelta(hours=9))

# =======================
# 기본 설정 + 경로 설정
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = "dev-secret-key-change-this"

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "환경변수 DATABASE_URL 이 설정되어 있지 않습니다. "
        "Neon의 Postgres connection string을 Render Environment에 DATABASE_URL로 넣어주세요."
    )

PRODUCT_FILE = os.path.join(BASE_DIR, "products.json")

ADMIN_EMAILS = {"022wasted@gmail.com", "i89624356@gmail.com"}


# =======================
# DB 관련 함수
# =======================
def get_db():
    if "db" not in g:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now_kst_str():
    return datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")


def now_kst_iso():
    return datetime.now(KST).isoformat(timespec="seconds")


def init_db():
    db = get_db()
    cur = db.cursor()

    # ---------- users ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    # ---------- inquiries ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS inquiries (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute("ALTER TABLE inquiries ADD COLUMN IF NOT EXISTS admin_reply TEXT")
    cur.execute("ALTER TABLE inquiries ADD COLUMN IF NOT EXISTS replied_at TEXT")

    # ---------- products ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            price INTEGER NOT NULL,
            image_url TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS sort_order INTEGER")
    cur.execute("UPDATE products SET sort_order = id WHERE sort_order IS NULL")

    # (구버전 호환: 남겨둬도 무방)
    cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS image_data BYTEA")
    cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS image_mime TEXT")

    # ---------- product_images ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS product_images (
            id SERIAL PRIMARY KEY,
            product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            image_data BYTEA,
            image_mime TEXT,
            image_url TEXT,
            sort_order INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )

    # ---------- color ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS product_colors (
            id SERIAL PRIMARY KEY,
            product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            color_name TEXT NOT NULL,
            image_id INTEGER REFERENCES product_images(id),
            created_at TEXT NOT NULL
        )
        """
    )

    # ---------- Size stock by color ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS product_color_variants (
            id SERIAL PRIMARY KEY,
            color_id INTEGER NOT NULL REFERENCES product_colors(id) ON DELETE CASCADE,
            size TEXT NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    db.commit()
    migrate_products_from_json_if_needed()


def migrate_products_from_json_if_needed():
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] > 0:
        return

    if not os.path.exists(PRODUCT_FILE):
        return

    with open(PRODUCT_FILE, "r", encoding="utf-8") as f:
        try:
            products = json.load(f)
        except Exception:
            products = []

    if not products:
        return

    now = now_kst_str()
    for p in products:
        name = p.get("name", "")
        price = int(p.get("price", 0))
        image_url = p.get("image_url") or "https://via.placeholder.com/600x800?text=PRODUCT"
        category = p.get("category") or "TOP"
        description = p.get("description") or ""

        cur.execute(
            """
            INSERT INTO products (name, price, image_url, category, description, created_at, sort_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (name, price, image_url, category, description, now, p.get("id", 0)),
        )

    db.commit()


# =======================
# products 헬퍼 (DB)
# =======================
def db_get_products(category: str | None = None):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if category and category != "ALL":
        cur.execute(
            """
            SELECT
                p.id, p.name, p.price, p.image_url, p.category, p.description,
                COALESCE(SUM(v.stock), 0) AS total_stock
            FROM products p
            LEFT JOIN product_colors c ON c.product_id = p.id
            LEFT JOIN product_color_variants v ON v.color_id = c.id
            WHERE p.category = %s
            GROUP BY p.id, p.name, p.price, p.image_url, p.category, p.description
            ORDER BY p.sort_order ASC, p.id DESC
            """,
            (category,),
        )
    else:
        cur.execute(
            """
            SELECT
                p.id, p.name, p.price, p.image_url, p.category, p.description,
                COALESCE(SUM(v.stock), 0) AS total_stock
            FROM products p
            LEFT JOIN product_colors c ON c.product_id = p.id
            LEFT JOIN product_color_variants v ON v.color_id = c.id
            GROUP BY p.id, p.name, p.price, p.image_url, p.category, p.description
            ORDER BY p.sort_order ASC, p.id DESC
            """
        )

    return cur.fetchall()


def db_get_product(product_id: int):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, name, price, image_url, category, description
        FROM products
        WHERE id = %s
        """,
        (product_id,),
    )
    return cur.fetchone()


def db_create_product(name, price, image_url, category, description, image_data=None, image_mime=None):
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT COALESCE(MAX(sort_order), 0) FROM products")
    new_order = cur.fetchone()[0] + 1

    now = now_kst_str()
    cur.execute(
        """
        INSERT INTO products (
            name, price, image_url, category, description,
            created_at, sort_order, image_data, image_mime
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (name, price, image_url, category, description, now, new_order, image_data, image_mime),
    )
    new_id = cur.fetchone()[0]
    db.commit()
    return new_id


def db_update_product(product_id, name, price, image_url, category, description, image_data=None, image_mime=None):
    db = get_db()
    cur = db.cursor()

    if image_data is not None and image_mime is not None:
        cur.execute(
            """
            UPDATE products
            SET name = %s,
                price = %s,
                image_url = %s,
                category = %s,
                description = %s,
                image_data = %s,
                image_mime = %s
            WHERE id = %s
            """,
            (name, price, image_url, category, description, image_data, image_mime, product_id),
        )
    else:
        cur.execute(
            """
            UPDATE products
            SET name = %s,
                price = %s,
                image_url = %s,
                category = %s,
                description = %s
            WHERE id = %s
            """,
            (name, price, image_url, category, description, product_id),
        )

    db.commit()


def db_delete_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
    db.commit()


def db_delete_user_and_related(user_id: int) -> bool:
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    if not user:
        return False
    if user["email"] in ADMIN_EMAILS:
        return False

    cur2 = db.cursor()
    cur2.execute("DELETE FROM inquiries WHERE user_id = %s", (user_id,))
    cur2.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    return True


def db_get_product_images(product_id: int):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, sort_order
        FROM product_images
        WHERE product_id = %s
        ORDER BY sort_order ASC, id ASC
        """,
        (product_id,),
    )
    return cur.fetchall()


def db_insert_product_images(product_id: int, files):
    db = get_db()
    cur = db.cursor()
    ts = now_kst_iso()

    cur.execute(
        "SELECT COALESCE(MAX(sort_order), 0) FROM product_images WHERE product_id=%s",
        (product_id,),
    )
    order = cur.fetchone()[0]

    inserted_ids = []

    for f in files:
        if not f or not getattr(f, "filename", ""):
            continue
        data = f.read()
        mime = f.mimetype or "image/jpeg"
        order += 1
        cur.execute(
            """
            INSERT INTO product_images (product_id, image_data, image_mime, image_url, sort_order, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (product_id, data, mime, "", order, ts),
        )
        inserted_ids.append(cur.fetchone()[0])

    db.commit()
    return inserted_ids


def db_get_colors(product_id):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT c.id, c.color_name, c.image_id
        FROM product_colors c
        WHERE c.product_id=%s
        ORDER BY c.id ASC
        """,
        (product_id,),
    )
    return cur.fetchall()


def db_get_color_variants(color_id):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT size, stock
        FROM product_color_variants
        WHERE color_id=%s
        ORDER BY
          CASE UPPER(size)
            WHEN 'XS' THEN 0
            WHEN 'S'  THEN 1
            WHEN 'M'  THEN 2
            WHEN 'L'  THEN 3
            WHEN 'XL' THEN 4
            WHEN 'XXL' THEN 5
            ELSE 99
          END,
          size ASC
    """, (color_id,))
    return cur.fetchall()

def db_get_color(color_id: int):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, product_id, color_name, image_id
        FROM product_colors
        WHERE id=%s
        """,
        (color_id,),
    )
    return cur.fetchone()


# ✅ FIX 1: 반드시 commit
def db_delete_colors_for_product(product_id: int):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM product_colors WHERE product_id=%s", (product_id,))
    db.commit()


# ✅ FIX 2: upsert 후 commit (edit에서 필수)
def db_upsert_color(product_id: int, color_name: str, image_id):
    db = get_db()
    cur = db.cursor()
    now = now_kst_str()

    cur.execute(
        """
        SELECT id FROM product_colors
        WHERE product_id=%s AND LOWER(color_name)=LOWER(%s)
        LIMIT 1
        """,
        (product_id, color_name),
    )
    row = cur.fetchone()

    if row:
        cid = row[0]
        cur.execute(
            """
            UPDATE product_colors
            SET image_id=%s
            WHERE id=%s
            """,
            (image_id, cid),
        )
    else:
        cur.execute(
            """
            INSERT INTO product_colors (product_id, color_name, image_id, created_at)
            VALUES (%s,%s,%s,%s)
            RETURNING id
            """,
            (product_id, color_name, image_id, now),
        )
        cid = cur.fetchone()[0]

    db.commit()
    return cid


# ✅ FIX 3: variants 교체 후 commit
def db_replace_color_variants(color_id: int, sizes: list[str], stocks: list[str]):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM product_color_variants WHERE color_id=%s", (color_id,))

    for s, st in zip(sizes, stocks):
        s = (s or "").strip()
        if not s:
            continue
        try:
            stock_i = int(st)
        except Exception:
            stock_i = 0
        cur.execute(
            """
            INSERT INTO product_color_variants (color_id, size, stock)
            VALUES (%s,%s,%s)
            """,
            (color_id, s.upper(), stock_i),
        )

    db.commit()


# =======================
# 템플릿 공통 컨텍스트
# =======================
def is_admin():
    return session.get("user_email") in ADMIN_EMAILS


@app.context_processor
def inject_user():
    return {
        "current_user_email": session.get("user_email"),
        "is_admin": is_admin(),
    }


# =======================
# 라우트: 메인 / 상품 목록
# =======================
@app.route("/shop")
def shop_list():
    category = request.args.get("category", "ALL")
    products = db_get_products(category)

    categories = ["ALL", "OUTER", "TOP", "BOTTOM", "ACCESSORIES"]
    return render_template(
        "shop_list.html",
        products=products,
        current_category=category,
        categories=categories,
    )


@app.route("/")
def index():
    return redirect(url_for("shop_list"))


# =======================
# 라우트: 회원가입
# =======================
@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("shop_list"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not email:
            flash("이메일을 입력하세요.", "error")
            return render_template("register.html")
        if not password:
            flash("비밀번호를 입력하세요.", "error")
            return render_template("register.html")
        if password != password2:
            flash("비밀번호 확인이 일치하지 않습니다.", "error")
            return render_template("register.html")

        db = get_db()
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            flash("이미 가입된 이메일입니다.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        now = now_kst_str()

        cur2 = db.cursor()
        cur2.execute(
            "INSERT INTO users (email, password, name, created_at) VALUES (%s, %s, %s, %s)",
            (email, password_hash, name, now),
        )
        db.commit()

        flash("회원가입이 완료되었습니다. 로그인 해주세요.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# =======================
# 라우트: 로그인
# =======================
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("shop_list"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            flash("존재하지 않는 이메일입니다.", "error")
            return render_template("login.html")
        if not check_password_hash(user["password"], password):
            flash("비밀번호가 올바르지 않습니다.", "error")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session["user_name"] = user["name"]
        flash("로그인 되었습니다.", "success")
        return redirect(url_for("shop_list"))

    return render_template("login.html")


# =======================
# 라우트: 로그아웃
# =======================
@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃 되었습니다.", "success")
    return redirect(url_for("shop_list"))


# =======================
# 라우트: 회원 본인 탈퇴
# =======================
@app.route("/account/delete", methods=["GET", "POST"])
def account_delete():
    if not session.get("user_id"):
        flash("로그인이 필요한 서비스입니다.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    if request.method == "POST":
        ok = db_delete_user_and_related(user_id)
        if not ok:
            flash("관리자 계정이거나 존재하지 않는 계정이라 탈퇴할 수 없습니다.", "error")
            return redirect(url_for("shop_list"))

        session.clear()
        flash("회원 탈퇴가 완료되었습니다.", "success")
        return redirect(url_for("shop_list"))

    return render_template("account_delete.html")


# ============================================
# 라우트: 사용자 - 고객센터 문의
# ============================================
@app.route("/support", methods=["GET", "POST"])
def support():
    if not session.get("user_id"):
        flash("로그인이 필요한 서비스입니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    user_id = session["user_id"]
    user_email = session.get("user_email")

    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not message:
            flash("제목과 내용을 모두 입력하세요.", "error")
        else:
            now = now_kst_str()
            cur2 = db.cursor()
            cur2.execute(
                """
                INSERT INTO inquiries (user_id, email, subject, message, status, created_at)
                VALUES (%s, %s, %s, %s, 'OPEN', %s)
                """,
                (user_id, user_email, subject, message, now),
            )
            db.commit()
            flash("문의가 접수되었습니다.", "success")
            return redirect(url_for("support"))

    cur.execute(
        """
        SELECT id, subject, status, created_at, admin_reply, replied_at
        FROM inquiries
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (user_id,),
    )
    inquiries = cur.fetchall()

    return render_template("support.html", inquiries=inquiries)


@app.route("/support/<int:inquiry_id>")
def support_detail(inquiry_id):
    if not session.get("user_id"):
        flash("로그인이 필요한 서비스입니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    user_id = session["user_id"]
    cur.execute(
        """
        SELECT id, subject, message, status, created_at, admin_reply, replied_at
        FROM inquiries
        WHERE id = %s AND user_id = %s
        """,
        (inquiry_id, user_id),
    )
    inquiry = cur.fetchone()
    if inquiry is None:
        abort(404)

    return render_template("support_detail.html", inquiry=inquiry)


# =======================
# 관리자 - 상품 목록
# =======================
@app.route("/admin/products")
def admin_products():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    products = db_get_products(category=None)
    categories = ["OUTER", "TOP", "BOTTOM", "ACCESSORIES"]

    return render_template("admin_products.html", products=products, categories=categories)


# =======================
# 관리자 - 회원 목록
# =======================
@app.route("/admin/users")
def admin_users():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, email, name, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_user_delete(user_id):
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    ok = db_delete_user_and_related(user_id)
    if not ok:
        flash("관리자 계정이거나 존재하지 않는 계정이라 삭제할 수 없습니다.", "error")
    else:
        flash("해당 회원이 탈퇴 처리되었습니다.", "success")

    return redirect(url_for("admin_users"))


# =======================
# 관리자 - 문의 목록/상세
# =======================
@app.route("/admin/inquiries")
def admin_inquiries():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT
            i.id, i.subject, i.message, i.status, i.created_at,
            i.admin_reply, i.replied_at,
            u.email AS user_email, u.name AS user_name
        FROM inquiries i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.created_at DESC
        """
    )
    rows = cur.fetchall()

    return render_template("admin_inquiries.html", inquiries=rows)


@app.route("/admin/inquiries/<int:inquiry_id>", methods=["GET", "POST"])
def admin_inquiry_detail(inquiry_id):
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if request.method == "POST":
        action = request.form.get("action")
        reply_text = request.form.get("admin_reply", "").strip()
        now = now_kst_str()

        cur2 = db.cursor()

        if reply_text:
            cur2.execute(
                """
                UPDATE inquiries
                SET admin_reply = %s, replied_at = %s
                WHERE id = %s
                """,
                (reply_text, now, inquiry_id),
            )

        if action == "close":
            cur2.execute(
                "UPDATE inquiries SET status = 'CLOSED' WHERE id = %s",
                (inquiry_id,),
            )

        db.commit()
        flash("문의 답변이 저장되었습니다.", "success")
        return redirect(url_for("admin_inquiry_detail", inquiry_id=inquiry_id))

    cur.execute(
        """
        SELECT
            i.id, i.subject, i.message, i.status, i.created_at,
            i.admin_reply, i.replied_at,
            u.email AS user_email, u.name AS user_name
        FROM inquiries i
        JOIN users u ON i.user_id = u.id
        WHERE i.id = %s
        """,
        (inquiry_id,),
    )
    row = cur.fetchone()
    if row is None:
        abort(404)

    return render_template("admin_inquiry_detail.html", inquiry=row)


# =======================
# 관리자 - 새 상품 추가
# (네 HTML: color_image_idx[] “번호(1~N)” 방식에 맞춤)
# =======================
@app.route("/admin/products/new", methods=["GET", "POST"])
def admin_product_new():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    categories = ["OUTER", "TOP", "BOTTOM", "ACCESSORIES"]

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_raw = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip() or "TOP"

        if not name:
            flash("상품명을 입력하세요.", "error")
            return render_template("admin_product_new.html", categories=categories)

        try:
            price = int(price_raw) if price_raw else 0
        except ValueError:
            flash("가격은 숫자로 입력하세요.", "error")
            return render_template("admin_product_new.html", categories=categories)

        db = get_db()
        try:
            # 1) products 생성
            new_id = db_create_product(
                name=name,
                price=price,
                image_url="",
                category=category,
                description=description,
                image_data=None,
                image_mime=None,
            )

            # 2) 이미지 업로드 -> product_images 저장 -> 실제 id 리스트
            images = request.files.getlist("images")
            images = [f for f in images if f and getattr(f, "filename", "")]
            inserted_image_ids = []
            if images:
                inserted_image_ids = db_insert_product_images(new_id, images)

            # 3) 컬러/재고 저장
            color_names = request.form.getlist("color_name[]")
            color_image_idxs = request.form.getlist("color_image_idx[]")

            cur = db.cursor()
            for idx, cname in enumerate(color_names):
                cname = (cname or "").strip()
                if not cname:
                    continue

                image_id = None
                raw = color_image_idxs[idx] if idx < len(color_image_idxs) else ""
                if raw and raw.isdigit() and inserted_image_ids:
                    num = int(raw)
                    if 1 <= num <= len(inserted_image_ids):
                        image_id = inserted_image_ids[num - 1]

                cur.execute(
                    """
                    INSERT INTO product_colors (product_id, color_name, image_id, created_at)
                    VALUES (%s,%s,%s,%s)
                    RETURNING id
                    """,
                    (new_id, cname, image_id, now_kst_str()),
                )
                color_id = cur.fetchone()[0]

                # variants
                sizes = request.form.getlist(f"size_{idx}[]")
                stocks = request.form.getlist(f"stock_{idx}[]")
                cur.execute("DELETE FROM product_color_variants WHERE color_id=%s", (color_id,))
                for s, st in zip(sizes, stocks):
                    s = (s or "").strip().upper()
                    if not s:
                        continue
                    try:
                        stock_i = int(st)
                    except Exception:
                        stock_i = 0
                    cur.execute(
                        """
                        INSERT INTO product_color_variants (color_id, size, stock)
                        VALUES (%s, %s, %s)
                        """,
                        (color_id, s, stock_i),
                    )

            db.commit()
            flash("새 상품이 추가되었습니다.", "success")
            return redirect(url_for("admin_products"))

        except Exception:
            db.rollback()
            raise

    return render_template("admin_product_new.html", categories=categories)


@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
def admin_product_delete(product_id):
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db_delete_product(product_id)
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
def admin_product_edit(product_id):
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    categories = ["OUTER", "TOP", "BOTTOM", "ACCESSORIES"]

    target = db_get_product(product_id)
    if not target:
        flash("해당 상품을 찾을 수 없습니다.", "error")
        return redirect(url_for("admin_products"))

    images = db_get_product_images(product_id)
    colors = db_get_colors(product_id)

    color_map = []
    for c in colors:
        v = db_get_color_variants(c["id"])
        color_map.append(
            {
                "id": c["id"],
                "name": c["color_name"],
                "image_id": c["image_id"],
                "variants": v,
            }
        )

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_raw = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip() or target["category"]

        if not name:
            flash("상품명을 입력하세요.", "error")
            return render_template(
                "admin_product_edit.html",
                product=target,
                categories=categories,
                images=images,
                colors=color_map,
            )

        try:
            price = int(price_raw) if price_raw else 0
        except ValueError:
            flash("가격은 숫자로 입력하세요.", "error")
            return render_template(
                "admin_product_edit.html",
                product=target,
                categories=categories,
                images=images,
                colors=color_map,
            )

        db = get_db()
        try:
            # 1) 기본 정보 업데이트
            db_update_product(
                product_id=product_id,
                name=name,
                price=price,
                image_url=target.get("image_url", "") or "",
                category=category,
                description=description,
                image_data=None,
                image_mime=None,
            )

            # 2) 새 이미지 업로드 추가
            new_images = request.files.getlist("images")
            new_images = [f for f in new_images if f and getattr(f, "filename", "")]
            if new_images:
                db_insert_product_images(product_id, new_images)

            # 3) 컬러/재고는 통째로 교체
            db_delete_colors_for_product(product_id)

            color_names = request.form.getlist("color_name[]")
            color_image_ids = request.form.getlist("color_image_id[]")  # edit 템플릿 기준

            for idx, cname in enumerate(color_names):
                cname = (cname or "").strip()
                if not cname:
                    continue

                raw = color_image_ids[idx] if idx < len(color_image_ids) else ""
                image_id = int(raw) if raw and raw.isdigit() else None

                color_id = db_upsert_color(product_id, cname, image_id)

                sizes = request.form.getlist(f"size_{idx}[]")
                stocks = request.form.getlist(f"stock_{idx}[]")
                db_replace_color_variants(color_id, sizes, stocks)

            db.commit()
            flash("상품 정보가 수정되었습니다.", "success")
            return redirect(url_for("admin_products"))

        except Exception:
            db.rollback()
            raise

    return render_template(
        "admin_product_edit.html",
        product=target,
        categories=categories,
        images=images,
        colors=color_map,
    )


@app.route("/admin/products/reorder", methods=["POST"])
def admin_products_reorder():
    if not session.get("user_id") or not is_admin():
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    data = request.get_json() or {}
    order = data.get("order", [])
    if not isinstance(order, list):
        return jsonify({"ok": False, "error": "invalid payload"}), 400

    db = get_db()
    cur = db.cursor()
    for idx, pid in enumerate(order, start=1):
        try:
            pid_int = int(pid)
        except ValueError:
            continue
        cur.execute("UPDATE products SET sort_order = %s WHERE id = %s", (idx, pid_int))

    db.commit()
    return jsonify({"ok": True})


# =======================
# 상품 상세 페이지
# =======================
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = db_get_product(product_id)
    if not product:
        abort(404)

    colors = db_get_colors(product_id)

    color_map = []
    for c in colors:
        variants = db_get_color_variants(c["id"])
        color_map.append(
            {"id": c["id"], "name": c["color_name"], "image_id": c["image_id"], "variants": variants}
        )

    return render_template("product_detail.html", product=product, colors=color_map)


# =======================
# 이미지 제공
# =======================
@app.route("/product_image/<int:product_id>")
def product_image(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT image_data, image_mime, image_url
        FROM product_images
        WHERE product_id = %s
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
        """,
        (product_id,),
    )
    row = cur.fetchone()
    if not row:
        abort(404)

    data, mime, url = row
    if data:
        return Response(data, mimetype=mime or "image/jpeg")
    if url:
        return redirect(url)
    abort(404)


@app.route("/product_image_by_id/<int:image_id>")
def product_image_by_id(image_id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT image_data, image_mime, image_url
        FROM product_images
        WHERE id=%s
        """,
        (image_id,),
    )
    row = cur.fetchone()
    if not row:
        abort(404)

    data, mime, url = row
    if data:
        return Response(data, mimetype=mime or "image/jpeg")
    if url:
        return redirect(url)
    abort(404)


# =======================
# 실행부
# =======================
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)