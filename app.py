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
from werkzeug.utils import secure_filename

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

# 세션에 쓸 비밀키 (실서비스에서는 환경변수로 빼야 함)
app.secret_key = "dev-secret-key-change-this"

# PostgreSQL 연결 문자열 (Neon / Render 환경변수에서 읽기)
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "환경변수 DATABASE_URL 이 설정되어 있지 않습니다. "
        "Neon의 Postgres connection string을 Render Environment에 DATABASE_URL로 넣어주세요."
    )

# 예전 products.json (있으면 초기 데이터로만 사용)
PRODUCT_FILE = os.path.join(BASE_DIR, "products.json")

# 이미지 업로드 설정
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# 관리자 이메일 목록 (여기에 있는 이메일로 가입하면 관리자 취급)
ADMIN_EMAILS = {"022wasted@gmail.com", "i89624356@gmail.com"}


# =======================
# DB 관련 함수 (PostgreSQL)
# =======================
def get_db():
    if "db" not in g:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False  # 명시적으로 commit 호출
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """users, inquiries, products 테이블 생성 + inquiries 컬럼 보정"""
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

    # inquiries 보조 컬럼 (있으면 추가 안 됨)
    cur.execute(
        "ALTER TABLE inquiries "
        "ADD COLUMN IF NOT EXISTS admin_reply TEXT"
    )
    cur.execute(
        "ALTER TABLE inquiries "
        "ADD COLUMN IF NOT EXISTS replied_at TEXT"
    )

    # ---------- products ----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            price INTEGER NOT NULL,
            image_url TEXT NOT NULL,
            status TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    # 정렬용 sort_order 컬럼 (없으면 추가)
    cur.execute(
        "ALTER TABLE products "
        "ADD COLUMN IF NOT EXISTS sort_order INTEGER"
    )

    # sort_order 가 NULL 인 행은 id 기준으로 기본값 채우기
    cur.execute(
        "UPDATE products SET sort_order = id WHERE sort_order IS NULL"
    )

    # 이미지 바이너리 + MIME 타입
    cur.execute(
        "ALTER TABLE products "
        "ADD COLUMN IF NOT EXISTS image_data BYTEA"
    )
    cur.execute(
        "ALTER TABLE products "
        "ADD COLUMN IF NOT EXISTS image_mime TEXT"
    )

    db.commit()

    # products 테이블이 비어 있고, products.json 이 있으면 한번만 마이그레이션
    migrate_products_from_json_if_needed()


def migrate_products_from_json_if_needed():
    """DB products 테이블이 비어 있고 products.json이 있으면 한 번만 옮겨담기"""
    db = get_db()
    cur = db.cursor()

    # 이미 데이터가 있으면 패스
    cur.execute("SELECT COUNT(*) FROM products")
    count = cur.fetchone()[0]
    if count > 0:
        return

    if not os.path.exists(PRODUCT_FILE):
        return

    # JSON 읽어서 insert
    with open(PRODUCT_FILE, "r", encoding="utf-8") as f:
        try:
            products = json.load(f)
        except Exception:
            products = []

    if not products:
        return

    now = datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")
    for p in products:
        name = p.get("name", "")
        price = int(p.get("price", 0))
        image_url = p.get("image_url") or "https://via.placeholder.com/600x800?text=PRODUCT"
        status = p.get("status") or "IN_STOCK"
        category = p.get("category") or "TOP"
        description = p.get("description") or ""

        cur.execute(
            """
            INSERT INTO products (name, price, image_url, status, category, description, created_at, sort_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (name, price, image_url, status, category, description, now, p.get("id", 0)),
        )

    db.commit()


# =======================
# products 헬퍼 함수 (DB)
# =======================
def db_get_products(category: str | None = None):
    """카테고리 필터 포함한 상품 목록 (sort_order 기준 정렬)"""
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if category and category != "ALL":
        cur.execute(
            """
            SELECT id, name, price, image_url, status, category, description
            FROM products
            WHERE category = %s
            ORDER BY sort_order ASC, id DESC
            """,
            (category,),
        )
    else:
        cur.execute(
            """
            SELECT id, name, price, image_url, status, category, description
            FROM products
            ORDER BY sort_order ASC, id DESC
            """
        )

    return cur.fetchall()


def db_get_product(product_id: int):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, name, price, image_url, status, category, description
        FROM products
        WHERE id = %s
        """,
        (product_id,),
    )
    return cur.fetchone()


def db_create_product(name, price, image_url, status, category, description,
                      image_data=None, image_mime=None):
    db = get_db()
    cur = db.cursor()

    # 정렬용 sort_order
    cur.execute("SELECT COALESCE(MAX(sort_order), 0) FROM products")
    max_order = cur.fetchone()[0]
    new_order = max_order + 1

    now = datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        """
        INSERT INTO products (
            name, price, image_url, status, category, description,
            created_at, sort_order, image_data, image_mime
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (name, price, image_url, status, category, description,
         now, new_order, image_data, image_mime),
    )
    new_id = cur.fetchone()[0]
    db.commit()
    return new_id


def db_update_product(product_id, name, price, image_url, status, category, description,
                      image_data=None, image_mime=None):
    db = get_db()
    cur = db.cursor()

    if image_data is not None and image_mime is not None:
        # 새 이미지까지 포함해서 변경
        cur.execute(
            """
            UPDATE products
            SET name = %s,
                price = %s,
                image_url = %s,
                status = %s,
                category = %s,
                description = %s,
                image_data = %s,
                image_mime = %s
            WHERE id = %s
            """,
            (name, price, image_url, status, category, description,
             image_data, image_mime, product_id),
        )
    else:
        # 텍스트 정보만 변경 (이미지는 그대로 유지)
        cur.execute(
            """
            UPDATE products
            SET name = %s,
                price = %s,
                image_url = %s,
                status = %s,
                category = %s,
                description = %s
            WHERE id = %s
            """,
            (name, price, image_url, status, category, description, product_id),
        )

    db.commit()


def db_delete_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
    db.commit()


def db_delete_user_and_related(user_id: int) -> bool:
    """
    회원 1명을 탈퇴 처리한다.
    - inquiries: 해당 user_id가 남긴 문의 모두 삭제
    - users: 해당 회원 삭제
    - 관리자(ADMIN_EMAILS)는 보호 차원에서 삭제 금지 → False 반환
    """
    db = get_db()
    # 이메일 먼저 조회
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    if not user:
        return False

    # 관리자 계정은 삭제 금지
    if user["email"] in ADMIN_EMAILS:
        return False

    # 실제 삭제
    cur2 = db.cursor()
    # 1) 해당 회원이 남긴 문의 삭제
    cur2.execute("DELETE FROM inquiries WHERE user_id = %s", (user_id,))
    # 2) 회원 삭제
    cur2.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    return True


# =======================
# 템플릿 공통 컨텍스트
# =======================
def is_admin():
    email = session.get("user_email")
    return email in ADMIN_EMAILS


@app.context_processor
def inject_user():
    # 템플릿 어디서나 current_user_email, is_admin 사용 가능
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
    # 그냥 / 로 접근하면 /shop으로
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

        errors = []

        if not email:
            errors.append("이메일을 입력하세요.")
        if not password:
            errors.append("비밀번호를 입력하세요.")
        if password != password2:
            errors.append("비밀번호 확인이 일치하지 않습니다.")

        if errors:
            flash(errors[0], "error")
            return render_template("register.html")

        db = get_db()
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # 이메일 중복 체크
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing = cur.fetchone()
        if existing:
            flash("이미 가입된 이메일입니다.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        now = datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")

        cur2 = db.cursor()
        cur2.execute(
            "INSERT INTO users (email, password, name, created_at) "
            "VALUES (%s, %s, %s, %s)",
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

        # 세션 정리
        session.clear()
        flash("회원 탈퇴가 완료되었습니다.", "success")
        return redirect(url_for("shop_list"))

    # GET: 확인 페이지
    return render_template("account_delete.html")


# ============================================
# 라우트: 사용자 - 고객센터 문의 작성 및 조회
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

    # POST: 문의 저장
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not message:
            flash("제목과 내용을 모두 입력하세요.", "error")
        else:
            now = datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")
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

    # GET: 내가 보낸 문의 목록
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


# ============================================
# 라우트: 사용자 - 내 문의 상세 보기
# ============================================
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
        SELECT
            id,
            subject,
            message,
            status,
            created_at,
            admin_reply,
            replied_at
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
# 라우트: 관리자 - 상품 목록
# =======================
@app.route("/admin/products")
def admin_products():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    products = db_get_products(category=None)
    categories = ["OUTER", "TOP", "BOTTOM", "ACCESSORIES"]

    return render_template(
        "admin_products.html",
        products=products,
        categories=categories,
    )


# =======================
# 라우트: 관리자 - 회원 목록 조회
# =======================
@app.route("/admin/users")
def admin_users():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, email, name, created_at
        FROM users
        ORDER BY created_at DESC
        """
    )
    users = cur.fetchall()

    return render_template("admin_users.html", users=users)


# =======================
# 라우트: 관리자 - 회원 강제 탈퇴
# =======================
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
# 라우트: 관리자 - 고객센터 문의 목록 조회
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
            i.id,
            i.subject,
            i.message,
            i.status,
            i.created_at,
            i.admin_reply,
            i.replied_at,
            u.email AS user_email,
            u.name AS user_name
        FROM inquiries i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.created_at DESC
        """
    )
    rows = cur.fetchall()

    return render_template("admin_inquiries.html", inquiries=rows)


# =======================
# 라우트: 관리자 - 특정 문의 상세 보기 + 답변/상태 변경
# =======================
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
        now = datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")

        cur2 = db.cursor()

        if reply_text:
            cur2.execute(
                """
                UPDATE inquiries
                SET admin_reply = %s,
                    replied_at = %s
                WHERE id = %s
                """,
                (reply_text, now, inquiry_id),
            )

        if action == "close":
            cur2.execute(
                """
                UPDATE inquiries
                SET status = 'CLOSED'
                WHERE id = %s
                """,
                (inquiry_id,),
            )

        db.commit()
        flash("문의 답변이 저장되었습니다.", "success")
        return redirect(url_for("admin_inquiry_detail", inquiry_id=inquiry_id))

    # GET
    cur.execute(
        """
        SELECT
            i.id,
            i.subject,
            i.message,
            i.status,
            i.created_at,
            i.admin_reply,
            i.replied_at,
            u.email AS user_email,
            u.name AS user_name
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
# 라우트: 관리자 - 새 상품 추가 (이미지 업로드)
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
        status = request.form.get("status", "IN_STOCK").strip()

        if not name:
            flash("상품명을 입력하세요.", "error")
            return render_template("admin_product_new.html", categories=categories)

        try:
            price = int(price_raw) if price_raw else 0
        except ValueError:
            flash("가격은 숫자로 입력하세요.", "error")
            return render_template("admin_product_new.html", categories=categories)

        image_file = request.files.get("image")
        # 예전 필드 호환용. 굳이 안 써도 되지만 남겨두자.
        image_url = "https://via.placeholder.com/600x800?text=PRODUCT"
        image_data = None
        image_mime = None

        if image_file and image_file.filename:
            # 파일 내용을 그대로 읽어서 DB에 넣기
            image_data = image_file.read()
            image_mime = image_file.mimetype or "image/jpeg"
            # image_url은 일단 빈 문자열로 두거나 placeholder 유지
            image_url = ""

        new_id = db_create_product(
            name=name,
            price=price,
            image_url=image_url,
            status=status,
            category=category,
            description=description,
            image_data=image_data,
            image_mime=image_mime,
        )

        flash(f"새 상품이 추가되었습니다. (ID: {new_id})", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin_product_new.html", categories=categories)


# =======================
# 라우트: 관리자 - 상품 삭제
# =======================
@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
def admin_product_delete(product_id):
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db_delete_product(product_id)
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for("admin_products"))


# =======================
# 라우트: 관리자 - 상품 수정
# =======================
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

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_raw = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip() or target["category"]
        status = request.form.get("status", "").strip() or target["status"]

        if not name:
            flash("상품명을 입력하세요.", "error")
            return render_template(
                "admin_product_edit.html",
                product=target,
                categories=categories,
            )

        try:
            price = int(price_raw) if price_raw else 0
        except ValueError:
            flash("가격은 숫자로 입력하세요.", "error")
            return render_template(
                "admin_product_edit.html",
                product=target,
                categories=categories,
            )

        image_file = request.files.get("image")
        # 기존 image_url 유지 (사실 이제 의미는 거의 없음)
        image_url = target.get("image_url", "") or ""

        image_data = None
        image_mime = None

        if image_file and image_file.filename:
            image_data = image_file.read()
            image_mime = image_file.mimetype or "image/jpeg"
            image_url = ""

        db_update_product(
            product_id=product_id,
            name=name,
            price=price,
            image_url=image_url,
            status=status,
            category=category,
            description=description or "",
            image_data=image_data,
            image_mime=image_mime,
        )

        flash("상품 정보가 수정되었습니다.", "success")
        return redirect(url_for("admin_products"))

    return render_template(
        "admin_product_edit.html",
        product=target,
        categories=categories,
    )


# =======================
# 라우트: 관리자 - 상품 순서 재정렬 (AJAX)
# =======================
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

    # order = [5, 2, 7, ...] 이런 식의 상품 id 리스트
    for idx, pid in enumerate(order, start=1):
        try:
            pid_int = int(pid)
        except ValueError:
            continue
        cur.execute(
            "UPDATE products SET sort_order = %s WHERE id = %s",
            (idx, pid_int),
        )

    db.commit()
    return jsonify({"ok": True})


# =======================
# 라우트: 상품 상세 페이지
# =======================
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    target = db_get_product(product_id)

    if not target:
        abort(404)

    return render_template("product_detail.html", product=target)


@app.route("/product_image/<int:product_id>")
def product_image(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT image_data, image_mime, image_url FROM products WHERE id = %s",
        (product_id,),
    )
    row = cur.fetchone()
    if not row:
        abort(404)

    image_data, image_mime, image_url = row

    if image_data:
        # DB에 저장된 바이너리 이미지 사용
        return Response(image_data, mimetype=image_mime or "image/jpeg")

    # 바이너리가 없고 image_url만 있을 때는 그쪽으로 redirect
    if image_url:
        return redirect(image_url)

    # 둘 다 없으면 404
    abort(404)


# =======================
# 실행부
# =======================
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)