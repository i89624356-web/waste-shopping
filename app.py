import os
import json
import sqlite3
from datetime import datetime

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
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets
import smtplib
from email.mime.text import MIMEText

# =======================
# 기본 설정
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# 세션에 쓸 비밀키 (실서비스에서는 환경변수로 빼야 함)
app.secret_key = "dev-secret-key-change-this"

PRODUCT_FILE = os.path.join(BASE_DIR, "products.json")
DB_PATH = os.path.join(BASE_DIR, "shop.db")

# 이미지 업로드 설정
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# 관리자 이메일 목록 (여기에 있는 이메일로 가입하면 관리자 취급)
ADMIN_EMAILS = {"022wasted@gmail.com"}


# =======================
# DB 관련 함수 (users)
# =======================
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # dict처럼 사용 가능
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """users, inquiries 테이블이 없으면 생성"""
    db = get_db()

    # users 테이블
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    # 새로 추가: 고객센터 문의 테이블
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS inquiries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT NOT NULL
        )
        """
    )

    db.commit()


# =======================
# 상품 데이터 (products.json)
# =======================
def ensure_products_file():
    """products.json이 없으면 빈 리스트로 생성"""
    if not os.path.exists(PRODUCT_FILE):
        with open(PRODUCT_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)


def load_products():
    ensure_products_file()
    with open(PRODUCT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def save_products(products):
    with open(PRODUCT_FILE, "w", encoding="utf-8") as f:
        json.dump(products, f, ensure_ascii=False, indent=2)


def next_product_id(products):
    if not products:
        return 1
    return max(p.get("id", 0) for p in products) + 1


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
    products = load_products()

    if category != "ALL":
        filtered = [p for p in products if p.get("category") == category]
    else:
        filtered = products

    categories = ["ALL", "OUTER", "TOP", "BOTTOM", "ACCESSORIES"]

    return render_template(
        "shop_list.html",
        products=filtered,
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
    # 이미 로그인 상태면 리스트로 보냄
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

        # 이메일 중복 체크
        cur = db.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cur.fetchone()
        if existing:
            flash("이미 가입된 이메일입니다.", "error")
            return render_template("register.html")

        # 비밀번호 해시 후 저장
        password_hash = generate_password_hash(password)
        now = datetime.now().isoformat(timespec="seconds")

        db.execute(
            "INSERT INTO users (email, password, name, created_at) VALUES (?, ?, ?, ?)",
            (email, password_hash, name, now),
        )
        db.commit()

        flash("회원가입이 완료되었습니다. 로그인 해주세요.", "success")
        return redirect(url_for("login"))

    # GET 요청
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
        cur = db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            flash("존재하지 않는 이메일입니다.", "error")
            return render_template("login.html")

        if not check_password_hash(user["password"], password):
            flash("비밀번호가 올바르지 않습니다.", "error")
            return render_template("login.html")

        # 로그인 성공 → 세션 저장
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


@app.route("/support", methods=["GET", "POST"])
def support():
    # 로그인 안 했으면 로그인 페이지로
    if not session.get("user_id"):
        flash("로그인이 필요한 서비스입니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    user_id = session["user_id"]
    user_email = session.get("user_email")

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not message:
            flash("제목과 내용을 모두 입력하세요.", "error")
        else:
            now = datetime.now().isoformat(timespec="seconds")
            db.execute(
                """
                INSERT INTO inquiries (user_id, email, subject, message, status, created_at)
                VALUES (?, ?, ?, ?, 'OPEN', ?)
                """,
                (user_id, user_email, subject, message, now),
            )
            db.commit()
            flash("문의가 접수되었습니다.", "success")
            return redirect(url_for("support"))

    # 내가 보낸 문의 목록
    inquiries = db.execute(
        """
        SELECT id, subject, message, status, created_at
        FROM inquiries
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user_id,),
    ).fetchall()

    return render_template("support.html", inquiries=inquiries)


# =======================
# 라우트: 관리자 - 상품 목록
# =======================
@app.route("/admin/products")
def admin_products():
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    products = load_products()
    categories = ["OUTER", "TOP", "BOTTOM", "ACCESSORIES"]

    return render_template(
        "admin_products.html",
        products=products,
        categories=categories,
    )


@app.route("/admin/inquiries")
def admin_inquiries():
    # 관리자 체크
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    db = get_db()
    rows = db.execute(
        """
        SELECT
            i.id,
            i.subject,
            i.message,
            i.status,
            i.created_at,
            u.email AS user_email,
            u.name AS user_name
        FROM inquiries i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.created_at DESC
        """
    ).fetchall()

    return render_template("admin_inquiries.html", inquiries=rows)


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

        products = load_products()
        new_id = next_product_id(products)

        # 이미지 파일 받기
        image_file = request.files.get("image")
        image_url = "https://via.placeholder.com/600x800?text=PRODUCT"  # 기본 이미지

        if image_file and image_file.filename:
            if not allowed_file(image_file.filename):
                flash(
                    "이미지 파일(png, jpg, jpeg, gif, webp)만 업로드 가능합니다.",
                    "error",
                )
                return render_template("admin_product_new.html", categories=categories)

            filename = f"{new_id}_" + secure_filename(image_file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            image_file.save(save_path)

            image_url = "/static/uploads/" + filename

        new_product = {
            "id": new_id,
            "name": name,
            "price": price,
            "image_url": image_url,
            "status": status,
            "category": category,
            "description": description,  # ★ 설명 추가
        }

        products.append(new_product)
        save_products(products)

        flash("새 상품이 추가되었습니다.", "success")
        return redirect(url_for("admin_products"))

    # GET 요청
    return render_template("admin_product_new.html", categories=categories)


# =======================
# 라우트: 관리자 - 상품 삭제
# =======================
@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
def admin_product_delete(product_id):
    if not session.get("user_id") or not is_admin():
        flash("관리자 권한이 필요합니다.", "error")
        return redirect(url_for("login"))

    products = load_products()
    new_products = [p for p in products if p.get("id") != product_id]

    if len(products) == len(new_products):
        flash("해당 상품을 찾을 수 없습니다.", "error")
    else:
        save_products(new_products)
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
    products = load_products()

    # 수정할 상품 찾기
    target = None
    for p in products:
        if p.get("id") == product_id:
            target = p
            break

    if not target:
        flash("해당 상품을 찾을 수 없습니다.", "error")
        return redirect(url_for("admin_products"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price_raw = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip() or target.get("category", "TOP")
        status = request.form.get("status", "").strip() or target.get("status", "IN_STOCK")

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

        # 이미지 파일(선택) 받기
        image_file = request.files.get("image")
        image_url = target.get("image_url")

        if image_file and image_file.filename:
            if not allowed_file(image_file.filename):
                flash("이미지 파일(png, jpg, jpeg, gif, webp)만 업로드 가능합니다.", "error")
                return render_template(
                    "admin_product_edit.html",
                    product=target,
                    categories=categories,
                )

            filename = f"{product_id}_" + secure_filename(image_file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            image_file.save(save_path)

            image_url = "/static/uploads/" + filename

        # 실제 데이터 수정
        target["name"] = name
        target["price"] = price
        target["category"] = category
        target["status"] = status
        target["image_url"] = image_url
        target["description"] = description or target.get("description", "")

        save_products(products)

        flash("상품 정보가 수정되었습니다.", "success")
        return redirect(url_for("admin_products"))

    # GET 요청: 기존 데이터 채워진 폼 보여주기
    return render_template(
        "admin_product_edit.html",
        product=target,
        categories=categories,
    )


# =======================
# 라우트: 상품 상세 페이지
# =======================
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    products = load_products()

    # id가 일치하는 상품 찾기
    target = None
    for p in products:
        if p.get("id") == product_id:
            target = p
            break

    if not target:
        # 없는 상품이면 404
        abort(404)

    return render_template("product_detail.html", product=target)


# =======================
# 실행부
# =======================

# 로컬이든 Render든, 모듈이 import될 때 한 번 실행되도록
with app.app_context():
    init_db()
    ensure_products_file()

if __name__ == "__main__":
    app.run(debug=True)