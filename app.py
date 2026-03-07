import os
import json
import secrets
import datetime
import smtplib
import socket
from functools import wraps
from email.mime.text import MIMEText

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import or_, func as sqla_func
from sqlalchemy.orm import joinedload
import markdown


# =========================
# APP + CONFIG
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_DB_PATH = os.path.join(BASE_DIR, "techhubtr_users.db")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")

app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static", "avatars")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Cookie güvenliği
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# =========================
# DATABASE
# Render: PostgreSQL
# Local: SQLite fallback
# =========================
db_url = os.getenv("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Render'da SQLite'a yanlışlıkla düşmesin istersen bunu true yap
require_database_url = os.getenv("REQUIRE_DATABASE_URL", "false").lower() == "true"
if require_database_url and not db_url:
    raise RuntimeError("DATABASE_URL zorunlu ama bulunamadı.")

app.config["SQLALCHEMY_DATABASE_URI"] = db_url or f"sqlite:///{SQLITE_DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# =========================
# MAIL / SMTP
# =========================
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "TechHubTR Destek <techhubtr@gmail.com>")
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "10"))

# =========================
# INIT EXTENSIONS
# =========================
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "giris"
login_manager.login_message = "Bu sayfayı görüntülemek için giriş yapmalısınız."
login_manager.login_message_category = "warning"


# =========================
# HELPERS
# =========================
def ensure_folders():
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
            flash("Bu sayfaya erişim yetkiniz yoktur.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def send_email_safely(to_email: str, subject: str, body: str) -> bool:
    """
    Timeout'lu SMTP gönderim.
    Mail başarısız olsa bile siteyi çökertmez.
    """
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        print("MAIL ENV eksik: MAIL_USERNAME veya MAIL_PASSWORD yok.")
        return False

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = MAIL_DEFAULT_SENDER
    msg["To"] = to_email

    try:
        if MAIL_USE_SSL:
            server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS)
        else:
            server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS)

        with server:
            server.ehlo()
            if MAIL_USE_TLS and not MAIL_USE_SSL:
                server.starttls()
                server.ehlo()

            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_USERNAME, [to_email], msg.as_string())

        return True

    except (socket.timeout, TimeoutError) as e:
        print("SMTP TIMEOUT:", type(e).__name__, e)
        return False
    except Exception as e:
        print("SMTP ERROR:", type(e).__name__, e)
        return False


def send_verification_email(to_email: str, token: str) -> bool:
    verification_url = url_for("verify_email", token=token, _external=True)
    subject = "TechHubTR: Hesabınızı Doğrulayın"
    body = (
        "Merhaba,\n\n"
        "TechHubTR hesabınızı aktifleştirmek için aşağıdaki linke tıklayınız:\n"
        f"{verification_url}\n"
    )
    ok = send_email_safely(to_email, subject, body)
    if ok:
        print(f"MAIL OK: doğrulama -> {to_email}")
    return ok


def send_password_reset_email(to_email: str, username: str, token: str) -> bool:
    reset_url = url_for("sifre_sifirla", token=token, _external=True)
    subject = "TechHubTR: Şifre Sıfırlama Talebi"
    body = (
        f"Merhaba {username},\n\n"
        "Hesabınız için şifre sıfırlama talebinde bulundunuz.\n"
        "Yeni şifrenizi belirlemek için aşağıdaki linke tıklayın:\n"
        f"{reset_url}\n\n"
        "Bu link 1 saat geçerlidir.\n"
    )
    ok = send_email_safely(to_email, subject, body)
    if ok:
        print(f"MAIL OK: reset -> {to_email}")
    return ok


# =========================
# MODELS
# =========================
topic_tags = db.Table(
    "topic_tags",
    db.Column("topic_id", db.Integer, db.ForeignKey("topic.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tag.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=db.func.now())
    theme = db.Column(db.String(10), default="dark")

    points = db.Column(db.Integer, default=0)
    rank = db.Column(db.String(50), default="Çaylak")

    avatar_filename = db.Column(db.String(128), default="default.png")

    is_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100), unique=True, nullable=True)

    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_expires_at = db.Column(db.DateTime, nullable=True)

    topics = db.relationship("Topic", backref="author", lazy=True)
    comments = db.relationship("Comment", backref="commenter", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_total_posts(self) -> int:
        topic_count = (
            db.session.execute(
                db.select(sqla_func.count(Topic.id)).filter(Topic.user_id == self.id)
            ).scalar() or 0
        )
        comment_count = (
            db.session.execute(
                db.select(sqla_func.count(Comment.id)).filter(Comment.user_id == self.id)
            ).scalar() or 0
        )
        return int(topic_count + comment_count)

    def update_points_and_rank(self, points_to_add: int):
        self.points += int(points_to_add)

        if self.points > 1000:
            self.rank = "Usta Geliştirici"
        elif self.points > 200:
            self.rank = "Deneyimli"
        elif self.points > 50:
            self.rank = "Yeni Katılımcı"

        db.session.commit()


class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(150), nullable=False)
    slug = db.Column(db.String(150), unique=True, nullable=False)

    main_category = db.Column(db.String(50), nullable=False)
    sub_category = db.Column(db.String(50), nullable=False)

    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    level = db.Column(db.String(20), default="Başlangıç")
    lesson_count = db.Column(db.Integer, default=1)
    description = db.Column(db.String(250), default="")


class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    comments = db.relationship("Comment", backref="topic", lazy=True)

    tags = db.relationship(
        "Tag",
        secondary=topic_tags,
        lazy="subquery",
        backref=db.backref("topics", lazy=True),
    )


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

    topic_id = db.Column(db.Integer, db.ForeignKey("topic.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    created_at = db.Column(db.DateTime, default=db.func.now())


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    topic_id = db.Column(db.Integer, db.ForeignKey("topic.id"), nullable=True)

    message = db.Column(db.String(256), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    recipient = db.relationship("User", foreign_keys=[user_id], backref="notifications", lazy=True)
    sender = db.relationship("User", foreign_keys=[sender_id], lazy=True)
    topic = db.relationship("Topic", backref="notifications_topic", lazy=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_notifications_count():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return {"unread_notifications_count": unread_count}
    return {"unread_notifications_count": 0}


# =========================
# ROUTES
# =========================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/giris", methods=["GET", "POST"])
def giris():
    if current_user.is_authenticated:
        return redirect(url_for("profil"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()

        if user and user.check_password(password):
            if not user.is_verified:
                flash("Hesabınız doğrulanmamıştır. Lütfen e-postanızı kontrol edin.", "warning")
                return redirect(url_for("giris"))

            login_user(user)
            flash("Başarıyla giriş yaptınız.", "success")
            return redirect(url_for("profil"))

        flash("Geçersiz e-posta veya şifre.", "danger")

    return render_template("giris.html")


@app.route("/cikis")
@login_required
def cikis():
    logout_user()
    flash("Başarıyla çıkış yaptınız.", "success")
    return redirect(url_for("index"))


@app.route("/kayit", methods=["GET", "POST"])
def kayit():
    if current_user.is_authenticated:
        return redirect(url_for("profil"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not username or not email or not password:
            flash("Lütfen tüm alanları doldurun.", "danger")
            return redirect(url_for("kayit"))

        exists = db.session.execute(
            db.select(User).filter((User.username == username) | (User.email == email))
        ).first()
        if exists:
            flash("Bu kullanıcı adı veya e-posta zaten mevcut.", "danger")
            return redirect(url_for("kayit"))

        token = generate_token()
        new_user = User(
            username=username,
            email=email,
            is_verified=False,
            email_verification_token=token,
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        send_verification_email(new_user.email, token)

        flash("Kayıt başarılı. Doğrulama e-postası gönderildi. Spam/Junk klasörünü de kontrol edin.", "success")
        return redirect(url_for("giris"))

    return render_template("kayit.html")


@app.route("/verify/<token>")
def verify_email(token):
    user = db.session.execute(
        db.select(User).filter_by(email_verification_token=token)
    ).scalar_one_or_none()

    if user and not user.is_verified:
        user.is_verified = True
        user.email_verification_token = None
        db.session.commit()
        flash("E-posta adresiniz başarıyla doğrulandı. Giriş yapabilirsiniz.", "success")
        return redirect(url_for("giris"))

    flash("Geçersiz veya süresi dolmuş doğrulama linki.", "danger")
    return redirect(url_for("index"))


@app.route("/sifremi-unuttum", methods=["GET", "POST"])
def sifremi_unuttum():
    if current_user.is_authenticated:
        return redirect(url_for("profil"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()

        if user:
            token = generate_token()
            user.password_reset_token = token
            user.password_reset_expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
            db.session.commit()

            send_password_reset_email(user.email, user.username, token)

        flash("Şifre sıfırlama linki e-posta adresinize gönderildi. Spam/Junk klasörünü de kontrol edin.", "success")
        return redirect(url_for("giris"))

    return render_template("sifremi_unuttum.html")


@app.route("/sifre-sifirla/<token>", methods=["GET", "POST"])
def sifre_sifirla(token):
    if current_user.is_authenticated:
        return redirect(url_for("profil"))

    user = db.session.execute(
        db.select(User).filter_by(password_reset_token=token)
    ).scalar_one_or_none()

    now = datetime.datetime.now()
    expired = (
        user is None
        or user.password_reset_expires_at is None
        or user.password_reset_expires_at < now
    )

    if expired:
        flash("Geçersiz veya süresi dolmuş link.", "danger")
        return redirect(url_for("sifremi_unuttum"))

    if request.method == "POST":
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not new_password:
            flash("Yeni şifre boş olamaz.", "danger")
            return redirect(url_for("sifre_sifirla", token=token))

        if new_password != confirm_password:
            flash("Yeni şifreler eşleşmiyor.", "danger")
            return redirect(url_for("sifre_sifirla", token=token))

        user.set_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires_at = None
        db.session.commit()

        flash("Şifreniz başarıyla güncellendi.", "success")
        return redirect(url_for("giris"))

    return render_template("sifre_sifirla.html", token=token)


@app.route("/profil")
@login_required
def profil():
    if current_user.is_admin:
        all_lessons = db.session.execute(
            db.select(Lesson).order_by(Lesson.created_at.desc())
        ).scalars().all()
        return render_template("profil.html", all_lessons=all_lessons)

    return redirect(url_for("kullanici_profil"))


@app.route("/kullanici-profil")
@login_required
def kullanici_profil():
    total_posts = current_user.get_total_posts()
    return render_template("kullanici_profil.html", total_posts=total_posts)


@app.route("/tumunu-oku")
@login_required
def tumunu_oku():
    unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for item in unread:
        item.is_read = True
    db.session.commit()
    flash("Tüm bildirimler okundu olarak işaretlendi.", "success")
    return redirect(url_for("bildirimler"))


@app.route("/bildirim-oku/<int:notification_id>")
@login_required
def bildirim_oku(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    if notification.user_id != current_user.id:
        flash("Bu bildirimi görüntüleme yetkiniz yok.", "danger")
        return redirect(url_for("profil"))

    notification.is_read = True
    db.session.commit()

    if notification.topic_id:
        return redirect(url_for("konu_detay", topic_id=notification.topic_id))
    return redirect(url_for("bildirimler"))


@app.route("/bildirimler")
@login_required
def bildirimler():
    notifications = (
        Notification.query
        .filter_by(user_id=current_user.id)
        .order_by(Notification.timestamp.desc())
        .all()
    )

    changed = False
    for item in notifications:
        if not item.is_read:
            item.is_read = True
            changed = True

    if changed:
        db.session.commit()

    return render_template("bildirimler.html", notifications=notifications)


# =========================
# DERS YÖNETİMİ
# =========================
@app.route("/ders-yukle", methods=["POST"])
@login_required
@admin_required
def ders_yukle():
    title = (request.form.get("title") or "").strip()
    slug = (request.form.get("slug") or "").strip()
    content = request.form.get("content") or ""

    main_category = (request.form.get("main_category") or "").strip()
    sub_category = (request.form.get("sub_category") or "").strip()
    description = (request.form.get("description") or "").strip()
    level = (request.form.get("level") or "").strip()
    lesson_count = request.form.get("lesson_count") or "1"

    if not all([title, slug, content, main_category, sub_category, description, level, lesson_count]):
        flash("Lütfen tüm zorunlu alanları doldurun.", "danger")
        return redirect(url_for("profil"))

    existing = db.session.scalar(db.select(Lesson).filter_by(slug=slug))
    if existing:
        flash("Bu URL kısaltması zaten mevcut.", "danger")
        return redirect(url_for("profil"))

    try:
        lesson_count_int = int(lesson_count)
    except ValueError:
        lesson_count_int = 1

    new_lesson = Lesson(
        title=title,
        slug=slug,
        main_category=main_category,
        sub_category=sub_category,
        content=content,
        description=description,
        level=level,
        lesson_count=lesson_count_int,
    )

    try:
        db.session.add(new_lesson)
        db.session.commit()
        flash(f"Ders başarıyla yüklendi: {title}", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Ders yüklenirken hata oluştu: {type(e).__name__}: {e}", "danger")

    return redirect(url_for("profil"))


@app.route("/ders-sil/<int:lesson_id>", methods=["GET", "POST"])
@login_required
@admin_required
def ders_sil(lesson_id):
    lesson = db.session.get(Lesson, lesson_id)
    if not lesson:
        flash("Silinecek ders bulunamadı.", "danger")
        return redirect(url_for("profil"))

    db.session.delete(lesson)
    db.session.commit()
    flash(f'"{lesson.title}" başlıklı ders silindi.', "success")
    return redirect(url_for("profil"))


@app.route("/egitim")
def egitim():
    all_lessons = db.session.execute(
        db.select(Lesson)
        .filter_by(main_category="egitim")
        .order_by(Lesson.created_at.desc())
    ).scalars().all()

    categories = {}
    for lesson in all_lessons:
        categories.setdefault(lesson.sub_category, []).append(lesson)

    return render_template("egitim.html", categories=categories)


@app.route("/gomulu")
def gomulu():
    all_lessons = db.session.execute(
        db.select(Lesson)
        .filter_by(main_category="gomulu")
        .order_by(Lesson.created_at.desc())
    ).scalars().all()

    categories = {}
    for lesson in all_lessons:
        categories.setdefault(lesson.sub_category, []).append(lesson)

    return render_template("gomulu.html", categories=categories)


@app.route("/ders/<slug>")
def ders_detay(slug):
    lesson = db.session.execute(
        db.select(Lesson).filter_by(slug=slug)
    ).scalar_one_or_none()

    if lesson is None:
        flash("Aradığınız ders bulunamadı.", "danger")
        return redirect(url_for("egitim"))

    content_to_process = lesson.content.replace("\r\n", "\n").replace("\r", "\n")
    lesson.html_content = markdown.markdown(
        content_to_process,
        extensions=["fenced_code", "tables"]
    )

    return render_template("ders_detay.html", lesson=lesson)


@app.route("/kategori/<sub_category_name>")
def kategori_listele(sub_category_name):
    lessons = db.session.execute(
        db.select(Lesson)
        .filter_by(sub_category=sub_category_name)
        .order_by(Lesson.created_at.desc())
    ).scalars().all()

    display_name = (
        sub_category_name
        .replace("Cpp", "C++")
        .replace("Siber", "Siber Güvenlik")
        .replace("Arduino", "Arduino Projeleri")
    )

    return render_template("kategori_listesi.html", lessons=lessons, category_name=display_name)


# =========================
# FORUM
# =========================
@app.route("/topluluk")
def topluluk():
    topics = (
        db.session.execute(
            db.select(Topic)
            .order_by(Topic.created_at.desc())
            .options(joinedload(Topic.author))
        )
        .scalars()
        .all()
    )
    return render_template("forum_anasayfa.html", topics=topics)


@app.route("/yeni-konu", methods=["GET", "POST"])
@login_required
def yeni_konu():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()
        tags_input = request.form.get("tags", "")

        if not title or not content:
            flash("Başlık ve içerik boş bırakılamaz.", "danger")
            return redirect(url_for("yeni_konu"))

        new_topic = Topic(title=title, user_id=current_user.id)
        db.session.add(new_topic)
        db.session.flush()

        tag_names = [name.strip().lower() for name in tags_input.split(",") if name.strip()]

        for tag_name in set(tag_names):
            tag = db.session.execute(
                db.select(Tag).filter_by(name=tag_name)
            ).scalar_one_or_none()

            if tag is None:
                tag = Tag(name=tag_name)
                db.session.add(tag)
                db.session.flush()

            new_topic.tags.append(tag)

        first_comment = Comment(
            content=content,
            topic_id=new_topic.id,
            user_id=current_user.id
        )
        db.session.add(first_comment)
        db.session.commit()

        current_user.update_points_and_rank(20)

        flash("Konunuz başarıyla açıldı.", "success")
        return redirect(url_for("topluluk"))

    return render_template("yeni_konu.html")


@app.route("/konu/<int:topic_id>", methods=["GET", "POST"])
def konu_detay(topic_id):
    topic = db.session.get(Topic, topic_id)
    if topic is None:
        flash("Aradığınız konu bulunamadı.", "danger")
        return redirect(url_for("topluluk"))

    comments = (
        db.session.execute(
            db.select(Comment)
            .filter_by(topic_id=topic_id)
            .options(joinedload(Comment.commenter))
            .order_by(Comment.created_at.asc())
        )
        .scalars()
        .all()
    )

    for item in comments:
        item.html_content = markdown.markdown(item.content, extensions=["fenced_code"])

    if request.method == "POST" and current_user.is_authenticated:
        content = (request.form.get("content") or "").strip()

        if not content:
            flash("Yorum içeriği boş olamaz.", "danger")
        else:
            new_comment = Comment(content=content, topic_id=topic_id, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()

            current_user.update_points_and_rank(5)

            topic_creator = topic.author
            if topic_creator and topic_creator.id != current_user.id:
                msg = f"'{topic.title}' başlıklı konunuza yeni cevap geldi."
                notif = Notification(
                    user_id=topic_creator.id,
                    sender_id=current_user.id,
                    topic_id=topic_id,
                    message=msg,
                )
                db.session.add(notif)
                db.session.commit()

            flash("Yorumunuz başarıyla eklendi.", "success")
            return redirect(url_for("konu_detay", topic_id=topic_id))

    return render_template("konu_detay.html", topic=topic, comments=comments)


@app.route("/konu-sil/<int:topic_id>", methods=["POST"])
@login_required
def konu_sil(topic_id):
    topic = db.session.get(Topic, topic_id)

    if topic and (current_user.is_admin or current_user.id == topic.user_id):
        Comment.query.filter_by(topic_id=topic_id).delete()
        Notification.query.filter_by(topic_id=topic_id).delete()
        db.session.delete(topic)
        db.session.commit()

        flash("Konu ve ilgili içerikler silindi.", "success")
        return redirect(url_for("topluluk"))

    flash("Bu konuyu silme yetkiniz yok veya konu bulunamadı.", "danger")
    return redirect(url_for("topluluk"))


@app.route("/yorum-sil/<int:comment_id>")
@login_required
def yorum_sil(comment_id):
    comment = db.session.get(Comment, comment_id)

    if comment and (current_user.is_admin or current_user.id == comment.user_id):
        topic_id = comment.topic_id
        db.session.delete(comment)
        db.session.commit()
        flash("Yorum başarıyla silindi.", "success")
        return redirect(url_for("konu_detay", topic_id=topic_id))

    flash("Yorum silme yetkiniz yok veya yorum bulunamadı.", "danger")
    return redirect(url_for("topluluk"))


@app.route("/tag/<tag_name>")
def tag_detay(tag_name):
    tag = db.session.execute(
        db.select(Tag).filter_by(name=tag_name)
    ).scalar_one_or_none()

    if tag is None:
        flash(f'"{tag_name}" etiketinde konu bulunamadı.', "warning")
        return redirect(url_for("topluluk"))

    return render_template("forum_anasayfa.html", topics=tag.topics, tag_name=tag_name)


@app.route("/arama")
def arama():
    query = (request.args.get("q") or "").strip()
    results = {"lessons": [], "topics": []}

    if query:
        like = f"%{query}%"

        lesson_results = db.session.execute(
            db.select(Lesson).filter(
                or_(Lesson.title.like(like), Lesson.content.like(like))
            )
        ).scalars().all()
        results["lessons"] = lesson_results

        topic_results = db.session.execute(
            db.select(Topic)
            .filter(Topic.title.like(like))
            .options(joinedload(Topic.author))
        ).scalars().all()
        results["topics"] = topic_results

    return render_template("arama_sonuclari.html", query=query, results=results)


@app.route("/iletisim", methods=["GET", "POST"])
def iletisim():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        message_content = (request.form.get("message") or "").strip()

        if not subject or not message_content:
            flash("Konu ve mesaj boş olamaz.", "danger")
            return redirect(url_for("iletisim"))

        recipient = MAIL_USERNAME
        if not recipient:
            flash("Mail sistemi ayarlı değil.", "danger")
            return redirect(url_for("iletisim"))

        msg_subject = f"İLETİŞİM FORMU: {subject} - Gönderen: {name} ({email})"
        msg_body = (
            f"Gönderen Adı: {name}\n"
            f"Gönderen E-postası: {email}\n\n"
            f"Mesaj:\n{message_content}"
        )

        ok = send_email_safely(recipient, msg_subject, msg_body)

        if ok:
            flash("Mesajınız gönderildi.", "success")
        else:
            flash("Mail gönderilemedi. Sunucu kısıtı veya SMTP sorunu olabilir.", "danger")

        return redirect(url_for("iletisim"))

    return render_template("iletisim.html")


@app.route("/ayarlar", methods=["GET", "POST"])
@login_required
def ayarlar():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "update_theme":
            new_theme = request.form.get("theme_preference")
            if new_theme in ["dark", "light"]:
                current_user.theme = new_theme
                db.session.commit()
                flash(f'Tema tercihi "{new_theme}" olarak güncellendi.', "success")
            else:
                flash("Geçersiz tema tercihi.", "danger")

        elif action == "update_profile":
            new_username = (request.form.get("username") or "").strip()

            current_password = request.form.get("current_password") or ""
            new_password = request.form.get("new_password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            updated = False

            if new_password:
                if not current_password:
                    flash("Şifre değiştirmek için mevcut şifrenizi girmelisiniz.", "danger")
                    return redirect(url_for("ayarlar"))

                if not current_user.check_password(current_password):
                    flash("Mevcut şifreniz yanlış.", "danger")
                    return redirect(url_for("ayarlar"))

                if new_password != confirm_password:
                    flash("Yeni şifreler eşleşmiyor.", "danger")
                    return redirect(url_for("ayarlar"))

                current_user.set_password(new_password)
                updated = True
                flash("Şifre güncellendi.", "success")

            if new_username and new_username != current_user.username:
                existing = db.session.scalar(db.select(User).filter_by(username=new_username))
                if existing:
                    flash("Bu kullanıcı adı zaten kullanılıyor.", "danger")
                    return redirect(url_for("ayarlar"))

                current_user.username = new_username
                updated = True
                flash("Kullanıcı adı güncellendi.", "success")

            if updated:
                db.session.commit()
            else:
                flash("Güncellenecek bir bilgi girmediniz.", "warning")

        elif action == "upload_avatar":
            if "avatar" not in request.files:
                flash("Dosya yüklenemedi.", "danger")
                return redirect(url_for("ayarlar"))

            file = request.files["avatar"]
            if not file or file.filename == "":
                flash("Dosya seçilmedi.", "danger")
                return redirect(url_for("ayarlar"))

            if not allowed_file(file.filename):
                flash("Geçersiz dosya türü. Sadece PNG/JPG/JPEG/GIF desteklenir.", "danger")
                return redirect(url_for("ayarlar"))

            filename = secure_filename(file.filename)
            ext = filename.rsplit(".", 1)[1].lower()
            new_filename = f"user_{current_user.id}.{ext}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)

            ensure_folders()
            file.save(filepath)

            current_user.avatar_filename = new_filename
            db.session.commit()

            flash("Profil resminiz güncellendi.", "success")

        return redirect(url_for("ayarlar"))

    return render_template("ayarlar.html")


# =========================
# ADMIN: LESSON IMPORT
# lessons_seed.json repo kökünde olmalı
# =========================
@app.route("/admin/import-lessons", methods=["POST"])
@login_required
@admin_required
def import_lessons():
    seed_path = os.path.join(BASE_DIR, "lessons_seed.json")

    if not os.path.exists(seed_path):
        flash("lessons_seed.json bulunamadı.", "danger")
        return redirect(url_for("profil"))

    with open(seed_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    created = 0
    skipped = 0

    for item in data:
        slug = item.get("slug")
        if not slug:
            continue

        exists = db.session.execute(
            db.select(Lesson).filter_by(slug=slug)
        ).scalar_one_or_none()

        if exists:
            skipped += 1
            continue

        lesson = Lesson(
            title=(item.get("title") or "Ders").strip(),
            slug=slug,
            main_category=item.get("main_category") or "egitim",
            sub_category=item.get("sub_category") or "Genel",
            content=item.get("content") or "",
            level=item.get("level") or "Başlangıç",
            lesson_count=int(item.get("lesson_count") or 1),
            description=item.get("description") or "",
        )
        db.session.add(lesson)
        created += 1

    db.session.commit()
    flash(f"Import tamamlandı: {created} eklendi, {skipped} zaten vardı.", "success")
    return redirect(url_for("profil"))


# =========================
# INIT DB + ADMIN
# =========================
def init_db_and_admin():
    db.create_all()

    admin_email = os.getenv("ADMIN_EMAIL", "admin@techhubtr.com")
    admin_password = os.getenv("ADMIN_PASSWORD", "degistir-bunu")

    admin_user = db.session.execute(
        db.select(User).filter_by(email=admin_email)
    ).scalar_one_or_none()

    if not admin_user:
        admin = User(
            username="AdminUser",
            email=admin_email,
            is_admin=True,
            is_verified=True,
            points=5000,
            theme="dark",
            rank="Kurucu",
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
    else:
        if not admin_user.is_verified:
            admin_user.is_verified = True
            db.session.commit()


# =========================
# BOOTSTRAP
# =========================
try:
    ensure_folders()
    with app.app_context():
        init_db_and_admin()
    print("BOOT OK. DB:", app.config["SQLALCHEMY_DATABASE_URI"][:80], "...")
except Exception as e:
    print("BOOTSTRAP ERROR:", type(e).__name__, e)


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    ensure_folders()
    with app.app_context():
        init_db_and_admin()

    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)