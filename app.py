import hashlib
import logging
import os
import re
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db_connection

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "local-development-key-change-before-deployment"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)
logging.basicConfig(level=logging.INFO)


def query_one(sql, params=()):
    conn = get_db_connection()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchone()
    finally:
        if cur:
            cur.close()
        conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    """Return a cryptographically random session-backed token for HTML forms."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not submitted or not expected or not secrets.compare_digest(submitted, expected):
            flash("Your form session expired. Please try again.", "danger")
            return redirect(url_for("index"))


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


@app.context_processor
def inject_contact_email():
    return {"contact_email": os.getenv("CONTACT_EMAIL", "support@example.com")}


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("view_all"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("Please complete all fields.", "danger")
        elif len(username) > 100 or len(email) > 100:
            flash("Username and email must be 100 characters or fewer.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
        elif password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            conn = get_db_connection()
            cur = None
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.rollback()
                flash("That username or email is already registered.", "warning")
                return render_template("register.html")
            finally:
                if cur:
                    cur.close()
                conn.close()
            flash("Your account was created. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        user = query_one(
            "SELECT id, username, email, password_hash FROM users WHERE LOWER(email)=? OR LOWER(username)=?",
            (identity.lower(), identity.lower()),
        )
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            flash(f"Welcome, {user['username']}!", "success")
            return redirect(url_for("view_all"))
        flash("Incorrect username/email or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/notes")
@app.route("/viewall")
@login_required
def view_all():
    search = request.args.get("q", "").strip()
    conn = get_db_connection()
    cur = None
    try:
        cur = conn.cursor()
        if search:
            like = f"%{search}%"
            cur.execute(
                """SELECT id, title, content, created_at, updated_at FROM notes
                   WHERE user_id=? AND (title LIKE ? OR content LIKE ?)
                   ORDER BY updated_at DESC, id DESC""",
                (session["user_id"], like, like),
            )
        else:
            cur.execute(
                """SELECT id, title, content, created_at, updated_at FROM notes
                   WHERE user_id=? ORDER BY updated_at DESC, id DESC""",
                (session["user_id"],),
            )
        notes = cur.fetchall()
    finally:
        if cur:
            cur.close()
        conn.close()
    return render_template("notes.html", notes=notes, search=search)


@app.route("/addnote", methods=["GET", "POST"])
@login_required
def add_note():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            flash("Please enter both a title and note content.", "danger")
            return render_template("note_form.html", mode="add", note=None)
        if len(title) > 150:
            flash("Title must be 150 characters or fewer.", "danger")
            return render_template("note_form.html", mode="add", note=None)

        conn = get_db_connection()
        cur = None
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)",
                (title, content, session["user_id"]),
            )
            conn.commit()
        finally:
            if cur:
                cur.close()
            conn.close()
        flash("Note added successfully!", "success")
        return redirect(url_for("view_all"))
    return render_template("note_form.html", mode="add", note=None)


@app.route("/viewnotes/<int:note_id>")
@login_required
def view_note(note_id):
    note = query_one(
        """SELECT id, title, content, created_at, updated_at FROM notes
           WHERE id=? AND user_id=?""",
        (note_id, session["user_id"]),
    )
    if not note:
        flash("Note not found.", "warning")
        return redirect(url_for("view_all"))
    return render_template("note_detail.html", note=note)


@app.route("/updatenote/<int:note_id>", methods=["GET", "POST"])
@login_required
def update_note(note_id):
    note = query_one(
        """SELECT id, title, content, created_at, updated_at FROM notes
           WHERE id=? AND user_id=?""",
        (note_id, session["user_id"]),
    )
    if not note:
        flash("Note not found.", "warning")
        return redirect(url_for("view_all"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            flash("Please enter both a title and note content.", "danger")
            note["title"], note["content"] = title, content
            return render_template("note_form.html", mode="edit", note=note)
        if len(title) > 150:
            flash("Title must be 150 characters or fewer.", "danger")
            note["title"], note["content"] = title, content
            return render_template("note_form.html", mode="edit", note=note)

        conn = get_db_connection()
        cur = None
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE notes SET title=?, content=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
                (title, content, note_id, session["user_id"]),
            )
            conn.commit()
        finally:
            if cur:
                cur.close()
            conn.close()
        flash("Note updated successfully!", "success")
        return redirect(url_for("view_note", note_id=note_id))
    return render_template("note_form.html", mode="edit", note=note)


@app.route("/deletenote/<int:note_id>", methods=["POST"])
@login_required
def delete_note(note_id):
    conn = get_db_connection()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM notes WHERE id=? AND user_id=?", (note_id, session["user_id"]))
        deleted = cur.rowcount
        conn.commit()
    finally:
        if cur:
            cur.close()
        conn.close()
    flash("Note deleted successfully." if deleted else "Note not found.", "success" if deleted else "warning")
    return redirect(url_for("view_all"))


def send_reset_email(recipient, reset_url):
    mail_username = os.getenv("MAIL_USERNAME", "")
    mail_password = os.getenv("MAIL_PASSWORD", "")
    sender = os.getenv("MAIL_DEFAULT_SENDER", mail_username)
    if not mail_username or not mail_password or not sender:
        raise RuntimeError("SMTP credentials are not configured")

    message = EmailMessage()
    message["Subject"] = "Reset your Notes App password"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your Notes App password.\n\n"
        f"Open this link within 30 minutes: {reset_url}\n\n"
        "If you did not request this, you can ignore this message."
    )
    with smtplib.SMTP(os.getenv("MAIL_SERVER", "smtp.gmail.com"), int(os.getenv("MAIL_PORT", "587")), timeout=15) as smtp:
        smtp.starttls()
        smtp.login(mail_username, mail_password)
        smtp.send_message(message)


@app.route("/forgot-password", methods=["GET", "POST"])
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = query_one("SELECT id, email FROM users WHERE LOWER(email)=?", (email,))
        # Generic response prevents attackers from checking which email addresses are registered.
        if user:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            expires_at = (datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            conn = get_db_connection()
            cur = None
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                    (user["id"], token_hash, expires_at),
                )
                conn.commit()
            finally:
                if cur:
                    cur.close()
                conn.close()
            reset_url = url_for("reset_password", token=token, _external=True)
            try:
                send_reset_email(user["email"], reset_url)
            except Exception:
                app.logger.exception("Password reset email failed")
                if app.debug:
                    print(f"[DEVELOPMENT ONLY] Password reset link: {reset_url}")
        flash("If that email is registered, password-reset instructions will be sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    reset_record = query_one(
        """SELECT id, user_id FROM password_resets
           WHERE token_hash=? AND used_at IS NULL AND expires_at > datetime('now')""",
        (token_hash,),
    )
    if not reset_record:
        flash("This password-reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
        elif password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            conn = get_db_connection()
            cur = None
            try:
                # Acquire a write lock before checking and consuming the token,
                # so two requests cannot reuse the same one-time token.
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.cursor()
                cur.execute(
                    "SELECT id FROM password_resets WHERE id=? AND used_at IS NULL AND expires_at > datetime('now')",
                    (reset_record["id"],),
                )
                still_valid = cur.fetchone()
                if not still_valid:
                    conn.rollback()
                    flash("This password-reset link has already been used or expired.", "danger")
                    return redirect(url_for("forgot_password"))
                cur.execute("UPDATE users SET password_hash=? WHERE id=?",
                            (generate_password_hash(password), reset_record["user_id"]))
                cur.execute("UPDATE password_resets SET used_at=datetime('now') WHERE user_id=? AND used_at IS NULL",
                            (reset_record["user_id"],))
                conn.commit()
            finally:
                if cur:
                    cur.close()
                conn.close()
            flash("Password changed successfully. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    """Show the contact form and email submitted support requests."""
    if request.method == "POST":
        # Honeypot field: normal users should leave it empty.
        if request.form.get("website", "").strip():
            # Do not reveal bot detection details.
            flash("Thanks for contacting us. Your message has been received.", "success")
            return redirect(url_for("contact"))

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        problem = request.form.get("message", "").strip()

        if not all((name, email, subject, problem)):
            flash("Please complete every field before sending your message.", "danger")
            return render_template("contact.html", form_data=request.form)
        if len(name) > 100 or len(email) > 254 or len(subject) > 150 or len(problem) > 5000:
            flash("One or more fields are too long. Please shorten your message and try again.", "danger")
            return render_template("contact.html", form_data=request.form)
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Please enter a valid email address so support can reply to you.", "danger")
            return render_template("contact.html", form_data=request.form)

        mail_username = os.getenv("MAIL_USERNAME", "sudineshvuluvala@gmail.com")
        mail_password = os.getenv("MAIL_PASSWORD", "mvobhhnupkcrufvw")
        sender = os.getenv("MAIL_DEFAULT_SENDER", mail_username)
        recipient = os.getenv("CONTACT_EMAIL", "").strip()
        if not mail_username or not mail_password or not sender or not recipient:
            app.logger.error("Contact form email settings are incomplete")
            flash("The contact form is not configured yet. Please try again later or contact the site administrator.", "danger")
            return render_template("contact.html", form_data=request.form), 503

        # Keep message construction inside the try block too: malformed From/To
        # settings or a bad MAIL_PORT should produce a logged mail error, not an
        # unhandled Flask 500 page.
        try:
            message = EmailMessage()
            # App-generated subject prevents user-provided email header injection.
            message["Subject"] = f"Notes App support: {subject[:150]}"
            message["From"] = sender
            message["To"] = recipient
            message["Reply-To"] = email
            current_user = session.get("username", "Guest")
            message.set_content(
                "A new support request was submitted through the Notes App contact form.\n\n"
                f"Name: {name}\n"
                f"Email: {email}\n"
                f"Account: {current_user}\n"
                f"Subject: {subject}\n\n"
                "Problem / message:\n"
                f"{problem}\n"
            )

            with smtplib.SMTP(
                os.getenv("MAIL_SERVER", "smtp.gmail.com"),
                int(os.getenv("MAIL_PORT", "587")),
                timeout=20,
            ) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(mail_username, mail_password)
                smtp.send_message(message)
        except Exception as exc:
            # Full details go to the server terminal/log; never expose SMTP
            # credentials or internal exception details to the browser.
            app.logger.exception("Failed to send contact form message (?)", type(exc).__name__)
            flash(
                "The form was submitted, but the email could not be sent. Check the MAIL_* and CONTACT_EMAIL settings in your .env file, then restart Flask.",
                "danger",
            )
            return render_template("contact.html", form_data=request.form), 502

        flash("Your message was sent successfully. Our support team will get back to you.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", form_data={})



@app.errorhandler(sqlite3.Error)
def database_error(error):
    app.logger.exception("Database error: ?", error)
    return render_template(
        "error.html",
        message="Could not open or query the SQLite database. Run python init_db.py and check DATABASE_PATH in your .env file.",
    ), 500


@app.errorhandler(404)
def page_not_found(_error):
    return render_template("error.html", message="The page you requested could not be found."), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
