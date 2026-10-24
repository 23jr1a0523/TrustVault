from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory,
    jsonify,
)
from database import init_db, get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv
from google import genai
import hashlib
import os
import uuid

# ---------------- CONFIGURATION ----------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-this-key"
)

UPLOAD_FOLDER = BASE_DIR / "private_uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 5 * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Initialize database
init_db()


# ---------------- LOGIN REQUIRED ----------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            error = "Username must have at least 3 characters."

        elif len(password) < 8:
            error = "Password must have at least 8 characters."

        else:
            connection = get_db_connection()

            try:
                connection.execute(
                    """
                    INSERT INTO users (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (username, generate_password_hash(password)),
                )
                connection.commit()
                return redirect(url_for("login"))

            except Exception:
                connection.rollback()
                error = "Username may already exist. Try another."

            finally:
                connection.close()

    return render_template("register.html", error=error)


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()

        try:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template("login.html", error=error)


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ---------------- ACCESS CONTROL ----------------

@app.route("/access-control")
@login_required
def access_control():
    return render_template("access_control.html")


# ---------------- FILE INTEGRITY ----------------

@app.route("/file-integrity")
@login_required
def file_integrity():
    return render_template("file_integrity.html")


# ---------------- AI ASSISTANT ----------------

@app.route("/ai-assistant")
@login_required
def ai_assistant():
    return render_template("ai_assistant.html")


# ---------------- AI CHAT API ----------------

@app.route("/api/chat", methods=["POST"])
@login_required
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({"error": "Invalid message format."}), 400

    message = message.strip()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    if len(message) > 1000:
        return jsonify({
            "error": "Message must be 1000 characters or fewer."
        }), 400

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return jsonify({
            "error": "AI is not configured. Check your .env file."
        }), 503

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=(
                "You are TrustVault's AI security assistant. "
                "Answer questions about document security, access control, "
                "password safety, SHA-256 integrity checks, and the "
                "TrustVault application. Be clear and helpful. "
                "Never request passwords or API keys. "
                "You cannot access the application's private files or "
                "database. Do not ask users to submit confidential documents.\n\n"
                f"User question: {message}"
            ),
        )

        answer = response.text

        if not answer:
            return jsonify({
                "error": "The AI returned an empty response. Please try again."
            }), 502

        return jsonify({"answer": answer})

    except Exception as e:
        app.logger.exception("Gemini API request failed")

        return jsonify({
            "error": (
                f"Gemini error: {type(e).__name__}: {str(e)[:300]}"
            )
        }), 502


# ---------------- LIST DOCUMENTS ----------------

@app.route("/documents")
@login_required
def documents():
    connection = get_db_connection()

    try:
        files = connection.execute(
            """
            SELECT * FROM documents
            WHERE owner_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],),
        ).fetchall()
    finally:
        connection.close()

    return render_template(
        "documents.html",
        files=files,
        message=None
    )


# ---------------- UPLOAD DOCUMENT ----------------

@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    uploaded_file = request.files.get("document")

    if not uploaded_file or not uploaded_file.filename:
        return render_template(
            "documents.html",
            files=[],
            message="Please select a file.",
        ), 400

    safe_name = secure_filename(uploaded_file.filename)

    if not safe_name or "." not in safe_name:
        return render_template(
            "documents.html",
            files=[],
            message="Invalid filename.",
        ), 400

    extension = safe_name.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return render_template(
            "documents.html",
            files=[],
            message="File type not allowed.",
        ), 400

    content = uploaded_file.read(MAX_FILE_SIZE + 1)

    if not content or len(content) > MAX_FILE_SIZE:
        return render_template(
            "documents.html",
            files=[],
            message="File is empty or exceeds 5 MB.",
        ), 400

    file_hash = hashlib.sha256(content).hexdigest()
    stored_name = f"{uuid.uuid4().hex}.{extension}"
    stored_path = UPLOAD_FOLDER / stored_name

    stored_path.write_bytes(content)

    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO documents
                (owner_id, original_name, stored_name, sha256_hash)
            VALUES (?, ?, ?, ?)
            """,
            (
                session["user_id"],
                safe_name,
                stored_name,
                file_hash,
            ),
        )

        connection.execute(
            """
            INSERT INTO audit_logs (user_id, action, document_name)
            VALUES (?, ?, ?)
            """,
            (session["user_id"], "UPLOAD", safe_name),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        stored_path.unlink(missing_ok=True)
        raise

    finally:
        connection.close()

    return redirect(url_for("documents"))


# ---------------- DOWNLOAD DOCUMENT ----------------

@app.route("/documents/download/<int:document_id>")
@login_required
def download_document(document_id):
    connection = get_db_connection()

    try:
        document = connection.execute(
            """
            SELECT * FROM documents
            WHERE id = ? AND owner_id = ?
            """,
            (document_id, session["user_id"]),
        ).fetchone()
    finally:
        connection.close()

    if not document:
        return "Document not found or access denied.", 404

    file_path = UPLOAD_FOLDER / document["stored_name"]

    if not file_path.is_file():
        return "Stored document is missing.", 404

    current_hash = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    if current_hash != document["sha256_hash"]:
        return (
            "Integrity check failed! Document may have been modified.",
            409,
        )

    response = send_from_directory(
        str(UPLOAD_FOLDER),
        document["stored_name"],
        as_attachment=True,
        download_name=document["original_name"],
    )

    response.headers["Cache-Control"] = "no-store"

    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO audit_logs (user_id, action, document_name)
            VALUES (?, ?, ?)
            """,
            (
                session["user_id"],
                "DOWNLOAD",
                document["original_name"],
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return response


# ---------------- ADMIN AUDIT LOGS ----------------

@app.route("/admin/audit-logs")
@login_required
def audit_logs():
    if session.get("role") != "admin":
        return "Access denied: Admins only.", 403

    connection = get_db_connection()

    try:
        logs = connection.execute(
            """
            SELECT audit_logs.*, users.username
            FROM audit_logs
            LEFT JOIN users ON audit_logs.user_id = users.id
            ORDER BY audit_logs.id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("audit_logs.html", logs=logs)


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- ADMIN USERS ----------------

@app.route("/admin/users")
@login_required
def admin_users():
    if session.get("role") != "admin":
        return "Access denied: Admins only.", 403

    connection = get_db_connection()

    try:
        users = connection.execute(
            """
            SELECT id, username, role, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("admin_users.html", users=users)


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)