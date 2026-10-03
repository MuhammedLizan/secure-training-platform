from flask import Flask, render_template, request, redirect, url_for, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secure-training-platform-secret-key"
app.config["JWT_SECRET_KEY"] = "jwt-secret-key-for-training-platform"
app.config["JWT_TOKEN_LOCATION"] = ["query_string"]
app.config["JWT_QUERY_STRING_NAME"] = "token"
jwt = JWTManager(app)

DATABASE = "database/users.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            mobile TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

@app.route("/")
def home():
    return "Secure Training Platform"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        full_name = request.form["full_name"].strip()
        email = request.form["email"].strip()
        mobile = request.form["mobile"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not username or not full_name or not email or not mobile or not password or not confirm_password:
            return "Please fill all the required fields"

        if not re.match(r"^[A-Za-z0-9._%+-]+@gmail\.com$", email):
            return "Please enter a valid Gmail address"

        if not re.match(r"^\d{10}$", mobile):
            return "Mobile number must contain exactly 10 digits"

        missing_rules = []

        if not re.search(r"[A-Z]", password):
            missing_rules.append("one uppercase letter")

        if not re.search(r"[a-z]", password):
            missing_rules.append("one lowercase letter")

        if not re.search(r"\d", password):
            missing_rules.append("one number")

        if not re.search(r"[^A-Za-z0-9]", password):
            missing_rules.append("one symbol")

        if missing_rules:
            return "Password must contain: " + ", ".join(missing_rules)

        if password != confirm_password:
            return "Passwords do not match"

        conn = get_db()

        existing_user = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:
            conn.close()
            return "Username already exists"

        password_hash = generate_password_hash(password)

        conn.execute(
            """
            INSERT INTO users (username, full_name, email, mobile, password)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, full_name, email, mobile, password_hash)
        )

        conn.commit()
        conn.close()

        return "Registration successful"

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username and not password:
            return "Please enter username and password"

        if not username:
            return "Please enter username"

        if not password:
            return "Please enter password"

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if not user:
            return "Username does not match with registered names"

        attempts_key = "failed_attempts_" + username
        attempts = session.get(attempts_key, 0)

        if attempts >= 3:
            return "Warning: Maximum login attempts exceeded"

        if not check_password_hash(user["password"], password):
            attempts += 1
            session[attempts_key] = attempts

            if attempts >= 3:
                return "Warning: Maximum login attempts exceeded"

            return f"Incorrect password. Attempt {attempts} of 3"


        session[attempts_key] = 0

        access_token = create_access_token(identity=username)

        return redirect(url_for("dashboard", token=access_token))

    return render_template("login.html")

@app.route("/dashboard")
@jwt_required()
def dashboard():
    username = get_jwt_identity()
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)