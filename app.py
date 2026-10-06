from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from urllib.parse import urlparse, parse_qs, unquote
from difflib import SequenceMatcher
from datetime import datetime
import json, os, time, re

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-development-only-change-me")

USERS_FILE = "users.json"
WATCH_LOG = "watch_log.json"
SAFE_LIST_FILE = "safe_urls.json"
MALICIOUS_LIST_FILE = "malicious_urls.json"

# ----------------- Load/Save Users -----------------
def load_users():
    # create default file if missing
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
        json.dump({}, f)

    # load and normalize older formats where user -> password string
    with open(USERS_FILE, "r") as f:
        data = json.load(f)

    normalized = {}
    for username, value in data.items():
        if isinstance(value, str):
            normalized[username] = {"password": value, "email": f"{username}@example.com"}
        elif isinstance(value, dict):
            # ensure keys exist
            pwd = value.get("password", "")
            email = value.get("email", f"{username}@example.com")
            normalized[username] = {"password": pwd, "email": email}
        else:
            # unexpected format — coerce to string password
            normalized[username] = {"password": str(value), "email": f"{username}@example.com"}

    # write back normalized form (safe to do every load)
    with open(USERS_FILE, "w") as f:
        json.dump(normalized, f, indent=4)

    return normalized

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# ----------------- Utility: load JSON list -----------------
def load_json_list(path):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
                return [s.lower().strip() for s in data if isinstance(s, str)]
    except Exception:
        pass
    return []

# ----------------- LOGIN -----------------
login_attempts = {}

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    global login_attempts
    users = load_users()
    max_attempts = 3
    block_time = 60

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        now = time.time()

        if username not in login_attempts:
            login_attempts[username] = {"count": 0, "last_attempt": 0}

        # Block window check
        if login_attempts[username]["count"] >= max_attempts and now - login_attempts[username]["last_attempt"] < block_time:
            remaining = int(block_time - (now - login_attempts[username]["last_attempt"]))
            return render_template("login.html", error=f"Too many attempts. Try again in {remaining} seconds.")

        # Validate credentials
        if username in users and users[username]["password"] == password:
            session["user"] = username
            login_attempts[username] = {"count": 0, "last_attempt": 0}
            return redirect(url_for("dashboard"))
        else:
            login_attempts[username]["count"] += 1
            login_attempts[username]["last_attempt"] = now
            remaining_attempts = max_attempts - login_attempts[username]["count"]
            if remaining_attempts > 0:
                return render_template("login.html", error=f"Invalid credentials. {remaining_attempts} attempts left.")
            else:
                return render_template("login.html", error=f"Too many attempts. Try again in {block_time} seconds.")

    return render_template("login.html")

# ----------------- SIGNUP -----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    users = load_users()
    field_error = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        username_pattern = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=<>?]).+$')
        password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=<>?]).{10,}$')
        email_pattern = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

        # Username uniqueness
        if username in users:
            error = "User already exists!"
            field_error["username"] = True

        # Email uniqueness
        elif any(u.get("email", "").lower() == email for u in users.values()):
            error = "Email already in use. Please use a different email."
            field_error["email"] = True

        elif not username_pattern.match(username):
            error = "Username must include letters, numbers, and at least one special character (!@#$%^&*()_+-=<>?)."
            field_error["username"] = True

        elif not email_pattern.match(email):
            error = "Please enter a valid email address."
            field_error["email"] = True

        elif not password_pattern.match(password):
            error = "Password must be at least 10 characters long and include uppercase, lowercase, numbers, and a special character."
            field_error["password"] = True

        elif password != confirm_password:
            error = "Passwords do not match!"
            field_error["confirm_password"] = True

        else:
            users[username] = {"password": password, "email": email}
            save_users(users)
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))

        return render_template("signup.html", error=error, field_error=field_error)

    return render_template("signup.html", field_error={})

# ----------------- DASHBOARD -----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

# ----------------- AWARENESS -----------------
@app.route("/awareness")
def awareness():
    if "user" not in session:
        return redirect(url_for("login"))

    local_video = url_for('static', filename='videos/cyber.mp4')
    video_param = request.args.get('video', '').strip()

    if video_param:
        try:
            parsed = urlparse(video_param)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                video_url = video_param
            else:
                flash("Invalid video URL — using local video.", "error")
                video_url = local_video
        except Exception:
            flash("Invalid video URL — using local video.", "error")
            video_url = local_video
    else:
        video_url = local_video

    timestamp = int(time.time())
    return render_template("awareness.html", video_url=video_url, local_video=local_video, timestamp=timestamp)

# ----------------- LEGAL -----------------
@app.route("/legal")
def legal():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("legal.html")

# ----------------- URL DETECTION (improved) -----------------
def domain_from_netloc(netloc):
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return netloc.lower()

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

def check_domain_against_list(domain, lst):
    # exact match or suffix match (subdomains)
    for item in lst:
        if domain == item or domain.endswith("." + item):
            return True
    return False

@app.route("/url_detection", methods=["GET", "POST"])
def url_detection():
    if "user" not in session:
        return redirect(url_for("login"))

    result = None
    details = None

    # load lists
    safe_list = load_json_list(SAFE_LIST_FILE)
    malicious_list = load_json_list(MALICIOUS_LIST_FILE)

    # example known brands for typosquat checks (expand as needed)
    known_brands = ["google", "facebook", "paypal", "amazon", "microsoft", "apple",
                    "bankofamerica", "linkedin", "twitter", "github", "openai"]

    if request.method == "POST":
        raw = request.form.get("url", "").strip()
        if not raw:
            result = "❌ Please enter a URL."
            return render_template("url_detection.html", result=result, details=None)

        try:
            parsed = urlparse(raw)
            scheme = (parsed.scheme or "").lower()
            netloc = domain_from_netloc(parsed.netloc)
            path = parsed.path or ""
            query = parsed.query or ""
            full_url = raw

            # Basic validation
            if scheme not in ("http", "https") or not netloc:
                result = "❌ Invalid URL format. Use http:// or https://"
                return render_template("url_detection.html", result=result, details=None)

            score = 0
            details_list = []

            # 1) Check malicious list first
            if check_domain_against_list(netloc, malicious_list):
                result = f"⚠️ Malicious domain detected: {netloc}"
                details_list.append("Matched domain in malicious list.")
                details = " ".join(details_list)
                return render_template("url_detection.html", result=result, details=details)

            # 2) Check safe list first
            if check_domain_against_list(netloc, safe_list):
                result = f"✅ URL appears in safe list: {netloc}"
                details_list.append("Domain appears in safe list (trusted).")
                details = " ".join(details_list)
                return render_template("url_detection.html", result=result, details=details)

            # 3) Heuristic scoring
            if len(full_url) > 100:
                score += 2
                details_list.append(f"URL is long ({len(full_url)} chars).")

            if netloc.count('.') > 3:
                score += 2
                details_list.append(f"Many subdomains ({netloc.count('.')}).")

            # 4) Suspicious keywords in URL (bank removed)
            suspicious_keywords = ["login", "verify", "update", "secure", "account",
                                   "confirm", "free", "prize", "claim", "signin"]
            if any(kw in full_url.lower() for kw in suspicious_keywords):
                score += 2
                details_list.append("Contains suspicious keyword(s).")

            # 5) Executable/download file extensions
            dangerous_ext = [".exe", ".msi", ".apk", ".bat", ".cmd", ".scr", ".zip"]
            if any(path.lower().endswith(ext) for ext in dangerous_ext) or any(ext in path.lower() for ext in dangerous_ext):
                score += 3
                details_list.append("Contains download or executable file extension in path.")

            # 6) Redirect parameters
            q = parse_qs(query)
            redirect_params = ["redirect", "url", "to", "dest", "destination"]
            for p in redirect_params:
                if p in q:
                    for dest in q[p]:
                        decoded = unquote(dest)
                        try:
                            pd = urlparse(decoded)
                            dnet = domain_from_netloc(pd.netloc)
                            if dnet and check_domain_against_list(dnet, malicious_list):
                                result = f"⚠️ Redirects to known malicious domain: {dnet}"
                                details_list.append(f"Redirect param `{p}` points to {dnet} (malicious list).")
                                details = " ".join(details_list)
                                return render_template("url_detection.html", result=result, details=details)
                        except Exception:
                            pass

            # 7) Punycode / IDN
            if "xn--" in netloc:
                score += 2
                details_list.append("Contains punycode / IDN (xn--).")

            # 8) Numeric IP host
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc):
                score += 3
                details_list.append("Host is an IP address (numeric) — suspicious.")

            # 9) Typosquat / brand similarity
            host_parts = netloc.replace("www.", "").split('.')
            domain_root = host_parts[-2] if len(host_parts) >= 2 else host_parts[0]
            for brand in known_brands:
                sim = similar(domain_root, brand)
                if sim > 0.85 and domain_root != brand:
                    score += 3
                    details_list.append(f"Domain `{domain_root}` is very similar to brand `{brand}` (similarity {sim:.2f}).")
                    break
                elif sim > 0.65 and domain_root != brand:
                    score += 1
                    details_list.append(f"Domain `{domain_root}` is somewhat similar to brand `{brand}` (similarity {sim:.2f}).")

            # Final scoring
            if score >= 5:
                result = f"⚠️ Unsafe / Malicious-looking URL: {netloc}"
            elif score >= 2:
                result = f"⚠️ Suspicious URL: {netloc}"
            else:
                result = f"✅ URL looks safe: {netloc}"

            if not details_list:
                details_list = ["No obvious suspicious signs detected."]
            details = " ".join(details_list)

        except Exception as e:
            result = "❌ Error analyzing URL."
            details = str(e)

    return render_template("url_detection.html", result=result, details=details)

# ----------------- FORGOT PASSWORD -----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    users = load_users()
    field_error = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=<>?]).{10,}$')

        if username not in users:
            flash("User does not exist.", "error")
            field_error["username"] = True
        elif not password_pattern.match(new_password):
            flash("Weak password: use 10+ chars with uppercase, lowercase, numbers, and symbols.", "error")
            field_error["new_password"] = True
        elif new_password != confirm_password:
            flash("Passwords do not match.", "error")
            field_error["confirm_password"] = True
        else:
            users[username]["password"] = new_password
            save_users(users)
            flash("Password successfully updated! Please login.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html", field_error=field_error)

    return render_template("forgot_password.html", field_error={})

# ----------------- LOGOUT -----------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# ----------------- API: Mark watched -----------------
@app.route("/api/mark-watched", methods=["POST"])
def mark_watched():
    if "user" not in session:
        return jsonify({"error": "not authenticated"}), 401

    data = request.get_json() or {}
    video = data.get("video")
    entry = {
        "user": session["user"],
        "video": video,
        "time": datetime.utcnow().isoformat() + "Z"
    }

    try:
        logs = []
        if os.path.exists(WATCH_LOG):
            with open(WATCH_LOG, "r") as f:
                logs = json.load(f)
        logs.append(entry)
        with open(WATCH_LOG, "w") as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "ok"})

# ----------------- RUN APP -----------------
if __name__ == "__main__":
    app.run(debug=True)
