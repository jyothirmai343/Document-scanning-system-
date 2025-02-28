from flask import Flask, request, render_template, url_for, redirect, session, send_file
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
import threading


app = Flask(__name__, static_folder='static') 
app.secret_key = os.urandom(32)  
app.permanent_session_lifetime = timedelta(minutes=30) 
app.config['SESSION_COOKIE_SECURE'] = True  
app.config['SESSION_COOKIE_HTTPONLY'] = True  


DB_PATH = 'site.db'
DOCS_DIR = 'documents'
LOGS_FILE = 'activity_logs.txt'
os.makedirs(DOCS_DIR, exist_ok=True)


db_lock = threading.Lock()


def init_db():
    """Initialize SQLite database with user, post, and credit request tables."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            credits INTEGER DEFAULT 20,
            last_reset TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,  -- Store document content for export
            filename TEXT NOT NULL,
            date_posted TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS credit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        conn.commit()
        conn.close()

init_db()


def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance for text similarity."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def word_frequency(text):
    """Calculate word frequency for similarity comparison."""
    words = text.lower().split()
    freq = {}
    for word in words:
        freq[word] = freq.get(word, 0) + 1
    return freq

def text_similarity(text1, text2):
    """Enhanced similarity using Levenshtein distance and word frequency (AI-like)."""
    lev_dist = levenshtein_distance(text1, text2)
    freq1, freq2 = word_frequency(text1), word_frequency(text2)
    common_words = set(freq1.keys()) & set(freq2.keys())
    similarity = sum(min(freq1.get(w, 0), freq2.get(w, 0)) for w in common_words) / max(sum(freq1.values()), sum(freq2.values()), 1)
    length_factor = min(len(text1), len(text2)) / max(len(text1), len(text2), 1)
    return (similarity * 0.7 + length_factor * 0.3) - (lev_dist / max(len(text1), len(text2), 1))


def hash_password(password):
    """Hash password using SHA-256 for secure storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password, hashed):
    """Verify password against hashed value."""
    return hash_password(password) == hashed

def sanitize_input(text):
    """Basic sanitization to prevent injection."""
    return ''.join(c for c in text if c.isalnum() or c in ' @.-_')


def log_activity(user_id, action):
    """Log user actions to a text file securely with thread safety."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with threading.Lock():
        with open(LOGS_FILE, 'a') as f:
            f.write(f"{timestamp} - User {user_id} - {action}\n")


@app.route("/")
@app.route("/home")
def home():
    """Home page with welcome message and posts for authenticated users."""
    posts = []
    if 'user_id' in session:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT id, title, filename, date_posted FROM posts WHERE user_id = ?", (session['user_id'],))
            posts = [{'id': r[0], 'title': r[1], 'filename': r[2], 'date_posted': r[3]} for r in c.fetchall()]
            conn.close()
    return render_template('home.html', posts=posts)

@app.route("/register", methods=['GET', 'POST'])
def register():
    """Register a new user with secure data storage."""
    if 'user_id' in session:
        return redirect(url_for('home'))
    error = None
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        email = sanitize_input(request.form['email'])
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not all([username, email, password, confirm_password]):
            error = "All fields are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
                if c.fetchone():
                    error = "Username or email already registered. Please log in."
                else:
                    hashed = hash_password(password)
                    c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed))
                    conn.commit()
                    user_id = c.lastrowid
                    log_activity(user_id, "Registered")
                    return redirect(url_for('login'))
                conn.close()
    return render_template('register.html', error=error)

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Login user with secure session management and proper redirect."""
    if 'user_id' in session:
        return redirect(url_for('home'))  
    
    error = None
    if request.method == 'POST':
        email = sanitize_input(request.form['email'])
        password = request.form['password']
        if not all([email, password]):
            error = "Email and password are required."
        else:
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT id, username, password, role FROM users WHERE email = ?", (email,))
                user = c.fetchone()
                conn.close()
            
            if user and check_password(password, user[2]):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                session.permanent = True
                session.modified = True  
                log_activity(user[0], "Logged in")
                return redirect(url_for('home'))  
            else:
                error = "Invalid email or password."
    return render_template('login.html', error=error)

@app.route("/logout")
def logout():
    """Logout user and clear session securely."""
    if 'user_id' in session:
        log_activity(session['user_id'], "Logged out")
    session.clear()
    return redirect(url_for('home'))

@app.route("/profile")
def profile():
    """User profile with credits and scan form."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT credits FROM users WHERE id = ?", (session['user_id'],))
        credits = c.fetchone()[0]
        conn.close()
    return render_template('profile.html', credits=credits)

@app.route("/scan", methods=['GET', 'POST'])
def scan_document():
    """Scan document, deduct credit, and compare with existing documents securely."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    error = None
    message = None
    if request.method == 'POST':
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT credits FROM users WHERE id = ?", (session['user_id'],))
            credits = c.fetchone()[0]
            if credits <= 0:
                error = "No credits available. Wait for the daily reset or request more credits."
            else:
                file = request.files['file']
                if not file:
                    error = "No file uploaded."
                else:
                    try:
                        content = file.read().decode('utf-8')
                        filename = f"{session['user_id']}_{hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:8]}.txt"
                        filepath = os.path.join(DOCS_DIR, filename)
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        c.execute("INSERT INTO posts (title, content, filename, user_id) VALUES (?, ?, ?, ?)", 
                                  ("Scanned Document", content, filename, session['user_id']))
                        c.execute("UPDATE users SET credits = credits - 1 WHERE id = ?", (session['user_id'],))
                        conn.commit()

                        log_activity(session['user_id'], f"Scanned document: {filename}")

                        c.execute("SELECT id, content, filename FROM posts WHERE user_id = ?", (session['user_id'],))
                        all_posts = c.fetchall()
                        if len(all_posts) <= 1:
                            message = "Document scanned successfully. No other documents to compare yet."
                            return render_template('matches.html', similar_posts=[], message=message)
                        
                        similar_posts = []
                        new_content = content
                        for post_id, old_content, old_filename in all_posts[:-1]:
                            similarity = text_similarity(new_content, old_content)
                            if similarity > 0.5:
                                similar_posts.append({'id': post_id, 'filename': old_filename, 'similarity': similarity})

                        message = "Document scanned successfully."
                        return render_template('matches.html', similar_posts=similar_posts, message=message)
                    except UnicodeDecodeError:
                        error = "The uploaded file is not a valid UTF-8 text file."
            conn.close()
        return render_template('scan.html', error=error)
    return render_template('scan.html', error=None)

@app.route("/credits/request", methods=['GET', 'POST'])
def request_credits():
    """Submit a credit request with secure storage (Bonus Feature 3)."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    error = None
    if request.method == 'POST':
        reason = request.form['reason']
        if not reason:
            error = "Reason is required."
        else:
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO credit_requests (user_id, reason) VALUES (?, ?)", (session['user_id'], reason))
                conn.commit()
                conn.close()
            log_activity(session['user_id'], "Requested credits")
            return redirect(url_for('profile'))
    return render_template('request_credits.html', error=error)

@app.route("/admin/dashboard")
def admin_dashboard():
    """Admin dashboard with analytics and secure access (Bonus Feature 3)."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))
    
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, credits FROM users")
        users = [{'id': r[0], 'username': r[1], 'credits': r[2]} for r in c.fetchall()]
        c.execute("SELECT COUNT(*) FROM posts WHERE date_posted LIKE ?", (datetime.now().strftime('%Y-%m-%d') + '%',))
        scans_today = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM credit_requests WHERE status = 'pending'")
        pending_requests = c.fetchone()[0]
        conn.close()
    
    try:
        with open(LOGS_FILE, 'r') as f:
            recent_logs = f.readlines()[-5:]
    except FileNotFoundError:
        recent_logs = ["No logs available yet."]
    
    return render_template('admin_dashboard.html', users=users, scans_today=scans_today, pending_requests=pending_requests, recent_logs=recent_logs)

@app.route("/admin/credit_requests", methods=['GET', 'POST'])
def admin_credit_requests():
    """Approve or deny credit requests with secure updates (Bonus Feature 3)."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))

    message = None
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if request.method == 'POST':
            c.execute("SELECT id, user_id FROM credit_requests WHERE status = 'pending'")
            for req_id, user_id in c.fetchall():
                action = request.form.get(f"action_{req_id}")
                if action == "approve":
                    c.execute("UPDATE credit_requests SET status = 'approved' WHERE id = ?", (req_id,))
                    c.execute("UPDATE users SET credits = credits + 10 WHERE id = ?", (user_id,))
                    log_activity(user_id, "Credit request approved by admin")
                elif action == "reject":
                    c.execute("UPDATE credit_requests SET status = 'rejected' WHERE id = ?", (req_id,))
                    log_activity(user_id, "Credit request rejected by admin")
            conn.commit()
            message = "Credit requests updated successfully."

        c.execute("SELECT id, user_id, reason, requested_at FROM credit_requests WHERE status = 'pending'")
        credit_requests = [{'id': r[0], 'user_id': r[1], 'reason': r[2], 'requested_at': r[3]} for r in c.fetchall()]
        conn.close()
    return render_template('admin_credit_requests.html', credit_requests=credit_requests, message=message)

@app.route("/admin/adjust_credits/<int:user_id>", methods=['GET', 'POST'])
def adjust_credits(user_id):
    """Manually adjust user credits securely."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))

    error = None
    message = None
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, credits FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            return redirect(url_for('home'))
        username, credits = user

        if request.method == 'POST':
            try:
                new_credits = int(request.form['credits'])
                if new_credits < 0:
                    error = "Credits cannot be negative."
                else:
                    c.execute("UPDATE users SET credits = ? WHERE id = ?", (new_credits, user_id))
                    conn.commit()
                    log_activity(user_id, f"Credits adjusted to {new_credits} by admin")
                    message = f"Updated {username}'s credits to {new_credits}."
            except ValueError:
                error = "Invalid input. Please enter a valid number."

        conn.close()
    return render_template('adjust_credits.html', username=username, credits=credits, user_id=user_id, error=error, message=message)

@app.route("/export_scan_history")
def export_scan_history():
    """Export user's scan history including document content as text files (Bonus Feature 4)."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT title, content, filename, date_posted FROM posts WHERE user_id = ?", (session['user_id'],))
        posts = c.fetchall()
        conn.close()
    
    import zipfile
    import io
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for title, content, filename, date_posted in posts:
            text_filename = f"{filename}_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
            zip_file.writestr(text_filename, f"Title: {title}\nContent:\n{content}\nDate Posted: {date_posted}")
    
    zip_buffer.seek(0)
    log_activity(session['user_id'], "Exported scan history as ZIP")
    
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=f"scan_history_{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}.zip",
        mimetype='application/zip'
    )

@app.before_request
def reset_credits():
    """Auto-reset credits at midnight local time securely (Bonus Feature 1)."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, credits, last_reset FROM users")
        now = datetime.now()
        midnight = datetime(now.year, now.month, now.day, 0, 0, 0)
        for user_id, credits, last_reset in c.fetchall():
            last_reset_dt = datetime.strptime(last_reset, '%Y-%m-%d %H:%M:%S')
            if now >= midnight and last_reset_dt < midnight:
                c.execute("UPDATE users SET credits = 20, last_reset = ? WHERE id = ?", 
                          (now.strftime('%Y-%m-%d %H:%M:%S'), user_id))
                log_activity(user_id, "Credits reset to 20 at midnight")
        conn.commit()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', threaded=True) 