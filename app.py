from datetime import datetime
from time import time
import os
import cloudinary
import cloudinary.uploader
from flask import Flask, render_template, request, redirect, session, jsonify, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import threading
import time as time_module
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from dotenv import load_dotenv
from utils.security import verify_password, hash_password
from functools import wraps


env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(env_path)

app = Flask(__name__)
app.secret_key = 'skillbridgekey'

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', 4000))
app.config['UPLOAD_FOLDER'] = 'static/uploads'



app.config['MYSQL_CUSTOM_OPTIONS'] = {
    'ssl': {
        'ca': '/etc/secrets/isrgrootx1.pem'
    }
}


mysql = MySQL(app)
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
    secure=True)
bcrypt = Bcrypt(app)




# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = str(os.environ.get('MAIL_USE_TLS', 'True')).lower() == 'true'
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['BREVO_API_KEY'] = os.environ.get('BREVO_API_KEY')

print("MAIL_SERVER =", app.config['MAIL_SERVER'])
print("MAIL_PORT =", app.config['MAIL_PORT'])
print("MAIL_USERNAME =", app.config['MAIL_USERNAME'])
print("MAIL_PASSWORD exists =", bool(app.config['MAIL_PASSWORD']))

# DIAGNOSTIC LOGGING TO FILE
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = str(os.environ.get('MAIL_USE_TLS', 'True')).lower() == 'true'
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')


mail = Mail(app)

@app.template_filter('avatar_url')
def avatar_url_filter(filename, name=None):
    if not filename:
        if name:
            import urllib.parse
            safe_name = urllib.parse.quote(name)
            return f"https://ui-avatars.com/api/?name={safe_name}&background=E0E7FF&color=4F46E5&size=100"
        return "https://ui-avatars.com/api/?name=User&background=E0E7FF&color=4F46E5"
    if filename.startswith('http://') or filename.startswith('https://'):
        return filename
    return f"/static/uploads/{filename}"


def ensure_user_metrics_table():
    """Create a tiny metrics table used for persistent user totals."""
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_metrics (
            metric_key VARCHAR(100) PRIMARY KEY,
            metric_value BIGINT NOT NULL DEFAULT 0
        )
    """)
    mysql.connection.commit()


def ensure_total_user_metric():
    """
    Ensure total registered users is tracked persistently.

    We seed from MAX(user_id) so existing deleted accounts are approximated better
    than a simple current row count.
    """
    ensure_user_metrics_table()

    cur = mysql.connection.cursor()
    cur.execute("SELECT metric_value FROM app_metrics WHERE metric_key='total_registered_users'")
    row = cur.fetchone()
    if row is None:
        cur.execute("SELECT COALESCE(MAX(user_id), 0) FROM users")
        seeded_total = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO app_metrics (metric_key, metric_value) VALUES ('total_registered_users', %s)",
            (seeded_total,)
        )
        mysql.connection.commit()


def increment_total_user_metric():
    """Increase the persistent total-user counter after a successful signup."""
    ensure_total_user_metric()
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE app_metrics
        SET metric_value = metric_value + 1
        WHERE metric_key = 'total_registered_users'
    """)
    mysql.connection.commit()


def get_total_registered_users():
    """Return the total number of users ever registered, including deleted ones."""
    ensure_total_user_metric()
    cur = mysql.connection.cursor()
    cur.execute("SELECT metric_value FROM app_metrics WHERE metric_key='total_registered_users'")
    row = cur.fetchone()
    return row[0] if row else 0


def ensure_contact_messages_reply_tracking():
    """Ensure contact messages support reply expiry tracking."""
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'contact_messages'
          AND COLUMN_NAME = 'replied_at'
        LIMIT 1
    """)
    if not cur.fetchone():
        cur = mysql.connection.cursor()
        cur.execute("ALTER TABLE contact_messages ADD COLUMN replied_at DATETIME NULL AFTER status")
        mysql.connection.commit()


def cleanup_expired_replied_messages():
    """Delete replied contact messages once they are older than 48 hours."""
    cur = mysql.connection.cursor()
    cur.execute("""
        DELETE FROM contact_messages
        WHERE status = 'Replied'
          AND replied_at IS NOT NULL
          AND replied_at <= NOW() - INTERVAL 48 HOUR
    """)
    deleted = cur.rowcount
    if deleted:
        mysql.connection.commit()
    return deleted

# Register Blueprints
from routes.auth import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

# ─── Authentication Decorator ────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        is_valid, needs_migration = verify_password(user['password'], password)

        if user and is_valid:
            # Auto-migrate to Bcrypt if successful login with old hash
            if needs_migration:
                new_hash = hash_password(password)
                cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (new_hash, user['user_id']))
                mysql.connection.commit()

            session['user_id'] = user['user_id']
            session['name'] = user['name']
            session['profile_pic'] = user['profile_pic']
            session['role'] = 'candidate'
            flash(f'Welcome back, {user["name"]}!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

# ─── Pages ────────────────────────────────────────────────────────────────────

@app.route('/home')
@app.route('/')
def home():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Fetch platform metrics
    cur.execute("SELECT COUNT(*) as count FROM users")
    total_users = cur.fetchone()['count'] or 0
    
    cur.execute("SELECT COUNT(*) as count FROM sessions WHERE status='Completed'")
    total_sessions = cur.fetchone()['count'] or 0
    
    cur.execute("SELECT COUNT(*) as count FROM skills_offered")
    total_skills = cur.fetchone()['count'] or 0
    
    return render_template('home.html', 
                           total_users=total_users, 
                           total_sessions=total_sessions, 
                           total_skills=total_skills)

@app.route('/browse')
def browse():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT u.user_id, u.name, u.profile_pic, u.bio,
               COALESCE(AVG(r.rating), 0) AS avg_rating,
               (SELECT COUNT(*) FROM sessions WHERE (teacher_id = u.user_id OR learner_id = u.user_id) AND status='Completed') AS total_sessions,
               (SELECT GROUP_CONCAT(skill_name SEPARATOR ', ') FROM skills_offered WHERE user_id = u.user_id) AS offered_skills
        FROM users u
        LEFT JOIN ratings r ON u.user_id = r.rated_user_id
        GROUP BY u.user_id
        ORDER BY avg_rating DESC, total_sessions DESC
        LIMIT 10
    """)
    top_users = cur.fetchall()
    
    # Format avg_rating to 1 decimal place
    for u in top_users:
        if u['avg_rating']:
            u['avg_rating'] = round(float(u['avg_rating']), 1)
        else:
            u['avg_rating'] = 0.0
    
    # Get top skills
    cur.execute("""
        SELECT skill_name, COUNT(*) as count 
        FROM skills_offered 
        GROUP BY skill_name 
        ORDER BY count DESC 
        LIMIT 5
    """)
    top_skills = cur.fetchall()
            
    return render_template('browse.html', top_users=top_users, top_skills=top_skills)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get user info
    cur.execute("SELECT * FROM users WHERE user_id=%s", (uid,))
    user_info = cur.fetchone()
    
    # Calculate ratings
    cur.execute("""
        SELECT COALESCE(AVG(rating), 0) AS avg_rating, COUNT(rating) AS rating_count
        FROM ratings
        WHERE rated_user_id = %s
    """, (uid,))
    rating_data = cur.fetchone()
    
    avg_rating = 0.0
    rating_count = 0
    if rating_data:
        avg_rating = round(float(rating_data['avg_rating']), 1)
        rating_count = rating_data['rating_count']

    # Get recent reviews
    cur.execute("""
        SELECT r.rating, r.feedback, r.session_id, u.name AS rater_name, u.profile_pic AS rater_pic,
               s.topic AS session_topic, s.teacher_id, s.learner_id
        FROM ratings r
        JOIN users u ON r.rater_id = u.user_id
        LEFT JOIN sessions s ON r.session_id = s.id
        WHERE r.rated_user_id = %s
        ORDER BY r.id DESC
        LIMIT 5
    """, (uid,))
    reviews = cur.fetchall()
    for review in reviews:
        if review.get('session_topic'):
            topic = review['session_topic']
            if uid == review.get('teacher_id'):
                review['session_type'] = f"tutoring session for '{topic}'"
            elif uid == review.get('learner_id'):
                review['session_type'] = f"learning session for '{topic}'"
            else:
                review['session_type'] = f"session for '{topic}'"
        else:
            review['session_type'] = "skill exchange session"
    
    # Get skills offered
    cur.execute("SELECT skill_name FROM skills_offered WHERE user_id=%s", (uid,))
    skills_offered = [row['skill_name'] for row in cur.fetchall()]
    
    # Get skills wanted
    cur.execute("SELECT skill_name FROM skills_wanted WHERE user_id=%s", (uid,))
    skills_wanted = [row['skill_name'] for row in cur.fetchall()]
    
    return render_template('dashboard.html', 
                           user=user_info, 
                           skills_offered=skills_offered, 
                           skills_wanted=skills_wanted,
                           avg_rating=avg_rating,
                           rating_count=rating_count,
                           reviews=reviews)

@app.route('/add_skill', methods=['GET','POST'])
@login_required
def add_skill():
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        offers_raw = request.form.get('offers', '')
        wants_raw = request.form.get('wants', '')

        offer_list = [s.strip().title() for s in offers_raw.split('||') if s.strip()]
        want_list = [s.strip().title() for s in wants_raw.split('||') if s.strip()]

        added_count = 0
        for offer in offer_list:
            cur.execute("SELECT * FROM skills_offered WHERE user_id=%s AND skill_name=%s", (uid, offer))
            if not cur.fetchone():
                cur.execute("INSERT INTO skills_offered(user_id,skill_name) VALUES(%s,%s)", (uid, offer))
                added_count += 1

        for want in want_list:
            cur.execute("SELECT * FROM skills_wanted WHERE user_id=%s AND skill_name=%s", (uid, want))
            if not cur.fetchone():
                cur.execute("INSERT INTO skills_wanted(user_id,skill_name) VALUES(%s,%s)", (uid, want))
                added_count += 1

        mysql.connection.commit()
        if added_count > 0:
            flash(f'{added_count} skill(s) added successfully!', 'success')
        else:
            flash('No new skills were added (all already exist).', 'info')
        return redirect('/dashboard')

    # GET: fetch existing skills to show in the template
    cur.execute("SELECT skill_name FROM skills_offered WHERE user_id=%s", (uid,))
    existing_offers = [row['skill_name'] for row in cur.fetchall()]
    cur.execute("SELECT skill_name FROM skills_wanted WHERE user_id=%s", (uid,))
    existing_wants = [row['skill_name'] for row in cur.fetchall()]

    return render_template('add_skill.html', existing_offers=existing_offers, existing_wants=existing_wants)

@app.route('/search')
@login_required
def search():
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Broad matching: Match if:
    #   1. They OFFER a skill I WANT to learn, OR
    #   2. They WANT a skill I can OFFER (teach)
    # This allows learners to find teachers and vice versa
    query = """
    SELECT DISTINCT u.user_id, u.name, u.profile_pic,
           match_skill.skill_name AS matched_skill,
           match_skill.match_type
    FROM users u
    JOIN (
        -- Users who OFFER a skill I WANT to learn
        SELECT so.user_id, so.skill_name, 'they_teach' AS match_type
        FROM skills_offered so
        WHERE so.skill_name IN (SELECT skill_name FROM skills_wanted WHERE user_id=%s)
        UNION
        -- Users who WANT a skill I can OFFER
        SELECT sw.user_id, sw.skill_name, 'they_learn' AS match_type
        FROM skills_wanted sw
        WHERE sw.skill_name IN (SELECT skill_name FROM skills_offered WHERE user_id=%s)
    ) AS match_skill ON u.user_id = match_skill.user_id
    WHERE u.user_id != %s
    AND NOT EXISTS (
        SELECT 1 FROM connections c 
        WHERE (c.user1_id = %s AND c.user2_id = u.user_id) 
           OR (c.user1_id = u.user_id AND c.user2_id = %s)
    )
    ORDER BY u.name
    """

    cur.execute(query, (uid, uid, uid, uid, uid))
    raw_matches = cur.fetchall()

    # Check pending request status for each match (per user + per skill)
    for match in raw_matches:
        cur.execute("""
            SELECT status FROM swap_requests
            WHERE ((sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s))
            AND skill=%s AND status='Pending'
            LIMIT 1
        """, (uid, match['user_id'], match['user_id'], uid, match['matched_skill']))
        req = cur.fetchone()
        match['request_status'] = req['status'] if req else None

    return render_template('search.html', matches=raw_matches)

@app.route('/request/<int:receiver_id>')
@login_required
def request_swap(receiver_id):
    sender_id = session['user_id']
    skill = request.args.get('skill', '')

    # Create cursor
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # 0️⃣ Check if already connected
    cur.execute("""
        SELECT * FROM connections 
        WHERE (user1_id=%s AND user2_id=%s) OR (user1_id=%s AND user2_id=%s)
    """, (sender_id, receiver_id, receiver_id, sender_id))
    
    if cur.fetchone():
        flash('You are already connected with this user.', 'info')
        return redirect('/search')

    # 1️⃣ Prevent duplicate request for same user + same skill
    cur.execute("""
        SELECT * FROM swap_requests 
        WHERE ((sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s))
        AND skill=%s AND status='Pending'
    """, (sender_id, receiver_id, receiver_id, sender_id, skill))
    
    if cur.fetchone():
        flash('A request for this skill is already pending.', 'warning')
        return redirect('/search')

    # 2️⃣ Save swap request with skill info
    cur.execute("""
        INSERT INTO swap_requests(sender_id, receiver_id, skill)
        VALUES(%s, %s, %s)
    """, (sender_id, receiver_id, skill))
    mysql.connection.commit()

    # 3️⃣ Get sender name
    cur.execute("SELECT name FROM users WHERE user_id=%s", (sender_id,))
    sender = cur.fetchone()
    sender_name = sender['name']

    # 4️⃣ Save detailed clickable notification
    skill_text = f" for '{skill}'" if skill else ''
    cur.execute("""
        INSERT INTO notifications(user_id, sender_id, message, link)
        VALUES(%s, %s, %s, %s)
    """, (
        receiver_id,
        sender_id,
        f"{sender_name} sent you a skill exchange request{skill_text}",
        f"/requests"
    ))
    mysql.connection.commit()

    flash('Swap request sent!', 'success')
    return redirect('/search')


@app.route('/requests')
@login_required
def view_requests():
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT sr.id, sr.sender_id, u.name, sr.status, sr.skill
        FROM swap_requests sr
        JOIN users u ON sr.sender_id = u.user_id
        WHERE sr.receiver_id=%s
        AND NOT EXISTS (
            SELECT 1 FROM connections c 
            WHERE (c.user1_id = %s AND c.user2_id = u.user_id) 
               OR (c.user1_id = u.user_id AND c.user2_id = %s)
        )
        ORDER BY sr.id DESC
    """, (uid, uid, uid))

    requests = cur.fetchall()
    return render_template('requests.html', requests=requests)


@app.route('/accept/<int:req_id>')
@login_required
def accept_request(req_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get request details
    cur.execute("SELECT sender_id, receiver_id FROM swap_requests WHERE id=%s", (req_id,))
    req = cur.fetchone()
    
    if req and req['receiver_id'] == session['user_id']:
        sender_id = req['sender_id']
        receiver_id = req['receiver_id']
        
        # Mark Accepted
        cur.execute("UPDATE swap_requests SET status='Accepted' WHERE id=%s", (req_id,))
        
        # Add mutually to connections
        # Insert avoiding duplicates
        cur.execute("""
            INSERT IGNORE INTO connections(user1_id, user2_id) 
            VALUES(%s, %s)
        """, (min(sender_id, receiver_id), max(sender_id, receiver_id)))
        
        # Remove any other pending reverse requests between these two
        cur.execute("""
            DELETE FROM swap_requests 
            WHERE (sender_id=%s AND receiver_id=%s AND status='Pending')
        """, (receiver_id, sender_id))
        
        mysql.connection.commit()
    
    return redirect('/requests')

@app.route('/reject/<int:req_id>')
@login_required
def reject_request(req_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE swap_requests SET status='Rejected' WHERE id=%s", (req_id,))
    mysql.connection.commit()
    return redirect('/requests')

@app.route('/rate/<int:uid>', methods=['GET','POST'])
@login_required
def rate_user(uid):
    if request.method == 'POST':
        rating = request.form['rating']
        feedback = request.form['feedback']

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO ratings(rater_id, rated_user_id, rating, feedback)
            VALUES(%s,%s,%s,%s)
        """, (session['user_id'], uid, rating, feedback))
        mysql.connection.commit()

        return redirect('/dashboard')

    return render_template('rate.html', uid=uid)


@app.route('/connections')
@login_required
def connections():
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get users where (uid=user1 and other=user2) OR (uid=user2 and other=user1)
    cur.execute("""
        SELECT u.user_id, u.name, u.profile_pic, u.location, u.skill_level 
        FROM connections c
        JOIN users u ON (c.user1_id = u.user_id OR c.user2_id = u.user_id)
        WHERE (c.user1_id = %s OR c.user2_id = %s)
        AND u.user_id != %s
    """, (uid, uid, uid))
    
    connected_users = cur.fetchall()
    
    return render_template('connections.html', connections=connected_users)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        education = request.form.get('education', '')
        profession = request.form.get('profession', '')
        location = request.form.get('location', '')
        languages_list = request.form.getlist('language')
        language = ", ".join(languages_list)
        timezone = request.form.get('timezone', '')
        skill_level = request.form.get('skill_level', 'Beginner')
        bio = request.form.get('bio', '')
        
        file = request.files.get('pic')
        
        if file and file.filename != '':
            # Upload the profile picture directly to Cloudinary
            upload_result = cloudinary.uploader.upload(file)
            cloudinary_url = upload_result.get("secure_url")
            
            # Update including picture
            cur.execute("""
                UPDATE users 
                SET name=%s, email=%s, education=%s, profession=%s, location=%s, language=%s, timezone=%s, skill_level=%s, bio=%s, profile_pic=%s
                WHERE user_id=%s
            """, (name, email, education, profession, location, language, timezone, skill_level, bio, cloudinary_url, uid))
            session['profile_pic'] = cloudinary_url
        else:
            # Update without picture
            cur.execute("""
                UPDATE users 
                SET name=%s, email=%s, education=%s, profession=%s, location=%s, language=%s, timezone=%s, skill_level=%s, bio=%s
                WHERE user_id=%s
            """, (name, email, education, profession, location, language, timezone, skill_level, bio, uid))
        
        mysql.connection.commit()
        session['name'] = name
        flash('Profile updated!', 'success')
        return redirect('/dashboard')

    # GET request: fetch current info
    cur.execute("SELECT * FROM users WHERE user_id=%s", (uid,))
    user = cur.fetchone()
    return render_template('edit_profile.html', user=user)



@app.route('/profile/<int:uid>')
def view_profile(uid):
    is_admin = session.get('role') == 'admin'
    if 'user_id' not in session and not is_admin:
        return redirect('/')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get user info
    cur.execute("SELECT * FROM users WHERE user_id=%s", (uid,))
    user_info = cur.fetchone()
    
    if not user_info:
        return "User not found", 404

    # Calculate ratings
    cur.execute("""
        SELECT COALESCE(AVG(rating), 0) AS avg_rating, COUNT(rating) AS rating_count
        FROM ratings
        WHERE rated_user_id = %s
    """, (uid,))
    rating_data = cur.fetchone()
    
    avg_rating = 0.0
    rating_count = 0
    if rating_data:
        avg_rating = round(float(rating_data['avg_rating']), 1)
        rating_count = rating_data['rating_count']

    # Get recent reviews
    cur.execute("""
        SELECT r.rating, r.feedback, r.session_id, u.name AS rater_name, u.profile_pic AS rater_pic,
               s.topic AS session_topic, s.teacher_id, s.learner_id
        FROM ratings r
        JOIN users u ON r.rater_id = u.user_id
        LEFT JOIN sessions s ON r.session_id = s.id
        WHERE r.rated_user_id = %s
        ORDER BY r.id DESC
        LIMIT 5
    """, (uid,))
    reviews = cur.fetchall()
    for review in reviews:
        if review.get('session_topic'):
            topic = review['session_topic']
            if uid == review.get('teacher_id'):
                review['session_type'] = f"tutoring session for '{topic}'"
            elif uid == review.get('learner_id'):
                review['session_type'] = f"learning session for '{topic}'"
            else:
                review['session_type'] = f"session for '{topic}'"
        else:
            review['session_type'] = "skill exchange session"

    # Get skills offered
    cur.execute("SELECT skill_name FROM skills_offered WHERE user_id=%s", (uid,))
    skills_offered = [row['skill_name'] for row in cur.fetchall()]
    
    # Get skills wanted
    cur.execute("SELECT skill_name FROM skills_wanted WHERE user_id=%s", (uid,))
    skills_wanted = [row['skill_name'] for row in cur.fetchall()]
    
    # Check connection and request status
    is_connected = False
    request_status = None
    if 'user_id' in session and session['user_id'] != uid:
        my_id = session['user_id']
        cur.execute("""
            SELECT 1 FROM connections 
            WHERE (user1_id=%s AND user2_id=%s) OR (user1_id=%s AND user2_id=%s)
        """, (my_id, uid, uid, my_id))
        if cur.fetchone():
            is_connected = True
        else:
            cur.execute("""
                SELECT status FROM swap_requests
                WHERE (sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s)
                ORDER BY id DESC LIMIT 1
            """, (my_id, uid, uid, my_id))
            req = cur.fetchone()
            if req:
                request_status = req['status']
                
    return render_template('profile.html', 
                           user=user_info, 
                           skills_offered=skills_offered, 
                           skills_wanted=skills_wanted,
                           is_admin=is_admin,
                           is_connected=is_connected,
                           request_status=request_status,
                           avg_rating=avg_rating,
                           rating_count=rating_count,
                           reviews=reviews)


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin_panel')
@admin_required
def admin_panel():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()

    return render_template('admin_panel.html', users=users)

@app.route('/delete_user/<int:id>', methods=['GET', 'POST'])
@admin_required
def delete_user(id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT name FROM users WHERE user_id=%s", (id,))
    user = cur.fetchone()

    if not user:
        flash('User not found.', 'warning')
        return redirect('/admin_panel')

    try:
        # Clean up related records before removing the user.
        cleanup_queries = [
            ("DELETE FROM blocked_users WHERE blocker_id=%s OR blocked_id=%s", (id, id)),
            ("DELETE FROM chat WHERE sender_id=%s OR receiver_id=%s", (id, id)),
            ("DELETE FROM connections WHERE user1_id=%s OR user2_id=%s", (id, id)),
            ("DELETE FROM notifications WHERE user_id=%s OR sender_id=%s", (id, id)),
            ("DELETE FROM ratings WHERE rater_id=%s OR rated_user_id=%s", (id, id)),
            ("DELETE FROM reports WHERE reporter_id=%s OR reported_id=%s", (id, id)),
            ("DELETE FROM sessions WHERE teacher_id=%s OR learner_id=%s", (id, id)),
            ("DELETE FROM skills_offered WHERE user_id=%s", (id,)),
            ("DELETE FROM skills_wanted WHERE user_id=%s", (id,)),
            ("DELETE FROM swap_requests WHERE sender_id=%s OR receiver_id=%s", (id, id)),
            ("DELETE FROM transactions WHERE user_id=%s", (id,)),
            ("DELETE FROM typing_status WHERE user_id=%s", (id,)),
            ("DELETE FROM wallet WHERE user_id=%s", (id,)),
        ]

        for query, params in cleanup_queries:
            cur.execute(query, params)

        cur.execute("DELETE FROM users WHERE user_id=%s", (id,))
        mysql.connection.commit()
        flash(f"{user['name']} was deleted successfully.", 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Couldn't delete user: {e}", 'danger')

    return redirect('/admin_panel')

@app.route('/admin_stats')
@admin_required
def admin_stats():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT COUNT(*) as count FROM users")
    total_users = cur.fetchone()['count'] or 0

    # Active users (last 7 days)
    cur.execute("SELECT COUNT(*) as count FROM users WHERE last_seen >= NOW() - INTERVAL 7 DAY")
    active_users = cur.fetchone()['count'] or 0
    inactive_users = total_users - active_users

    cur.execute("SELECT COUNT(*) as count FROM sessions")
    sessions_count = cur.fetchone()['count'] or 0

    # Skill Level Distribution
    cur.execute("SELECT skill_level, COUNT(*) as count FROM users GROUP BY skill_level")
    skill_data = cur.fetchall()
    
    # Format for Chart.js
    skill_labels = []
    skill_counts = []
    for row in skill_data:
        label = row['skill_level'] if row['skill_level'] else 'Unspecified'
        skill_labels.append(label)
        skill_counts.append(row['count'])

    return render_template('admin_stats.html',
                           active_users=active_users,
                           inactive_users=inactive_users,
                           sessions=sessions_count,
                           total_users=total_users,
                           skill_labels=skill_labels,
                           skill_counts=skill_counts)


@app.route('/admin_messages')
@admin_required
def admin_messages():
    ensure_contact_messages_reply_tracking()
    cleanup_expired_replied_messages()
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM contact_messages ORDER BY created_at DESC")
    messages = cur.fetchall()
    return render_template('admin_messages.html', messages=messages)

@app.route('/admin/reply_message', methods=['POST'])
@admin_required
def admin_reply_message():
    ensure_contact_messages_reply_tracking()
    data = request.get_json()
    msg_id = data.get('id')
    reply_text = data.get('reply')
    recipient_email = data.get('email')

    if not all([msg_id, reply_text, recipient_email]):
        return jsonify({'success': False, 'message': 'Missing data.'}), 400

    from flask_mail import Message
    try:
        msg = Message(subject="Re: Your SkillBridge Inquiry",
                      sender=app.config.get('MAIL_DEFAULT_SENDER'),
                      recipients=[recipient_email],
                      body=f"Hello,\n\n{reply_text}\n\nRegards,\nSkillBridge Team")
        mail.send(msg)

        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE contact_messages SET status='Replied', replied_at=NOW() WHERE id=%s",
            (msg_id,)
        )
        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'Reply sent successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/contact/submit', methods=['POST'])
def contact_submit():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')

    if not all([name, email, message]):
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO contact_messages (name, email, message) VALUES (%s, %s, %s)", (name, email, message))
    mysql.connection.commit()
    return jsonify({'success': True, 'message': 'Your message has been sent!'})


# ─── Sessions & Booking ──────────────────────────────────────────────────────

def read_wallet_credits(cur, user_id, default_credits=0):
    cur.execute("""
        SELECT COUNT(*) AS wallet_rows, COALESCE(MAX(credits), 0) AS credits
        FROM wallet
        WHERE user_id=%s
    """, (user_id,))
    row = cur.fetchone()

    if row and int(row['wallet_rows']) > 0:
        return int(row['credits'])
    return None if default_credits is None else int(default_credits)


def ensure_wallet_credits(cur, user_id, default_credits=20):
    current_credits = read_wallet_credits(cur, user_id, default_credits=None)
    if current_credits is not None:
        return int(current_credits)

    cur.execute("INSERT INTO wallet (user_id, credits) VALUES (%s, %s)", (user_id, default_credits))
    return int(default_credits)


def get_booking_topics(cur, my_id, peer_id):
    cur.execute("SELECT skill_name FROM skills_offered WHERE user_id=%s", (my_id,))
    my_offered = {row['skill_name'] for row in cur.fetchall()}

    cur.execute("SELECT skill_name FROM skills_wanted WHERE user_id=%s", (my_id,))
    my_wanted = {row['skill_name'] for row in cur.fetchall()}

    cur.execute("SELECT skill_name FROM skills_offered WHERE user_id=%s", (peer_id,))
    peer_offered = {row['skill_name'] for row in cur.fetchall()}

    cur.execute("SELECT skill_name FROM skills_wanted WHERE user_id=%s", (peer_id,))
    peer_wanted = {row['skill_name'] for row in cur.fetchall()}

    return sorted(my_offered.intersection(peer_wanted)), sorted(my_wanted.intersection(peer_offered))


def get_role_topic_options(cur, my_id, peer_id, role):
    topics_teach, topics_learn = get_booking_topics(cur, my_id, peer_id)
    return topics_teach if role == 'teach' else topics_learn


@app.route('/sessions')
@login_required
def sessions():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    my_id = session['user_id']
    cur.execute("""
        SELECT s.*, 
               CASE 
                   WHEN s.teacher_id = %s THEN u_learner.name
                   ELSE u_teacher.name
               END as peer_name,
               CASE
                   WHEN s.teacher_id = %s THEN 'Teaching'
                   ELSE 'Learning'
               END as my_role,
               w.credits as learner_credits,
               (SELECT COUNT(*) FROM ratings r WHERE r.rater_id = %s AND r.session_id = s.id) as has_rated
        FROM sessions s
        LEFT JOIN users u_teacher ON s.teacher_id = u_teacher.user_id
        LEFT JOIN users u_learner ON s.learner_id = u_learner.user_id
        LEFT JOIN wallet w ON s.learner_id = w.user_id
        WHERE s.teacher_id=%s OR s.learner_id=%s
        ORDER BY s.session_date DESC
    """, (my_id, my_id, my_id, my_id, my_id))

    data = cur.fetchall()
    return render_template('sessions.html', sessions=data)

@app.route('/book/<int:uid>', methods=['GET','POST'])
@login_required
def book_session(uid):
    my_id = session['user_id']

    if uid == my_id:
        flash("You cannot book a session with yourself.", "warning")
        return redirect('/sessions')

    if request.method == 'POST':
        session_time = request.form.get('session_time', '').strip()
        role = request.form.get('role', '').strip()
        topic = request.form.get('topic', '').strip()

        try:
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            if role not in ['teach', 'learn']:
                flash("Please select a role first.", "warning")
                return redirect(f'/book/{uid}')

            valid_topics = get_role_topic_options(cur, my_id, uid, role)
            if not topic or topic not in valid_topics:
                flash("Please select a valid skill for the chosen role.", "warning")
                return redirect(f'/book/{uid}')

            if role == 'teach':
                teacher_id = my_id
                learner_id = uid
            else:
                teacher_id = uid
                learner_id = my_id

            learner_credits = ensure_wallet_credits(cur, learner_id)
            if learner_credits < 10:
                mysql.connection.commit()
                flash("The learner needs at least 10 credits before you can continue.", "danger")
                return redirect(f'/book/{uid}')

            if not session_time:
                flash("Please select a valid date and time.", "warning")
                return redirect(f'/book/{uid}')

            try:
                session_dt = datetime.strptime(session_time, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash("Please select a valid date and time.", "warning")
                return redirect(f'/book/{uid}')

            if session_dt <= datetime.now():
                flash("Please choose a future date and time.", "warning")
                return redirect(f'/book/{uid}')

            status = 'Pending Confirmation'
            meet_link = f"https://meet.jit.si/skillbridge_{teacher_id}_{learner_id}"

            cur.execute("""
                INSERT INTO sessions (teacher_id, learner_id, session_date, meet_link, status, topic, booked_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (teacher_id, learner_id, session_dt.strftime('%Y-%m-%d %H:%M:%S'), meet_link, status, topic, my_id))
            session_id = cur.lastrowid
            cur.execute("UPDATE sessions SET booked_by=%s, status=%s WHERE id=%s", (my_id, status, session_id))

            cur.execute("SELECT name FROM users WHERE user_id=%s", (my_id,))
            sender = cur.fetchone()
            sender_name = sender['name'] if sender else 'Someone'

            cur.execute("""
                INSERT INTO notifications(user_id,message,link)
                VALUES(%s,%s,%s)
            """, (uid, f"{sender_name} requested a {topic} session and is waiting for your confirmation.", "/sessions"))

            mysql.connection.commit()
            flash("Booking request sent to the second user for confirmation.", "success")
            return redirect('/sessions')
        except Exception as e:
            mysql.connection.rollback()
            flash(f"An error occurred during booking: {str(e)}", "danger")
            return redirect(f'/book/{uid}')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    my_credits = 0
    peer_credits = 0

    try:
        my_credits = read_wallet_credits(cur, my_id, default_credits=0)
    except Exception as e:
        print(f"Booking my wallet read error for user {my_id}: {str(e)}")

    try:
        peer_credits = read_wallet_credits(cur, uid, default_credits=0)
    except Exception as e:
        print(f"Booking peer wallet read error for user {uid}: {str(e)}")

    cur.execute("SELECT name FROM users WHERE user_id=%s", (uid,))
    peer = cur.fetchone()
    peer_name = peer['name'] if peer else 'Peer'

    topics_teach, topics_learn = get_booking_topics(cur, my_id, uid)

    return render_template(
        'book_session.html',
        peer_id=uid,
        peer_name=peer_name,
        topics_teach=topics_teach or [],
        topics_learn=topics_learn or [],
        my_credits=int(my_credits or 0),
        peer_credits=int(peer_credits or 0)
    )


@app.route('/api/booking_state/<int:uid>')
@login_required
def booking_state(uid):
    my_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        my_credits = read_wallet_credits(cur, my_id, default_credits=0)
        peer_credits = read_wallet_credits(cur, uid, default_credits=0)
        return jsonify({
            'success': True,
            'my_credits': int(my_credits or 0),
            'peer_credits': int(peer_credits or 0)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/complete_session/<int:sid>')
@login_required
def complete_session(sid):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    my_id = session['user_id']

    # Get session info
    cur.execute("""
        SELECT s.*,
               u_teacher.name as teacher_name,
               u_learner.name as learner_name
        FROM sessions s
        LEFT JOIN users u_teacher ON s.teacher_id = u_teacher.user_id
        LEFT JOIN users u_learner ON s.learner_id = u_learner.user_id
        WHERE s.id=%s
    """, (sid,))
    s = cur.fetchone()

    if not s:
        flash("Session not found.", "danger")
        return redirect('/sessions')
        
    if s['teacher_id'] != my_id and s['learner_id'] != my_id:
        flash("Unauthorized.", "danger")
        return redirect('/sessions')

    if s['status'] == 'Completed':
        flash("Session already completed.", "info")
        # Still redirect to rating in case they missed it
        peer_id = s['learner_id'] if my_id == s['teacher_id'] else s['teacher_id']
        return redirect(f'/rate_peer/{peer_id}/{sid}')

    teacher = s['teacher_id']
    learner = s['learner_id']
    topic = s['topic'] or 'skill'
    peer_id = learner if my_id == teacher else teacher

    # Mark session completed
    cur.execute("UPDATE sessions SET status='Completed' WHERE id=%s", (sid,))

    cur.execute("INSERT INTO notifications(user_id,message,link) VALUES(%s,%s,%s)", 
               (teacher, f"Your {topic} session has been marked as completed.", "/sessions"))
    cur.execute("INSERT INTO notifications(user_id,message,link) VALUES(%s,%s,%s)", 
               (learner, f"Your {topic} session has been marked as completed.", "/sessions"))

    mysql.connection.commit()
    flash("Session marked as completed!", "success")

    return redirect(f'/rate_peer/{peer_id}/{sid}')

@app.route('/rate_peer/<int:peer_id>/<int:sid>', methods=['GET', 'POST'])
@login_required
def rate_peer(peer_id, sid):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    my_id = session['user_id']
    if request.method == 'POST':
        rating = request.form.get('rating')
        feedback = request.form.get('feedback')
        cur.execute("INSERT INTO ratings (rater_id, rated_user_id, rating, feedback, session_id) VALUES (%s, %s, %s, %s, %s)",
                    (my_id, peer_id, rating, feedback, sid))
        mysql.connection.commit()
        flash("Thank you for your feedback!", "success")
        return redirect('/sessions')

    cur.execute("SELECT name, profile_pic FROM users WHERE user_id=%s", (peer_id,))
    peer = cur.fetchone()
    peer_name = peer['name'] if peer else 'Peer'
    peer_pic = peer['profile_pic'] if peer else None
    return render_template('rate.html', peer_id=peer_id, sid=sid, peer_name=peer_name, peer_pic=peer_pic)

@app.route('/confirm_session/<int:sid>', methods=['POST'])
@login_required
def confirm_session(sid):
    my_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cur.execute("SELECT * FROM sessions WHERE id=%s", (sid,))
    s = cur.fetchone()
    
    if not s or (s['learner_id'] != my_id and s['teacher_id'] != my_id) or s['status'] != 'Pending Confirmation':
        flash("Invalid session confirmation.", "danger")
        return redirect('/sessions')
        
    booked_by = s.get('booked_by')
    if booked_by is None:
        flash("This booking request is missing requester information. Please create the booking again.", "danger")
        return redirect('/sessions')

    if int(booked_by) == int(my_id):
        flash("You cannot confirm a session you requested. Wait for the other user.", "danger")
        return redirect('/sessions')
        
    learner_id = s['learner_id']
    learner_credits = ensure_wallet_credits(cur, learner_id)

    if learner_credits < 10:
        mysql.connection.commit()
        flash("Confirmation failed: The learner lacks the required 10 credits.", "danger")
        return redirect('/sessions')

    teacher_id = s['teacher_id']
    topic = s['topic'] or 'Skill Session'

    try:
        cur.execute("""
            UPDATE wallet SET credits = credits - 5 
            WHERE user_id=%s AND credits >= 5
        """, (learner_id,))
        
        if cur.rowcount == 0:
            # Fallback for missing row or insufficient balance check
            cur.execute("SELECT credits FROM wallet WHERE user_id=%s", (learner_id,))
            w = cur.fetchone()
            if not w or w['credits'] < 5:
                flash("Confirmation failed: Learner has insufficient credits for upfront payment.", "danger")
                return redirect('/sessions')
            cur.execute("UPDATE wallet SET credits = credits - 5 WHERE user_id=%s", (learner_id,))

        cur.execute("""
            INSERT INTO wallet (user_id, credits) VALUES (%s, 5)
            ON DUPLICATE KEY UPDATE credits = credits + 5
        """, (teacher_id,))

        teach_desc_upfront = f"Confirmed '{topic}' session with learner {learner_id}"
        learn_desc_upfront = f"Confirmed '{topic}' session with teacher {teacher_id}"

        cur.execute("""
            INSERT INTO transactions(user_id,type,credits,description)
            VALUES(%s,'Earned',5,%s)
        """, (teacher_id, teach_desc_upfront))
        cur.execute("""
            INSERT INTO transactions(user_id,type,credits,description)
            VALUES(%s,'Spent',5,%s)
        """, (learner_id, learn_desc_upfront))

        cur.execute("UPDATE sessions SET status='Scheduled' WHERE id=%s", (sid,))
        cur.execute("""
            INSERT INTO notifications(user_id,message,link)
            VALUES(%s,%s,%s)
        """, (teacher_id, f"Your {topic} session is confirmed and scheduled.", "/sessions"))
        cur.execute("""
            INSERT INTO notifications(user_id,message,link)
            VALUES(%s,%s,%s)
        """, (learner_id, f"Your {topic} session is confirmed. 5 credits were deducted from your wallet.", "/wallet"))
        mysql.connection.commit()
        flash("Session confirmed and 5 credits debited from the learner wallet.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error during confirmation: {str(e)}", "danger")
        return redirect('/sessions')

    return redirect('/sessions')

@app.route('/cancel_session/<int:sid>', methods=['POST'])
@login_required
def cancel_session(sid):
    my_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cur.execute("SELECT * FROM sessions WHERE id=%s", (sid,))
    s = cur.fetchone()
    
    if not s or (s['learner_id'] != my_id and s['teacher_id'] != my_id) or s['status'] not in ['Pending Confirmation', 'Scheduled']:
        flash("Invalid cancellation.", "danger")
        return redirect('/sessions')
        
    if s['status'] == 'Scheduled':
        teacher_id = s['teacher_id']
        learner_id = s['learner_id']
        topic = s['topic']
        
        # Refund 5 credits to learner
        cur.execute("""
            INSERT INTO wallet (user_id, credits) VALUES (%s, 5)
            ON DUPLICATE KEY UPDATE credits = credits + 5
        """, (learner_id,))
        
        # Deduct 5 credits from teacher if possible
        cur.execute("""
            UPDATE wallet SET credits = credits - 5 WHERE user_id=%s AND credits >= 5
        """, (teacher_id,))
        
        teach_desc_refund = f"Cancelled '{topic}' session (Refunded 50%) with User {learner_id}"
        learn_desc_refund = f"Cancelled '{topic}' session (Refunded 50%) with User {teacher_id}"

        cur.execute("""
            INSERT INTO transactions(user_id,type,credits,description)
            VALUES(%s,'Spent',5,%s)
        """, (teacher_id, teach_desc_refund))
        cur.execute("""
            INSERT INTO transactions(user_id,type,credits,description)
            VALUES(%s,'Earned',5,%s)
        """, (learner_id, learn_desc_refund))

    cur.execute("UPDATE sessions SET status='Cancelled' WHERE id=%s", (sid,))
    cur.execute("""
        INSERT INTO notifications(user_id,message,link)
        VALUES(%s,%s,%s)
    """, (s['teacher_id'], f"The {s['topic'] or 'skill'} session request was cancelled.", "/sessions"))
    cur.execute("""
        INSERT INTO notifications(user_id,message,link)
        VALUES(%s,%s,%s)
    """, (s['learner_id'], f"The {s['topic'] or 'skill'} session request was cancelled.", "/sessions"))
    mysql.connection.commit()
    
    flash("Session cancelled.", "info")
    return redirect('/sessions')


# ─── Notifications ────────────────────────────────────────────────────────────

@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM notifications WHERE user_id=%s AND status='Unread'",
                    (session['user_id'],))
        count = cur.fetchone()[0]
        return dict(unread_notifications=count)
    return dict(unread_notifications=0)

@app.route('/notifications')
@login_required
def notifications():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT n.message, n.created_at, n.link,
               u.name AS sender_name, u.profile_pic
        FROM notifications n
        LEFT JOIN users u ON n.sender_id = u.user_id
        WHERE n.user_id=%s
        ORDER BY n.created_at DESC
    """, (session['user_id'],))
    notes = cur.fetchall()

    cur.execute("UPDATE notifications SET status='Read' WHERE user_id=%s",
                (session['user_id'],))
    mysql.connection.commit()

    return render_template('notifications.html', notifications=notes)

@app.route('/clear_notifications')
@login_required
def clear_notifications():
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM notifications WHERE user_id=%s", (session['user_id'],))
    mysql.connection.commit()
    return redirect('/notifications')

from flask import jsonify

@app.route('/check_notifications')
def check_notifications():

    if 'user_id' not in session:
        return jsonify({'count': 0})

    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT COUNT(*)
        FROM notifications
        WHERE user_id=%s
        AND status='Unread'
        """,
        (session['user_id'],)
    )

    count = cur.fetchone()[0]

    cur.close()

    return jsonify({'count': count})


# ─── Typing & Online Status ──────────────────────────────────────────────────

@app.route('/typing', methods=['POST'])
@login_required
def typing():
    cur = mysql.connection.cursor()
    cur.execute("REPLACE INTO typing_status(user_id, is_typing) VALUES(%s, %s)",
                (session['user_id'], True))
    mysql.connection.commit()
    return '', 204

@app.route('/stop_typing', methods=['POST'])
@login_required
def stop_typing():
    cur = mysql.connection.cursor()
    cur.execute("UPDATE typing_status SET is_typing=FALSE WHERE user_id=%s",
                (session['user_id'],))
    mysql.connection.commit()
    return '', 204

@app.route('/check_typing/<int:uid>')
def check_typing(uid):

    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT is_typing FROM typing_status WHERE user_id=%s",
        (uid,)
    )

    row = cur.fetchone()

    cur.close()

    return {
        'typing': bool(row and row[0])
    }

@app.before_request
def update_last_seen():

    if 'user_id' not in session:
        return

    last_update = session.get('last_seen_update', 0)

    if time() - last_update < 60:
        return

    try:
        cur = mysql.connection.cursor()

        cur.execute(
            "UPDATE users SET last_seen=NOW() WHERE user_id=%s",
            (session['user_id'],)
        )

        mysql.connection.commit()

        session['last_seen_update'] = time()

    except Exception as e:
        print(e)

@app.route('/check_online/<int:uid>')
def check_online(uid):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT TIMESTAMPDIFF(SECOND, last_seen, NOW()) < 15
        FROM users WHERE user_id=%s
    """, (uid,))
    online = cur.fetchone()[0]

    return {'online': bool(online)}


# ─── Wallet & Leaderboard ────────────────────────────────────────────────────

@app.route('/wallet')
@login_required
def wallet():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    credits = read_wallet_credits(cur, session['user_id'], default_credits=0)

    cur.execute("""
        SELECT * FROM transactions
        WHERE user_id=%s
        ORDER BY date DESC
    """, (session['user_id'],))
    transactions = cur.fetchall()

    return render_template('wallet.html',
                           credits=credits,
                           transactions=transactions)

@app.route('/leaderboard')
def leaderboard():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT u.user_id, u.name, u.profile_pic, 
               AVG(r.rating) as avg_rating,
               (SELECT COUNT(*) FROM sessions s WHERE (s.teacher_id = u.user_id OR s.learner_id = u.user_id) AND s.status='Completed') as total_sessions
        FROM users u
        LEFT JOIN ratings r ON u.user_id = r.rated_user_id
        GROUP BY u.user_id
        HAVING total_sessions > 0 OR avg_rating IS NOT NULL
        ORDER BY avg_rating DESC, total_sessions DESC
    """)
    users = cur.fetchall()
    return render_template('leaderboard.html', users=users)


# ─── Chat & Messages ─────────────────────────────────────────────────────────

@app.route('/messages')
@login_required
def messages_page():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    my_id = session['user_id']

    # Get conversations with last message preview and unread count
    cur.execute("""
        SELECT u.user_id, u.name, u.profile_pic,
               (SELECT message FROM chat 
                WHERE (sender_id=u.user_id AND receiver_id=%s) 
                   OR (sender_id=%s AND receiver_id=u.user_id) 
                ORDER BY id DESC LIMIT 1) AS last_message,
               (SELECT time FROM chat 
                WHERE (sender_id=u.user_id AND receiver_id=%s) 
                   OR (sender_id=%s AND receiver_id=u.user_id) 
                ORDER BY id DESC LIMIT 1) AS last_time,
               (SELECT COUNT(*) FROM chat 
                WHERE sender_id=u.user_id AND receiver_id=%s AND seen=0) AS unread_count,
               TIMESTAMPDIFF(SECOND, u.last_seen, NOW()) < 15 AS is_online
        FROM users u
        WHERE u.user_id IN (
            SELECT DISTINCT CASE 
                WHEN sender_id = %s THEN receiver_id 
                ELSE sender_id 
            END as peer_id
            FROM chat 
            WHERE sender_id = %s OR receiver_id = %s
        )
        ORDER BY last_time DESC
    """, (my_id, my_id, my_id, my_id, my_id, my_id, my_id, my_id))

    users = cur.fetchall()
    return render_template('messages.html', users=users)

@app.route('/chat/<int:uid>', methods=['GET', 'POST'])
@login_required
def chat(uid):
    current_user = session['user_id']

    # 📩 SEND MESSAGE / FILE
    if request.method == 'POST':
        msg = request.form.get('msg')
        file = request.files.get('file')
        reply_to = request.form.get('reply_to')
        filename = None

        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file.save(os.path.join('static/chat_files', filename))

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO chat(sender_id, receiver_id, message, file)
            VALUES(%s, %s, %s, %s)
        """, (current_user, uid, msg, filename))
        mysql.connection.commit()

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # 📨 FETCH MESSAGES
    cur.execute("""
        SELECT c.id, c.sender_id, c.message, c.file, c.seen, c.time,
               c.starred, c.pinned, c.reaction,
               u.name AS sender_name, u.profile_pic
        FROM chat c
        JOIN users u ON c.sender_id = u.user_id
        WHERE (c.sender_id=%s AND c.receiver_id=%s)
           OR (c.sender_id=%s AND c.receiver_id=%s)
        ORDER BY c.id ASC
    """, (current_user, uid, uid, current_user))
    messages = cur.fetchall()

    # 👁 MARK RECEIVED MESSAGES AS SEEN
    cur.execute("""
        UPDATE chat SET seen=TRUE
        WHERE receiver_id=%s AND sender_id=%s
    """, (current_user, uid))
    mysql.connection.commit()

    # 👤 GET OTHER USER INFO (for header)
    cur.execute("SELECT name, profile_pic FROM users WHERE user_id=%s", (uid,))
    other_user = cur.fetchone()

    return render_template(
        'chat.html',
        messages=messages,
        uid=uid,
        other_user_name=other_user['name'],
        other_user_pic=other_user['profile_pic']
    )


@app.route('/delete_message/<int:mid>')
@login_required
def delete_message(mid):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM chat WHERE id=%s AND sender_id=%s",
                (mid, session['user_id']))
    mysql.connection.commit()
    return redirect(request.referrer)

@app.route('/clear_chat/<int:uid>')
@login_required
def clear_chat(uid):
    cur = mysql.connection.cursor()
    cur.execute("""
        DELETE FROM chat
        WHERE (sender_id=%s AND receiver_id=%s)
           OR (sender_id=%s AND receiver_id=%s)
    """, (session['user_id'], uid, uid, session['user_id']))
    mysql.connection.commit()
    return redirect(f'/chat/{uid}')

@app.route('/block_user/<int:uid>')
@login_required
def block_user(uid):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO blocked_users VALUES(%s,%s)", (session['user_id'], uid))
    mysql.connection.commit()
    return redirect('/messages')

@app.route('/report_user/<int:uid>')
@login_required
def report_user(uid):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO reports(reporter_id, reported_id) VALUES(%s,%s)",
                (session['user_id'], uid))
    mysql.connection.commit()
    return redirect('/chat/' + str(uid))

@app.route('/delete_messages', methods=['POST'])
@login_required
def delete_messages():
    ids = request.get_json()['ids']
    cur = mysql.connection.cursor()
    format_strings = ','.join(['%s'] * len(ids))
    cur.execute(f"DELETE FROM chat WHERE id IN ({format_strings}) AND sender_id=%s",
                (*ids, session['user_id']))
    mysql.connection.commit()
    return '', 204

@app.route('/star_message/<int:mid>')
@login_required
def star_message(mid):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE chat SET starred=TRUE WHERE id=%s", (mid,))
    mysql.connection.commit()
    return '', 204

@app.route('/pin_message/<int:mid>')
@login_required
def pin_message(mid):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE chat SET pinned=TRUE WHERE id=%s", (mid,))
    mysql.connection.commit()
    return '', 204

@app.route('/react_message/<int:mid>/<emoji>')
@login_required
def react_message(mid, emoji):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE chat SET reaction=%s WHERE id=%s", (emoji, mid))
    mysql.connection.commit()
    return '', 204


# ─── REST APIs ────────────────────────────────────────────────────────────────

# --- Users API ---

@app.route('/api/users', methods=['GET'])
def api_get_users():
    """List all users (admin only)"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT user_id, name, email, profile_pic, location, skill_level, bio FROM users")
    users = cur.fetchall()
    return jsonify({'users': users}), 200

@app.route('/api/users/<int:uid>', methods=['GET'])
def api_get_user(uid):
    """Get user profile with skills"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT user_id, name, email, profile_pic, location, skill_level, bio, language, timezone FROM users WHERE user_id=%s", (uid,))
    user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    cur.execute("SELECT skill_name FROM skills_offered WHERE user_id=%s", (uid,))
    user['skills_offered'] = [r['skill_name'] for r in cur.fetchall()]

    cur.execute("SELECT skill_name FROM skills_wanted WHERE user_id=%s", (uid,))
    user['skills_wanted'] = [r['skill_name'] for r in cur.fetchall()]

    return jsonify({'user': user}), 200

@app.route('/api/users/<int:uid>', methods=['PUT'])
def api_update_user(uid):
    """Update user profile"""
    if 'user_id' not in session or session['user_id'] != uid:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    allowed = ['name', 'email', 'bio', 'location', 'language', 'timezone', 'skill_level']
    updates = []
    values = []
    for field in allowed:
        if field in data:
            updates.append(f"{field}=%s")
            values.append(data[field])

    if not updates:
        return jsonify({'error': 'No valid fields to update'}), 400

    values.append(uid)
    cur = mysql.connection.cursor()
    cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE user_id=%s", tuple(values))
    mysql.connection.commit()

    return jsonify({'message': 'Profile updated'}), 200


# --- Skills API ---

# All predefined skills (used for suggestions and API)
PREDEFINED_SKILLS = [
    "Web Development (HTML, CSS, JavaScript)", "Backend Development (Flask / Node.js)",
    "Python Programming", "Java Programming", "C / C++",
    "Data Structures & Algorithms", "Database Management (MySQL)",
    "Mobile App Development", "API Development", "Git & Version Control",
    "Graphic Design", "UI/UX Design", "Logo Design", "Video Editing",
    "Photo Editing", "Animation (2D/3D)", "Canva Design",
    "Digital Marketing", "Social Media Management",
    "SEO (Search Engine Optimization)", "Content Writing", "Copywriting",
    "Email Marketing", "Affiliate Marketing",
    "Mathematics", "Physics", "Chemistry", "Biology", "English Speaking",
    "Exam Preparation (JEE/NEET)", "Assignment Help",
    "Hindi Speaking", "Spanish Basics", "French Basics", "Public Speaking",
    "Guitar", "Piano", "Singing", "Music Production", "Drawing", "Sketching",
    "Communication Skills", "Time Management", "Interview Preparation",
    "Resume Building", "Personality Development",
    "Cooking", "Photography", "Video Shooting", "Fitness Training",
    "Yoga", "Basic First Aid"
]

@app.route('/api/skills')
def api_skills():
    """Return JSON list of all unique skills (predefined + user-added)"""
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get all offered and wanted skills from DB
    cur.execute("""
        SELECT DISTINCT skill_name FROM skills_offered
        UNION
        SELECT DISTINCT skill_name FROM skills_wanted
        ORDER BY skill_name ASC
    """)
    db_skills = [row['skill_name'] for row in cur.fetchall()]
    
    # Merge predefined + DB skills
    all_skills = sorted(set(PREDEFINED_SKILLS + db_skills))
    return jsonify({'skills': all_skills})

@app.route('/api/skills', methods=['POST'])
def api_add_skill():
    """Add offered/wanted skill"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    uid = session['user_id']
    cur = mysql.connection.cursor()

    offer = data.get('offer', '').strip().title()
    want = data.get('want', '').strip().title()

    added = []
    if offer:
        cur.execute("SELECT * FROM skills_offered WHERE user_id=%s AND skill_name=%s", (uid, offer))
        if not cur.fetchone():
            cur.execute("INSERT INTO skills_offered(user_id,skill_name) VALUES(%s,%s)", (uid, offer))
            added.append({'type': 'offered', 'skill': offer})

    if want:
        cur.execute("SELECT * FROM skills_wanted WHERE user_id=%s AND skill_name=%s", (uid, want))
        if not cur.fetchone():
            cur.execute("INSERT INTO skills_wanted(user_id,skill_name) VALUES(%s,%s)", (uid, want))
            added.append({'type': 'wanted', 'skill': want})

    mysql.connection.commit()
    return jsonify({'message': 'Skills added', 'added': added}), 201

@app.route('/api/skills/<skill_type>/<skill_name>', methods=['DELETE'])
def api_delete_skill(skill_type, skill_name):
    """Remove a skill (skill_type: offered or wanted)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    uid = session['user_id']
    cur = mysql.connection.cursor()

    if skill_type == 'offered':
        cur.execute("DELETE FROM skills_offered WHERE user_id=%s AND skill_name=%s", (uid, skill_name))
    elif skill_type == 'wanted':
        cur.execute("DELETE FROM skills_wanted WHERE user_id=%s AND skill_name=%s", (uid, skill_name))
    else:
        return jsonify({'error': 'Invalid skill type. Use offered or wanted'}), 400

    mysql.connection.commit()
    return jsonify({'message': f'Skill "{skill_name}" removed'}), 200


# --- Requests API ---

@app.route('/api/requests', methods=['GET'])
def api_get_requests():
    """Get all swap requests for user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT sr.id, sr.sender_id, sr.receiver_id, sr.status, u.name AS sender_name
        FROM swap_requests sr
        JOIN users u ON sr.sender_id = u.user_id
        WHERE sr.receiver_id=%s
        ORDER BY sr.id DESC
    """, (uid,))
    received = cur.fetchall()

    cur.execute("""
        SELECT sr.id, sr.sender_id, sr.receiver_id, sr.status, u.name AS receiver_name
        FROM swap_requests sr
        JOIN users u ON sr.receiver_id = u.user_id
        WHERE sr.sender_id=%s
        ORDER BY sr.id DESC
    """, (uid,))
    sent = cur.fetchall()

    return jsonify({'received': received, 'sent': sent}), 200

@app.route('/api/requests', methods=['POST'])
def api_send_request():
    """Send a swap request"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data or 'receiver_id' not in data:
        return jsonify({'error': 'receiver_id required'}), 400

    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    skill = data.get('skill', '')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check duplicates (per user + per skill)
    cur.execute("""
        SELECT * FROM swap_requests 
        WHERE ((sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s))
        AND skill=%s AND status='Pending'
    """, (sender_id, receiver_id, receiver_id, sender_id, skill))

    if cur.fetchone():
        return jsonify({'error': 'Request for this skill already exists'}), 409

    cur.execute("INSERT INTO swap_requests(sender_id, receiver_id, skill) VALUES(%s, %s, %s)", (sender_id, receiver_id, skill))
    mysql.connection.commit()

    return jsonify({'message': 'Request sent', 'id': cur.lastrowid}), 201

@app.route('/api/requests/<int:req_id>', methods=['PUT'])
def api_update_request(req_id):
    """Accept or reject a request"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data or 'action' not in data:
        return jsonify({'error': 'action required (accept/reject)'}), 400

    action = data['action']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT * FROM swap_requests WHERE id=%s", (req_id,))
    req = cur.fetchone()

    if not req or req['receiver_id'] != session['user_id']:
        return jsonify({'error': 'Request not found or unauthorized'}), 404

    if action == 'accept':
        cur.execute("UPDATE swap_requests SET status='Accepted' WHERE id=%s", (req_id,))
        s_id, r_id = req['sender_id'], req['receiver_id']
        cur.execute("INSERT IGNORE INTO connections(user1_id, user2_id) VALUES(%s, %s)",
                    (min(s_id, r_id), max(s_id, r_id)))
    elif action == 'reject':
        cur.execute("UPDATE swap_requests SET status='Rejected' WHERE id=%s", (req_id,))
    else:
        return jsonify({'error': 'Invalid action'}), 400

    mysql.connection.commit()
    return jsonify({'message': f'Request {action}ed'}), 200


# --- Messages API ---

@app.route('/api/conversations', methods=['GET'])
def api_get_conversations():
    """List all conversations for the current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    my_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT u.user_id, u.name, u.profile_pic,
               (SELECT message FROM chat 
                WHERE (sender_id=u.user_id AND receiver_id=%s) 
                   OR (sender_id=%s AND receiver_id=u.user_id) 
                ORDER BY id DESC LIMIT 1) AS last_message,
               (SELECT COUNT(*) FROM chat 
                WHERE sender_id=u.user_id AND receiver_id=%s AND seen=0) AS unread_count
        FROM users u
        WHERE u.user_id IN (
            SELECT DISTINCT CASE 
                WHEN sender_id = %s THEN receiver_id 
                ELSE sender_id 
            END as peer_id
            FROM chat 
            WHERE sender_id = %s OR receiver_id = %s
        )
    """, (my_id, my_id, my_id, my_id, my_id, my_id))

    conversations = cur.fetchall()
    return jsonify({'conversations': conversations}), 200

@app.route('/api/messages/<int:uid>', methods=['GET'])
def api_get_messages(uid):
    """Get chat messages with a user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    my_id = session['user_id']
    after = request.args.get('after', 0, type=int)

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if after > 0:
        # Polling: only get new messages after a specific ID
        cur.execute("""
            SELECT c.id, c.sender_id, c.message, c.file, c.seen, c.time,
                   c.starred, c.pinned, c.reaction,
                   u.name AS sender_name, u.profile_pic
            FROM chat c
            JOIN users u ON c.sender_id = u.user_id
            WHERE ((c.sender_id=%s AND c.receiver_id=%s) OR (c.sender_id=%s AND c.receiver_id=%s))
              AND c.id > %s
            ORDER BY c.id ASC
        """, (my_id, uid, uid, my_id, after))
    else:
        cur.execute("""
            SELECT c.id, c.sender_id, c.message, c.file, c.seen, c.time,
                   c.starred, c.pinned, c.reaction,
                   u.name AS sender_name, u.profile_pic
            FROM chat c
            JOIN users u ON c.sender_id = u.user_id
            WHERE (c.sender_id=%s AND c.receiver_id=%s) OR (c.sender_id=%s AND c.receiver_id=%s)
            ORDER BY c.id ASC
        """, (my_id, uid, uid, my_id))

    messages = cur.fetchall()

    # Convert time objects to strings
   for m in messages:
    if m['time']:
        m['time'] = (
            m['time'] + timedelta(hours=5, minutes=30)
        ).strftime('%I:%M %p')

    # Mark as seen
    cur.execute("UPDATE chat SET seen=TRUE WHERE receiver_id=%s AND sender_id=%s", (my_id, uid))
    mysql.connection.commit()

    return jsonify({'messages': messages, 'my_id': my_id}), 200

@app.route('/api/messages/<int:uid>', methods=['POST'])
def api_send_message(uid):
    """Send a message via AJAX"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    my_id = session['user_id']
    msg = request.form.get('msg', '')
    file = request.files.get('file')
    filename = None

    if file and file.filename != "":
        filename = secure_filename(file.filename)
        file.save(os.path.join('static/chat_files', filename))

    if not msg and not filename:
        return jsonify({'error': 'Empty message'}), 400

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO chat(sender_id, receiver_id, message, file)
        VALUES(%s, %s, %s, %s)
    """, (my_id, uid, msg, filename))
    mysql.connection.commit()

    return jsonify({'message': 'Sent', 'id': cur.lastrowid}), 201

@app.route('/api/messages/<int:mid>', methods=['DELETE'])
def api_delete_message(mid):
    """Delete a message"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM chat WHERE id=%s AND sender_id=%s", (mid, session['user_id']))
    mysql.connection.commit()
    return jsonify({'message': 'Deleted'}), 200


# ─── Mail Config ─────────────────────────────────────────────────────────────
from flask_mail import Message as MailMessage


# ─── Embedded Meeting Room ───────────────────────────────────────────────────

@app.route('/meeting/<int:sid>')
@login_required
def meeting_room(sid):
    """Render embedded Jitsi meeting inside the app"""
    uid = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT s.*, 
               u_teacher.name as teacher_name,
               u_learner.name as learner_name
        FROM sessions s
        LEFT JOIN users u_teacher ON s.teacher_id = u_teacher.user_id
        LEFT JOIN users u_learner ON s.learner_id = u_learner.user_id
        WHERE s.id=%s AND (s.teacher_id=%s OR s.learner_id=%s)
    """, (sid, uid, uid))
    s = cur.fetchone()

    if not s:
        flash('Session not found.', 'danger')
        return redirect('/sessions')

    peer_name = s['learner_name'] if s['teacher_id'] == uid else s['teacher_name']
    my_role = 'Teaching' if s['teacher_id'] == uid else 'Learning'
    # Extract Jitsi room name from the meet_link
    room_name = s['meet_link'].replace('https://meet.jit.si/', '') if s['meet_link'] else f'skillbridge_{sid}'
    user_name = session.get('name', 'User')

    return render_template('meeting.html',
                           session_info=s,
                           peer_name=peer_name,
                           my_role=my_role,
                           room_name=room_name,
                           user_name=user_name,
                           session_id=sid)


# ─── Email Reminder Scheduler ────────────────────────────────────────────────

def send_session_reminders():
    """Background thread that checks for sessions starting in ~30 minutes and sends email reminders"""
    while True:
        try:
            with app.app_context():
                cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                # Find sessions starting within 25-35 minutes that haven't had a reminder sent
                cur.execute("""
                    SELECT s.id, s.session_date, s.topic, s.meet_link,
                           s.teacher_id, s.learner_id,
                           ut.name AS teacher_name, ut.email AS teacher_email,
                           ul.name AS learner_name, ul.email AS learner_email
                    FROM sessions s
                    JOIN users ut ON s.teacher_id = ut.user_id
                    JOIN users ul ON s.learner_id = ul.user_id
                    WHERE s.status = 'Scheduled'
                    AND s.reminder_sent = FALSE
                    AND s.session_date BETWEEN NOW() + INTERVAL 25 MINUTE AND NOW() + INTERVAL 35 MINUTE
                """)
                upcoming = cur.fetchall()

                for sess in upcoming:
                    topic = sess['topic'] or 'General Session'
                    session_time = sess['session_date'].strftime('%B %d, %Y at %I:%M %p')
                    session_id = sess['id']

                    # Send to both teacher and learner
                    for role, name, email in [
                        ('Teacher', sess['teacher_name'], sess['teacher_email']),
                        ('Learner', sess['learner_name'], sess['learner_email'])
                    ]:
                        try:
                            msg = MailMessage(
                                subject=f'Reminder: Your SkillBridge session starts in 30 minutes!',
                                sender=app.config['MAIL_USERNAME'],
                                recipients=[email]
                            )
                            msg.html = f"""
                            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; border-radius: 16px; overflow: hidden; border: 1px solid #e2e8f0;">
                                <div style="background: linear-gradient(135deg, #4f46e5, #6366f1); padding: 2rem; text-align: center;">
                                    <h1 style="color: white; margin: 0; font-size: 1.5rem;">SkillBridge Session Reminder</h1>
                                </div>
                                <div style="padding: 2rem;">
                                    <p style="font-size: 1.1rem; color: #1e293b;">Hi <b>{name}</b>,</p>
                                    <p style="color: #475569;">Your session is starting in <b style="color: #4f46e5;">30 minutes</b>!</p>
                                    <div style="background: white; border-radius: 12px; padding: 1.5rem; margin: 1.5rem 0; border: 1px solid #e2e8f0;">
                                        <p style="margin: 0.5rem 0;"><b>Topic:</b> {topic}</p>
                                        <p style="margin: 0.5rem 0;"><b>Time:</b> {session_time}</p>
                                        <p style="margin: 0.5rem 0;"><b>Your Role:</b> {role}</p>
                                    </div>
                                    <div style="text-align: center; margin-top: 1.5rem;">
                                        <a href="{sess['meet_link']}" style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #6366f1); color: white; padding: 0.75rem 2rem; border-radius: 2rem; text-decoration: none; font-weight: 600;">Join Meeting</a>
                                    </div>
                                    <p style="color: #94a3b8; font-size: 0.85rem; margin-top: 1.5rem; text-align: center;">Good luck with your session!</p>
                                </div>
                            </div>
                            """
                            mail.send(msg)
                            print(f'[REMINDER] Email sent to {email} for session {session_id}')
                        except Exception as e:
                            print(f'[REMINDER ERROR] Failed to send to {email}: {e}')

                    # Mark reminder as sent
                    cur.execute("UPDATE sessions SET reminder_sent=TRUE WHERE id=%s", (session_id,))

                    # Also send in-app notification
                    for uid_notify in [sess['teacher_id'], sess['learner_id']]:
                        cur.execute("""
                            INSERT INTO notifications(user_id, message, link)
                            VALUES(%s, %s, %s)
                        """, (uid_notify,
                              f"Reminder: Your '{topic}' session starts in 30 minutes!",
                              sess['meet_link']))

                mysql.connection.commit()

        except Exception as e:
            print(f'[SCHEDULER ERROR] {e}')

        time_module.sleep(60)  # Check every 60 seconds


def cleanup_replied_messages_worker():
    """Background task that purges replied admin messages after 48 hours."""
    while True:
        try:
            with app.app_context():
                deleted = cleanup_expired_replied_messages()
                if deleted:
                    print(f'[ADMIN CLEANUP] Deleted {deleted} replied contact message(s).')
        except Exception as e:
            print(f'[ADMIN CLEANUP ERROR] {e}')

        time_module.sleep(3600)  # Check every hour


if __name__ == '__main__':
    with app.app_context():
        ensure_total_user_metric()
        ensure_contact_messages_reply_tracking()
        cleanup_expired_replied_messages()

    # Start background reminder thread
    reminder_thread = threading.Thread(target=send_session_reminders, daemon=True)
    reminder_thread.start()
    cleanup_thread = threading.Thread(target=cleanup_replied_messages_worker, daemon=True)
    cleanup_thread.start()
    print('[SCHEDULER] Email reminder service started.')
    app.run(host='0.0.0.0', debug=True, use_reloader=False)
