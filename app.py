import os
import io
import base64
import csv
import pyotp
import qrcode
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# ==========================================
# CONFIGURATION
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mfatrainer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==========================================
# TRANSLATIONS & DICTIONARY
# ==========================================
TRANSLATIONS = {
    'en': {
        'title': 'MFAurora',
        'login': 'Login',
        'register': 'Register',
        'logout': 'Logout',
        'dashboard': 'Dashboard',
        'training': 'Training Lab',
        'admin': 'Admin',
        'welcome': 'Secure identity. Understand MFA.',
        'start': 'Get started',
        'quiz': 'Tests',
        'theme': 'Theme',
        'lang': 'Language',
        'footer': 'MFA vulnerability training platform'
    },
    'ru': {
        'title': 'MFAurora',
        'login': 'Вход',
        'register': 'Регистрация',
        'logout': 'Выход',
        'dashboard': 'Личный кабинет',
        'training': 'Тренажёр',
        'admin': 'Админ',
        'welcome': 'Защити учётные записи. Изучи MFA.',
        'start': 'Начать',
        'quiz': 'Тесты',
        'theme': 'Тема',
        'lang': 'Язык',
        'footer': 'Платформа обучения уязвимостям MFA'
    }
}

# ==========================================
# DATABASE MODELS
# ==========================================
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_mfa_enabled = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    mfa_secret = db.relationship('MFASecret', backref='user', uselist=False)
    results = db.relationship('TrainingResult', backref='user', lazy=True)

class MFASecret(db.Model):
    __tablename__ = 'mfa_secrets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    secret = db.Column(db.String(32), nullable=False)

class AttackScenario(db.Model):
    __tablename__ = 'attack_scenarios'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500))
    difficulty = db.Column(db.String(20), default='MEDIUM')  # EASY, MEDIUM, HARD
    points = db.Column(db.Integer, default=100)

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    attempt_type = db.Column(db.String(20), default='login')  # login, mfa

class SessionLog(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TrainingResult(db.Model):
    __tablename__ = 'training_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scenario_id = db.Column(db.Integer, db.ForeignKey('attack_scenarios.id'), nullable=True)
    scenario_name = db.Column(db.String(80), nullable=False)
    success = db.Column(db.Boolean, default=False)
    time_taken = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    feedback = db.Column(db.String(500), nullable=True)

# ==========================================
# HELPERS & CONTEXT PROCESSORS
# ==========================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    g.lang = session.get('lang', 'ru')
    g.theme = session.get('theme', 'dark')

@app.context_processor
def inject_conf():
    def get_text(key):
        return TRANSLATIONS.get(g.lang, TRANSLATIONS['ru']).get(key, key)
    return dict(get_text=get_text, lang=g.lang, theme=g.theme)

def get_b64encoded_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black" if g.theme == 'light' else "white", 
                        back_color="white" if g.theme == 'light' else "#343a40")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

def _ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '')[:45] or '0.0.0.0'

def _log_login_attempt(user_id, success, attempt_type='login'):
    try:
        db.session.add(LoginAttempt(user_id=user_id, ip_address=_ip(), success=success, attempt_type=attempt_type))
        db.session.commit()
    except Exception:
        db.session.rollback()

def _log_session(user_id):
    try:
        db.session.add(SessionLog(user_id=user_id, ip_address=_ip()))
        db.session.commit()
    except Exception:
        db.session.rollback()

# ==========================================
# ROUTES: GENERAL
# ==========================================
@app.route('/set_lang/<lang_code>')
def set_lang(lang_code):
    if lang_code in ['ru', 'en']:
        session['lang'] = lang_code
    return redirect(request.referrer or url_for('index'))

@app.route('/set_theme/<theme_mode>')
def set_theme(theme_mode):
    if theme_mode in ['light', 'dark']:
        session['theme'] = theme_mode
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('trainer_list'))
    return render_template('index.html')

# ==========================================
# ROUTES: AUTH
# ==========================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        if len(password) < 8:
            flash('Пароль не менее 8 символов / Password at least 8 characters', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует / User exists', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email уже используется / Email already used', 'danger')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_pw)
        if User.query.count() == 0:
            new_user.is_admin = True
        db.session.add(new_user)
        db.session.commit()
        flash('OK. Login now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            _log_login_attempt(user.id, True, 'login')
            if user.is_mfa_enabled:
                session['pre_2fa_user_id'] = user.id
                return redirect(url_for('login_2fa'))
            _log_session(user.id)
            login_user(user)
            return redirect(url_for('dashboard'))
        _log_login_attempt(user.id if user else None, False, 'login')
        flash('Error credentials', 'danger')
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id: return redirect(url_for('login'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        if pyotp.TOTP(user.mfa_secret.secret).verify(request.form.get('code')):
            _log_login_attempt(user.id, True, 'mfa')
            _log_session(user.id)
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            return redirect(url_for('dashboard'))
        _log_login_attempt(user.id, False, 'mfa')
        flash('Invalid code', 'danger')
    return render_template('login_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ==========================================
# ROUTES: DASHBOARD & MFA
# ==========================================
@app.route('/dashboard')
@login_required
def dashboard():
    all_res = TrainingResult.query.filter_by(user_id=current_user.id).all()
    total = len(all_res)
    successful = sum(1 for r in all_res if r.success)
    success_rate = round(successful * 100.0 / total, 1) if total else 0
    results = TrainingResult.query.filter_by(user_id=current_user.id).order_by(TrainingResult.timestamp.desc()).limit(50).all()
    return render_template('dashboard.html', results=results, total=total, successful=successful, success_rate=success_rate)

@app.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    if current_user.is_mfa_enabled: return redirect(url_for('dashboard'))
    if 'mfa_temp_secret' not in session: session['mfa_temp_secret'] = pyotp.random_base32()
    secret = session['mfa_temp_secret']
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="MFAurora")
    qr_b64 = get_b64encoded_qr_image(totp_uri)
    
    if request.method == 'POST':
        if pyotp.TOTP(secret).verify(request.form.get('code')):
            db.session.add(MFASecret(user_id=current_user.id, secret=secret))
            current_user.is_mfa_enabled = True
            db.session.commit()
            session.pop('mfa_temp_secret', None)
            return redirect(url_for('dashboard'))
        flash('Invalid Code', 'danger')
    return render_template('mfa_setup.html', qr_b64=qr_b64, secret=secret)

# ==========================================
# ROUTES: TRAINING & QUIZ
# ==========================================
def _scenarios():
    rows = AttackScenario.query.order_by(AttackScenario.id).all()
    if rows:
        return [{'id': s.id, 'name': s.name, 'difficulty': s.difficulty, 'desc_ru': s.description or '', 'desc_en': s.description or '', 'points': s.points} for s in rows]
    return [
        {'id': 1, 'name': 'QR Phishing', 'difficulty': 'MEDIUM', 'desc_ru': 'Фишинг через подмену QR-кода', 'desc_en': 'QR Code spoofing', 'points': 100},
        {'id': 2, 'name': 'Brute Force', 'difficulty': 'EASY', 'desc_ru': 'Подбор паролей перебором', 'desc_en': 'Password guessing', 'points': 80},
        {'id': 3, 'name': 'Timing Attack', 'difficulty': 'HARD', 'desc_ru': 'Анализ времени верификации', 'desc_en': 'Verification timing analysis', 'points': 150},
        {'id': 4, 'name': 'Session Hijacking', 'difficulty': 'HARD', 'desc_ru': 'Захват сессии через XSS', 'desc_en': 'Session capture via XSS', 'points': 150},
        {'id': 5, 'name': 'Rate Limiting Bypass', 'difficulty': 'MEDIUM', 'desc_ru': 'Обход ограничения попыток', 'desc_en': 'Bypass rate limiting', 'points': 120},
    ]

@app.route('/trainer')
@login_required
def trainer_list():
    scenarios = _scenarios()
    return render_template('trainer_list.html', scenarios=scenarios)

@app.route('/trainer/lecture/<int:scenario_id>')
@login_required
def lecture(scenario_id):
    from lecture_data import LECTURES
    data = LECTURES.get(scenario_id)
    if not data:
        return "Not Found", 404
    title = data["name_ru"] if g.lang == "ru" else data["name_en"]
    blocks = data["blocks_ru"] if g.lang == "ru" else data["blocks_en"]
    return render_template("lecture.html", scenario_id=scenario_id, title=title, blocks=blocks)

def _save_result(scenario_id, scenario_name, success, time_taken=None, feedback=None):
    r = TrainingResult(user_id=current_user.id, scenario_id=scenario_id, scenario_name=scenario_name, success=success, time_taken=time_taken, feedback=feedback)
    db.session.add(r)
    db.session.commit()

@app.route('/trainer/sim/<int:sim_id>', methods=['GET', 'POST'])
@login_required
def trainer_sim(sim_id):
    time_taken = None
    raw = request.form.get('time_taken')
    if raw is not None:
        try:
            time_taken = float(raw)
        except (TypeError, ValueError):
            pass

    # 1: QR Phishing
    if sim_id == 1:
        if request.method == 'POST':
            success = request.form.get('choice') == 'report'
            fb = 'Report phishing' if success else 'Scanned fake QR'
            _save_result(1, 'QR Phishing', success, time_taken, fb)
            flash('Correct!' if success else 'Failed!', 'success' if success else 'danger')
            return redirect(url_for('dashboard'))
        return render_template('sim_phishing.html', sim_id=1)

    # 2: Brute Force
    if sim_id == 2:
        target_pass = "12345"
        if request.method == 'POST':
            attempt = request.form.get('password', '').strip()
            if attempt == target_pass:
                _save_result(2, 'Brute Force', True, time_taken, 'Guessed weak password')
                flash('Hacked successfully (Simulation passed)!', 'success')
                return redirect(url_for('dashboard'))
            _save_result(2, 'Brute Force', False, time_taken, 'Wrong password')
            flash('Incorrect password. Try a simpler one.', 'warning')
        return render_template('sim_bruteforce.html', sim_id=2)

    # 3: Timing Attack
    if sim_id == 3:
        if request.method == 'POST':
            # User must identify that early-exit on first wrong char = timing leak
            success = request.form.get('choice') == 'timing'
            _save_result(3, 'Timing Attack', success, time_taken, 'Timing leak detection' if success else 'Wrong choice')
            flash('Correct! Timing leaks can reveal valid prefixes.' if success else 'Wrong. Study timing attacks.', 'success' if success else 'danger')
            return redirect(url_for('dashboard'))
        return render_template('sim_timing.html', sim_id=3)

    # 4: Session Hijacking
    if sim_id == 4:
        if request.method == 'POST':
            success = request.form.get('choice') == 'invalid'
            _save_result(4, 'Session Hijacking', success, time_taken, 'Detected stolen token' if success else 'Accepted stolen token')
            flash('Correct! Never trust client-supplied tokens.' if success else 'Danger! That token was stolen.', 'success' if success else 'danger')
            return redirect(url_for('dashboard'))
        return render_template('sim_session.html', sim_id=4)

    # 5: Rate Limiting Bypass
    if sim_id == 5:
        if request.method == 'POST':
            # Simulate: multiple IPs or distributed attempt
            success = request.form.get('choice') == 'report'
            _save_result(5, 'Rate Limiting Bypass', success, time_taken, 'Reported bypass attempt' if success else 'Tried bypass')
            flash('Correct! Rate limit bypass is an attack.' if success else 'Rate limit bypass is an MFA bypass method.', 'success' if success else 'danger')
            return redirect(url_for('dashboard'))
        return render_template('sim_ratelimit.html', sim_id=5)

    return "Not Found", 404

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    from quiz_data import get_theory, get_practical, THEORY, PRACTICAL
    attack_id = request.args.get('attack') or request.form.get('attack')
    try:
        attack_id = int(attack_id) if attack_id else 0
    except (TypeError, ValueError):
        attack_id = 0
    theory = get_theory(attack_id)
    practical = get_practical(attack_id)
    scenarios = _scenarios()
    if request.method == 'POST':
        total, correct = 0, 0
        for q in theory + practical:
            ans = request.form.get(f'q_{q["id"]}')
            if ans is not None:
                total += 1
                if int(ans) == q['correct']:
                    correct += 1
        msg = f"Тесты: {correct}/{total}" if g.lang == 'ru' else f"Score: {correct}/{total}"
        flash(msg, 'info')
        return redirect(url_for('dashboard'))
    return render_template('quiz.html', theory=theory, practical=practical, scenarios=scenarios, attack_id=attack_id)

# ==========================================
# ROUTES: ADMIN
# ==========================================
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin: return "Access Denied", 403
    users = User.query.all()
    users_count = len(users)
    mfa_count = sum(1 for u in users if u.is_mfa_enabled)
    results = TrainingResult.query.order_by(TrainingResult.timestamp.desc()).limit(50).all()
    return render_template('admin_dashboard.html', users=users, users_count=users_count, mfa_count=mfa_count, results=results)

@app.route('/admin/db')
@login_required
def admin_db_view():
    if not current_user.is_admin: return "Access Denied", 403
    all_users = User.query.all()
    all_results = TrainingResult.query.all()
    return render_template('admin_db.html', users=all_users, results=all_results)

@app.route('/admin/export/csv')
@login_required
def admin_export_csv():
    if not current_user.is_admin:
        return "Access Denied", 403
    rows = TrainingResult.query.order_by(TrainingResult.timestamp.desc()).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['id', 'user_id', 'scenario_id', 'scenario_name', 'success', 'time_taken', 'timestamp', 'feedback'])
    for r in rows:
        w.writerow([r.id, r.user_id, r.scenario_id, r.scenario_name, r.success, r.time_taken, r.timestamp.isoformat() if r.timestamp else '', r.feedback or ''])
    buf.seek(0)
    fn = f"mfaurora_training_{datetime.utcnow().strftime('%Y-%m-%d')}.csv"
    return Response(buf.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{fn}"'})

@app.route('/admin/add_admin', methods=['POST'])
@login_required
def admin_add_admin():
    if not current_user.is_admin: return "Access Denied", 403
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        flash(f'User {username} is now Admin', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_dashboard'))

# ==========================================
# MAIN
# ==========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
