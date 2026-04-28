# -*- coding: utf-8 -*-
"""Вопросы тестов: теория и практика по атакам. attack_id: 0 = общее, 1–5 = сценарии."""

THEORY = [
    {"id": 1, "attack_id": 0, "q_ru": "Что такое TOTP?", "q_en": "What is TOTP?",
     "options_ru": ["Time-based One-Time Password", "Total Online Transfer Protocol", "Text Over TCP Port"],
     "options_en": ["Time-based One-Time Password", "Total Online Transfer Protocol", "Text Over TCP Port"], "correct": 0},
    {"id": 2, "attack_id": 0, "q_ru": "Какой длины код обычно в Google Authenticator?", "q_en": "Typical code length in Google Authenticator?",
     "options_ru": ["4 digits", "6 digits", "8 digits"], "options_en": ["4 digits", "6 digits", "8 digits"], "correct": 1},
    {"id": 3, "attack_id": 0, "q_ru": "Какой алгоритм используется в TOTP (RFC 6238)?", "q_en": "Which algorithm is used in TOTP (RFC 6238)?",
     "options_ru": ["HMAC-SHA1", "AES-256", "RSA"], "options_en": ["HMAC-SHA1", "AES-256", "RSA"], "correct": 0},
    {"id": 4, "attack_id": 1, "q_ru": "Почему опасно генерировать QR для MFA из параметров запроса (issuer, label, secret)?",
     "q_en": "Why is it dangerous to generate MFA QR from request params (issuer, label, secret)?",
     "options_ru": ["Атакующий может подставить свой secret и перехватить коды", "QR будет нечитаемым", "Это замедляет сервер"],
     "options_en": ["Attacker can supply their secret and capture codes", "QR becomes unreadable", "It slows the server"], "correct": 0},
    {"id": 5, "attack_id": 2, "q_ru": "Чем опасен перебор 6-значного TOTP-кода при отсутствии rate limiting?",
     "q_en": "Why is brute-forcing a 6-digit TOTP code dangerous without rate limiting?",
     "options_ru": ["10^6 комбинаций можно перебрать за минуты", "Коды станут длиннее", "TOTP отключится"],
     "options_en": ["10^6 combinations can be tried in minutes", "Codes become longer", "TOTP disables"], "correct": 0},
    {"id": 6, "attack_id": 3, "q_ru": "Почему посимвольное сравнение кода с ранним выходом уязвимо?",
     "q_en": "Why is character-by-character comparison with early exit vulnerable?",
     "options_ru": ["Время ответа выдаёт правильный префикс (timing attack)", "Код легче угадать", "Сравнение не выполняется"],
     "options_en": ["Response time leaks correct prefix (timing attack)", "Code is easier to guess", "Comparison never runs"], "correct": 0},
    {"id": 7, "attack_id": 4, "q_ru": "Почему хранение JWT в localStorage опасно при риске XSS?",
     "q_en": "Why is storing JWT in localStorage risky with XSS?",
     "options_ru": ["Любой скрипт может прочитать токен и отправить его атакующему", "localStorage медленный", "Токен истечёт быстрее"],
     "options_en": ["Any script can read the token and exfiltrate it", "localStorage is slow", "Token expires sooner"], "correct": 0},
    {"id": 8, "attack_id": 5, "q_ru": "Чем опасен rate limiting только по IP для MFA verify?",
     "q_en": "Why is rate limiting by IP only dangerous for MFA verify?",
     "options_ru": ["Атакующий меняет IP (прокси, VPN) и обходит лимит", "IP часто меняется", "Лимит по IP не работает"],
     "options_en": ["Attacker rotates IPs (proxy, VPN) and bypasses limit", "IP changes often", "IP-based limit doesn't work"], "correct": 0},
]

PRACTICAL = [
    {"id": 101, "attack_id": 1, "code_lang": "python", "code": """# Генерация QR для MFA
@app.route('/mfa/setup')
def mfa_setup():
    issuer = request.args.get('issuer', 'App')
    label = request.args.get('label', 'user@example.com')
    secret = request.args.get('secret') or pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
    return render_template('qr.html', qr_data=uri)""",
     "q_ru": "В чём уязвимость этого кода?", "q_en": "What is the vulnerability?",
     "options_ru": ["secret и label из request — атакующий подставляет свои", "Используется pyotp", "Возвращается HTML"],
     "options_en": ["secret and label from request — attacker supplies theirs", "Uses pyotp", "Returns HTML"], "correct": 0},
    {"id": 102, "attack_id": 2, "code": """@app.route('/mfa/verify', methods=['POST'])
def verify():
    code = request.json.get('code')
    secret = get_secret(current_user.id)
    if pyotp.TOTP(secret).verify(code):
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401""",
     "q_ru": "Какую уязвимость можно эксплуатировать?", "q_en": "Which vulnerability can be exploited?",
     "options_ru": ["Нет лимита попыток — brute-force 6-значного кода", "Используется JSON", "Возвращается 401"],
     "options_en": ["No attempt limit — brute-force 6-digit code", "Uses JSON", "Returns 401"], "correct": 0},
    {"id": 103, "attack_id": 3, "code_lang": "python", "code": """def verify_code(user_code: str, secret: str) -> bool:
    expected = pyotp.TOTP(secret).now()
    for i in range(len(expected)):
        if user_code[i] != expected[i]:
            return False
    return True""",
     "q_ru": "Как исправить уязвимость?", "q_en": "How to fix the vulnerability?",
     "options_ru": ["Заменить на hmac.compare_digest(user_code, expected)", "Увеличить длину кода", "Добавить sleep(1)"],
     "options_en": ["Use hmac.compare_digest(user_code, expected)", "Increase code length", "Add sleep(1)"], "correct": 0},
    {"id": 104, "attack_id": 4, "code": """fetch('/login', { method: 'POST', body: JSON.stringify({ user, pass, code }) })
  .then(r => r.json())
  .then(d => { localStorage.setItem('jwt', d.token); });
// later:
fetch('/api/me', { headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt') } });""",
     "q_ru": "В чём опасность при возможном XSS?", "q_en": "What's the risk with possible XSS?",
     "options_ru": ["Токен в localStorage — скрипт может прочитать и украсть", "Используется fetch", "Токен в заголовке"],
     "options_en": ["Token in localStorage — script can read and steal it", "Uses fetch", "Token in header"], "correct": 0},
    {"id": 105, "attack_id": 5, "code_lang": "python", "code": """@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
@app.route('/mfa/verify', methods=['POST'])
def verify(): ...""",
     "q_ru": "Как обойти это ограничение?", "q_en": "How can an attacker bypass this limit?",
     "options_ru": ["Менять IP (прокси, VPN) — лимит на каждый IP отдельно", "Отправлять реже", "Использовать другой браузер"],
     "options_en": ["Rotate IPs (proxy, VPN) — limit is per IP", "Send less often", "Use another browser"], "correct": 0},
]

def get_theory(attack_id=None):
    if attack_id is None or attack_id == 0:
        return THEORY
    return [q for q in THEORY if q["attack_id"] == 0 or q["attack_id"] == attack_id]

def get_practical(attack_id=None):
    if attack_id is None or attack_id == 0:
        return PRACTICAL
    return [q for q in PRACTICAL if q["attack_id"] == attack_id]
