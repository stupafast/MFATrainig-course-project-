# -*- coding: utf-8 -*-
"""Лекционный материал по каждой атаке. Ключ — scenario_id."""

LECTURES = {
    1: {
        "name_ru": "QR Phishing (Quishing)",
        "name_en": "QR Phishing (Quishing)",
        "blocks_ru": [
            {"type": "p", "text": "Фишинг через QR-коды (quishing) возможен, когда приложение при внедрении MFA доверяет данным извне: ссылкам из писем, QR, сгенерированным на стороне клиента или по переданному URL."},
            {"type": "h3", "text": "Уязвимость: генерация QR по переданному URI"},
            {"type": "p", "text": "Опасный фрагмент: бэкенд формирует provisioning URI для TOTP из параметров запроса и сразу отдаёт QR, не привязывая секрет к сессии пользователя."},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМЫЙ КОД: QR генерируется из request
@app.route('/mfa/setup')
def mfa_setup():
    issuer = request.args.get('issuer', 'MyApp')
    label = request.args.get('label', 'user@mail.com')
    secret = request.args.get('secret') or pyotp.random_base32()
    # Секрет и label приходят извне — атакующий может подставить свой!
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=label, issuer_name=issuer
    )
    return render_template('qr.html', qr_data=uri)"""},
            {"type": "p", "text": "Злоумышленник подставляет свой secret и label в URL. Жертва сканирует «официальный» QR с фишинговой страницы — коды генерируются у атакующего, а не у сервера."},
            {"type": "h3", "text": "Уязвимость: хранение секрета только на клиенте"},
            {"type": "code", "lang": "javascript", "code": """// УЯЗВИМО: секрет в localStorage, доступен XSS
const secret = localStorage.getItem('totp_secret');
const code = totp(secret);
fetch('/api/verify', { body: JSON.stringify({ code }) });"""},
            {"type": "p", "text": "При XSS атакующий читает secret из localStorage и получает действующие TOTP-коды. Защита: хранить секрет только на сервере, привязывать к сессии, не доверять client-side секретам."},
            {"type": "h3", "text": "Защита"},
            {"type": "code", "lang": "python", "code": """# БЕЗОПАСНО: секрет создаётся на сервере, привязан к сессии
@app.route('/mfa/setup')
def mfa_setup():
    if 'mfa_secret' not in session:
        session['mfa_secret'] = pyotp.random_base32()
    secret = session['mfa_secret']
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name='MFAurora'
    )
    return render_template('qr.html', qr_data=uri)"""},
        ],
        "blocks_en": [
            {"type": "p", "text": "QR-based phishing (quishing) is possible when the app trusts external data for MFA: links from emails, client-generated QR, or user-supplied URLs."},
            {"type": "h3", "text": "Vulnerability: generating QR from request"},
            {"type": "p", "text": "Dangerous pattern: backend builds TOTP provisioning URI from request params and returns a QR without binding the secret to the user session."},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: QR from request
@app.route('/mfa/setup')
def mfa_setup():
    issuer = request.args.get('issuer', 'MyApp')
    label = request.args.get('label', 'user@mail.com')
    secret = request.args.get('secret') or pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=label, issuer_name=issuer
    )
    return render_template('qr.html', qr_data=uri)"""},
            {"type": "p", "text": "Attacker supplies their secret and label via URL. Victim scans \"official\" QR from phishing page — codes are generated for the attacker."},
            {"type": "h3", "text": "Vulnerability: secret only on client"},
            {"type": "code", "lang": "javascript", "code": """// VULNERABLE: secret in localStorage, XSS can steal
const secret = localStorage.getItem('totp_secret');
const code = totp(secret);
fetch('/api/verify', { body: JSON.stringify({ code }) });"""},
            {"type": "p", "text": "With XSS, attacker reads secret from localStorage and gets valid TOTP codes. Mitigation: store secret only server-side, bind to session, never trust client-side secrets."},
            {"type": "h3", "text": "Secure implementation"},
            {"type": "code", "lang": "python", "code": """# SECURE: server-generated secret, session-bound
@app.route('/mfa/setup')
def mfa_setup():
    if 'mfa_secret' not in session:
        session['mfa_secret'] = pyotp.random_base32()
    secret = session['mfa_secret']
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name='MFAurora'
    )
    return render_template('qr.html', qr_data=uri)"""},
        ],
    },
    2: {
        "name_ru": "Brute Force",
        "name_en": "Brute Force",
        "blocks_ru": [
            {"type": "p", "text": "Перебор 6-значного TOTP-кода (10^6 комбинаций) возможен, если верификация не ограничена по попыткам и по времени. Уязвимость — в коде проверки и отсутствии rate limiting."},
            {"type": "h3", "text": "Уязвимость: нет ограничения попыток"},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМЫЙ КОД: неограниченные попытки верификации
@app.route('/mfa/verify', methods=['POST'])
def verify():
    code = request.json.get('code')
    secret = get_user_secret(current_user.id)
    if pyotp.TOTP(secret).verify(code):
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401
# Атакующий перебирает 000000..999999 без блокировки"""},
            {"type": "p", "text": "Запросы можно автоматизировать. За секунды перебираются тысячи кодов. Окно TOTP 30 секунд — за 30 с реально проверить порядка 100–500 кодов в зависимости от латентности."},
            {"type": "h3", "text": "Уязвимость: слабая энтропия кода"},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМО: 4-значный код вместо 6
totp = pyotp.TOTP(secret, digits=4)  # 10^4 = 10000 комбинаций
# Ещё хуже — код из cookie или predictable"""},
            {"type": "h3", "text": "Защита: rate limiting и блокировка"},
            {"type": "code", "lang": "python", "code": """# БЕЗОПАСНО: лимит попыток по user_id и IP
from flask_limiter import Limiter
limiter = Limiter(key_func=lambda: f"{request.remote_addr}:{current_user.id}")

@app.route('/mfa/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify():
    code = request.json.get('code')
    secret = get_user_secret(current_user.id)
    if pyotp.TOTP(secret).verify(code):
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401"""},
        ],
        "blocks_en": [
            {"type": "p", "text": "Brute-forcing a 6-digit TOTP code (10^6 combinations) is feasible if verification has no attempt or time limits. The vulnerability is in the verification logic and lack of rate limiting."},
            {"type": "h3", "text": "Vulnerability: no attempt limit"},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: unlimited verification attempts
@app.route('/mfa/verify', methods=['POST'])
def verify():
    code = request.json.get('code')
    secret = get_user_secret(current_user.id)
    if pyotp.TOTP(secret).verify(code):
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401
# Attacker iterates 000000..999999 with no lockout"""},
            {"type": "p", "text": "Requests can be automated. Thousands of codes per minute. TOTP window is 30 seconds — in 30s hundreds of codes can be tried depending on latency."},
            {"type": "h3", "text": "Vulnerability: weak code entropy"},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: 4-digit instead of 6
totp = pyotp.TOTP(secret, digits=4)  # 10^4 = 10000 combinations
# Worse: code from cookie or predictable"""},
            {"type": "h3", "text": "Mitigation: rate limiting"},
            {"type": "code", "lang": "python", "code": """# SECURE: limit attempts per user and IP
from flask_limiter import Limiter
limiter = Limiter(key_func=lambda: f"{request.remote_addr}:{current_user.id}")

@app.route('/mfa/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify():
    code = request.json.get('code')
    secret = get_user_secret(current_user.id)
    if pyotp.TOTP(secret).verify(code):
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401"""},
        ],
    },
    3: {
        "name_ru": "Timing Attack",
        "name_en": "Timing Attack",
        "blocks_ru": [
            {"type": "p", "text": "Если сравнение кода с эталоном выполняется посимвольно с ранним выходом при первом несовпадении, время ответа зависит от количества совпавших символов. По задержкам можно подобрать код посимвольно."},
            {"type": "h3", "text": "Уязвимость: посимвольное сравнение"},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМЫЙ КОД: early exit при первом несовпадении
def verify_totp(user_code: str, secret: str) -> bool:
    expected = pyotp.TOTP(secret).now()
    if len(user_code) != len(expected):
        return False
    for i in range(len(expected)):
        if user_code[i] != expected[i]:  # ранний выход!
            return False
    return True
# Больше совпавших символов → дольше выполнение → утечка"""},
            {"type": "p", "text": "Атакующий измеряет время ответа для 000000, 100000, 200000, … и по разнице во времени определяет первую цифру. Затем перебирает вторую и т.д."},
            {"type": "h3", "text": "Защита: constant-time сравнение"},
            {"type": "code", "lang": "python", "code": """# БЕЗОПАСНО: constant-time compare
import hmac

def verify_totp(user_code: str, secret: str) -> bool:
    expected = pyotp.TOTP(secret).now()
    if len(user_code) != len(expected):
        return False
    return hmac.compare_digest(user_code, expected)
# hmac.compare_digest всегда сравнивает все байты"""},
        ],
        "blocks_en": [
            {"type": "p", "text": "If the code is compared character-by-character with early exit on first mismatch, response time depends on how many characters match. Timing reveals the code digit-by-digit."},
            {"type": "h3", "text": "Vulnerability: character-by-character compare"},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: early exit on first mismatch
def verify_totp(user_code: str, secret: str) -> bool:
    expected = pyotp.TOTP(secret).now()
    if len(user_code) != len(expected):
        return False
    for i in range(len(expected)):
        if user_code[i] != expected[i]:  # early exit!
            return False
    return True
# More matching chars → longer execution → leak"""},
            {"type": "p", "text": "Attacker measures response time for 000000, 100000, 200000, … and infers the first digit. Then the second, etc."},
            {"type": "h3", "text": "Mitigation: constant-time compare"},
            {"type": "code", "lang": "python", "code": """# SECURE: constant-time compare
import hmac

def verify_totp(user_code: str, secret: str) -> bool:
    expected = pyotp.TOTP(secret).now()
    if len(user_code) != len(expected):
        return False
    return hmac.compare_digest(user_code, expected)
# hmac.compare_digest always compares all bytes"""},
        ],
    },
    4: {
        "name_ru": "Session Hijacking",
        "name_en": "Session Hijacking",
        "blocks_ru": [
            {"type": "p", "text": "JWT или session ID в localStorage, в URL или в cookie без HttpOnly доступны скриптам. При XSS атакующий крадёт токен и выполняет запросы от имени жертвы, в том числе обходя MFA после успешного входа."},
            {"type": "h3", "text": "Уязвимость: JWT в localStorage"},
            {"type": "code", "lang": "javascript", "code": """// УЯЗВИМО: токен в localStorage — доступен XSS
fetch('/login', { method: 'POST', body: JSON.stringify({ user, pass, code }) })
  .then(r => r.json())
  .then(data => {
    localStorage.setItem('jwt', data.token);  // любой скрипт может прочитать!
  });
// Запросы:
fetch('/api/me', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt') }
});"""},
            {"type": "p", "text": "Достаточно одной XSS — например, через неэкранированный вывод в шаблоне. Скрипт отправляет localStorage.getItem('jwt') на сервер атакующего."},
            {"type": "h3", "text": "Уязвимость: проверка только наличия токена"},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМО: не проверяем привязку к устройству/IP
def verify_jwt(token):
    payload = jwt.decode(token, SECRET)
    return payload.get('user_id')  # приняли украденный токен как свой"""},
            {"type": "h3", "text": "Защита: HttpOnly cookie, CSP"},
            {"type": "code", "lang": "python", "code": """# БЕЗОПАСНО: токен в HttpOnly cookie, не доступен JS
resp = make_response(redirect('/dashboard'))
resp.set_cookie('session', token, httponly=True, secure=True,
                samesite='Strict', max_age=3600)
return resp

# + Content-Security-Policy против XSS
# + привязка сессии к fingerprint/IP (опционально)"""},
        ],
        "blocks_en": [
            {"type": "p", "text": "JWT or session ID in localStorage, URL, or non-HttpOnly cookie is readable by scripts. With XSS, attacker steals the token and sends requests as the victim, bypassing MFA post-login."},
            {"type": "h3", "text": "Vulnerability: JWT in localStorage"},
            {"type": "code", "lang": "javascript", "code": """// VULNERABLE: token in localStorage — XSS can read
fetch('/login', { method: 'POST', body: JSON.stringify({ user, pass, code }) })
  .then(r => r.json())
  .then(data => {
    localStorage.setItem('jwt', data.token);  // any script can read!
  });
fetch('/api/me', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt') }
});"""},
            {"type": "p", "text": "One XSS is enough — e.g. unescaped output in a template. Script exfiltrates localStorage.getItem('jwt') to attacker's server."},
            {"type": "h3", "text": "Vulnerability: only checking token presence"},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: no device/IP binding
def verify_jwt(token):
    payload = jwt.decode(token, SECRET)
    return payload.get('user_id')  # accept stolen token as valid"""},
            {"type": "h3", "text": "Mitigation: HttpOnly cookie, CSP"},
            {"type": "code", "lang": "python", "code": """# SECURE: token in HttpOnly cookie, not readable by JS
resp = make_response(redirect('/dashboard'))
resp.set_cookie('session', token, httponly=True, secure=True,
                samesite='Strict', max_age=3600)
return resp

# + Content-Security-Policy against XSS
# + session binding to fingerprint/IP (optional)"""},
        ],
    },
    5: {
        "name_ru": "Rate Limiting Bypass",
        "name_en": "Rate Limiting Bypass",
        "blocks_ru": [
            {"type": "p", "text": "Ограничение попыток верификации MFA по IP или по user_id можно обойти: смена IP (прокси, VPN, Tor), распределённый перебор, разный ключ лимита для API и веб-формы. Уязвимость — в том, как и по чему считается лимит в коде."},
            {"type": "h3", "text": "Уязвимость: лимит только по IP"},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМО: счётчик только по IP
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
@app.route('/mfa/verify', methods=['POST'])
def verify():
    ...
# Атакующий перебирает коды с разных IP (прокси, облако)"""},
            {"type": "h3", "text": "Уязвимость: разные эндпоинты — разные счётчики"},
            {"type": "code", "lang": "python", "code": """# УЯЗВИМО: /api/verify и /web/verify — отдельные лимиты
@limiter.limit("5/min")
@app.route('/api/verify') ...

@limiter.limit("5/min")
@app.route('/web/verify') ...
# 5+5 попыток в минуту на одного пользователя"""},
            {"type": "h3", "text": "Защита: единый ключ user_id + глобальный лимит"},
            {"type": "code", "lang": "python", "code": """# БЕЗОПАСНО: лимит по user_id (после аутентификации)
def limit_key():
    if current_user.is_authenticated:
        return f"mfa:{current_user.id}"
    return f"mfa_ip:{request.remote_addr}"

@limiter.limit("5 per minute", key_func=limit_key)
@app.route('/mfa/verify', methods=['POST'])
def verify(): ...

# + общий глобальный лимит на /mfa/* по IP для неавторизованных"""},
        ],
        "blocks_en": [
            {"type": "p", "text": "Rate limiting MFA verification by IP or user_id can be bypassed: rotating IPs (proxy, VPN, Tor), distributed brute-force, or different limit keys for API vs web form. The bug is how and what we rate-limit in code."},
            {"type": "h3", "text": "Vulnerability: limit by IP only"},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: counter by IP only
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
@app.route('/mfa/verify', methods=['POST'])
def verify():
    ...
# Attacker rotates IPs (proxies, cloud)"""},
            {"type": "h3", "text": "Vulnerability: separate limits per endpoint"},
            {"type": "code", "lang": "python", "code": """# VULNERABLE: /api/verify and /web/verify — separate limits
@limiter.limit("5/min")
@app.route('/api/verify') ...

@limiter.limit("5/min")
@app.route('/web/verify') ...
# 5+5 attempts per minute per user"""},
            {"type": "h3", "text": "Mitigation: unified user_id key"},
            {"type": "code", "lang": "python", "code": """# SECURE: limit by user_id (after auth)
def limit_key():
    if current_user.is_authenticated:
        return f"mfa:{current_user.id}"
    return f"mfa_ip:{request.remote_addr}"

@limiter.limit("5 per minute", key_func=limit_key)
@app.route('/mfa/verify', methods=['POST'])
def verify(): ...

# + global cap on /mfa/* by IP for unauthenticated"""},
        ],
    },
}
