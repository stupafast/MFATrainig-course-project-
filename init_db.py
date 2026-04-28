"""Initialize DB and seed attack_scenarios. Run: python init_db.py"""
import os
import sys
import importlib.util

root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, root)
spec = importlib.util.spec_from_file_location("app_main", os.path.join(root, "app.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
app = mod.app
db = mod.db
User = mod.User
AttackScenario = mod.AttackScenario
MFASecret = mod.MFASecret
LoginAttempt = mod.LoginAttempt
SessionLog = mod.SessionLog
TrainingResult = mod.TrainingResult

from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash

SCENARIOS = [
    {"name": "QR Phishing", "description": "QR Code spoofing / Фишинг через подмену QR-кода", "difficulty": "MEDIUM", "points": 100},
    {"name": "Brute Force", "description": "Password guessing / Подбор паролей перебором", "difficulty": "EASY", "points": 80},
    {"name": "Timing Attack", "description": "Verification timing analysis / Анализ времени верификации", "difficulty": "HARD", "points": 150},
    {"name": "Session Hijacking", "description": "Session capture via XSS / Захват сессии через XSS", "difficulty": "HARD", "points": 150},
    {"name": "Rate Limiting Bypass", "description": "Bypass rate limiting / Обход ограничения попыток", "difficulty": "MEDIUM", "points": 120},
]

def _migrate_training_results():
    try:
        insp = inspect(db.engine)
        if "training_results" not in insp.get_table_names():
            return
        cols = {c["name"] for c in insp.get_columns("training_results")}
        if "scenario_id" not in cols:
            db.session.execute(text("ALTER TABLE training_results ADD COLUMN scenario_id INTEGER"))
        if "time_taken" not in cols:
            db.session.execute(text("ALTER TABLE training_results ADD COLUMN time_taken REAL"))
        if "feedback" not in cols:
            db.session.execute(text("ALTER TABLE training_results ADD COLUMN feedback VARCHAR(500)"))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Migration note:", e)

def main():
    with app.app_context():
        db.create_all()
        _migrate_training_results()
        if AttackScenario.query.count() == 0:
            for s in SCENARIOS:
                db.session.add(AttackScenario(**s))
            db.session.commit()
            print("Seeded 5 attack scenarios.")
        if User.query.count() == 0:
            u = User(
                username="admin",
                email="admin@mfaurora.local",
                password_hash=generate_password_hash("admin123"),
                is_admin=True,
            )
            db.session.add(u)
            db.session.commit()
            print("Created default admin (admin / admin123).")
        print("DB ready.")

if __name__ == "__main__":
    main()
