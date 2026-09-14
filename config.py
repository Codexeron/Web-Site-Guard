import os

class Config:
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 5432))
    DB_NAME = os.getenv("DB_NAME", "webshield")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASS = os.getenv("DB_PASS", "postgres")

    RATE_LIMIT_PER_MIN = 120
    RATE_LIMIT_PER_HOUR = 3000

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 30

    CSRF_EXPIRE_MIN = 30
    BLOCK_DURATION_MIN = 60

    TRUSTED_PROXIES = ["127.0.0.1"]
