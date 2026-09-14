import secrets
from datetime import datetime, timedelta
from database import get_pool
from config import Config

class CSRFGuard:
    async def issue(self, session_id: str, ip: str) -> str:
        token = secrets.token_urlsafe(48)
        pool = await get_pool()
        async with pool.acquire() as c:
            await c.execute("""
                INSERT INTO csrf_tokens (session_id, token, ip_address, expires_at)
                VALUES ($1,$2,$3::inet, NOW() + ($4||' minutes')::interval)
                ON CONFLICT (session_id) DO UPDATE
                  SET token=EXCLUDED.token,
                      expires_at=EXCLUDED.expires_at
            """, session_id, token, ip, Config.CSRF_EXPIRE_MIN)
        return token

    async def validate(self, session_id: str, token: str) -> bool:
        pool = await get_pool()
        async with pool.acquire() as c:
            row = await c.fetchrow("""
                SELECT 1 FROM csrf_tokens
                WHERE session_id=$1 AND token=$2 AND expires_at > NOW()
            """, session_id, token)
        return row is not None

csrf_guard = CSRFGuard()
