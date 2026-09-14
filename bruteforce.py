from datetime import datetime, timedelta
from database import get_pool
from config import Config

class BruteForceGuard:
    async def record(self, ip: str, username: str, success: bool):
        pool = await get_pool()
        async with pool.acquire() as c:
            await c.execute(
                "INSERT INTO login_attempts (ip_address, username, success) "
                "VALUES ($1::inet,$2,$3)", ip, username, success)

    async def is_locked(self, ip: str) -> bool:
        since = datetime.utcnow() - timedelta(minutes=Config.LOCKOUT_MINUTES)
        pool = await get_pool()
        async with pool.acquire() as c:
            row = await c.fetchrow("""
                SELECT COUNT(*) AS fails FROM login_attempts
                WHERE ip_address=$1::inet AND success=FALSE AND attempted_at >= $2
            """, ip, since)
        return row["fails"] >= Config.MAX_LOGIN_ATTEMPTS

bruteforce = BruteForceGuard()
