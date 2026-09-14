from datetime import datetime, timedelta
from database import get_pool
from config import Config

class RateLimiter:
    async def check(self, ip: str, endpoint: str) -> bool:
        """True döner istek izinli, False ise limit aşıldı."""
        window = datetime.utcnow().replace(second=0, microsecond=0)
        pool = await get_pool()
        async with pool.acquire() as c:
            row = await c.fetchrow("""
                INSERT INTO rate_limits (ip_address, endpoint, window_start, request_count)
                VALUES ($1,$2,$3,1)
                ON CONFLICT (ip_address, endpoint, window_start)
                DO UPDATE SET request_count = rate_limits.request_count + 1
                RETURNING request_count
            """, ip, endpoint, window)
        return row["request_count"] <= Config.RATE_LIMIT_PER_MIN

rate_limiter = RateLimiter()
