from database import get_pool

class IPManager:
    async def is_blacklisted(self, ip: str) -> bool:
        pool = await get_pool()
        async with pool.acquire() as c:
            row = await c.fetchrow("""
                SELECT 1 FROM ip_lists
                WHERE list_type='black'
                  AND (ip_address = $1::inet
                       OR (cidr IS NOT NULL AND $1::inet <<= cidr))
                  AND (expires_at IS NULL OR expires_at > NOW())
                LIMIT 1
            """, ip)
        return row is not None

    async def is_whitelisted(self, ip: str) -> bool:
        pool = await get_pool()
        async with pool.acquire() as c:
            row = await c.fetchrow("""
                SELECT 1 FROM ip_lists
                WHERE list_type='white'
                  AND (ip_address = $1::inet
                       OR (cidr IS NOT NULL AND $1::inet <<= cidr))
                LIMIT 1
            """, ip)
        return row is not None

    async def blacklist(self, ip: str, reason: str, minutes: int = 60):
        pool = await get_pool()
        async with pool.acquire() as c:
            await c.execute("""
                INSERT INTO ip_lists (ip_address, list_type, reason, expires_at, created_by)
                VALUES ($1::inet,'black',$2, NOW() + ($3 || ' minutes')::interval, 'auto')
            """, ip, reason, minutes)

ip_manager = IPManager()
