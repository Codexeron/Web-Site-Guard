from database import get_pool

class GeoGuard:
    def __init__(self):
        self.blocked = set()

    async def load(self):
        pool = await get_pool()
        async with pool.acquire() as c:
            rows = await c.fetch("SELECT country_code FROM geo_rules "
                                 "WHERE rule_type='block' AND is_active=TRUE")
        self.blocked = {r["country_code"] for r in rows}

    def is_blocked(self, country_code: str) -> bool:
        return country_code and country_code.upper() in self.blocked

geo_guard = GeoGuard()
