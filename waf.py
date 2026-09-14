import re, asyncpg
from database import get_pool
from typing import Tuple, Optional

class WAF:
    def __init__(self):
        self.rules = []
        self._loaded = False

    async def load_rules(self):
        pool = await get_pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                "SELECT id, rule_name, category, pattern, severity, action "
                "FROM waf_rules WHERE is_active = TRUE"
            )
        self.rules = [
            {**dict(r), "regex": re.compile(r["pattern"], re.IGNORECASE)}
            for r in rows
        ]
        self._loaded = True

    def scan(self, payload: str) -> Tuple[int, Optional[dict]]:
        """Payload'ı tara → (skor, eşleşen kural)"""
        if not payload:
            return 0, None
        max_sev, matched = 0, None
        for rule in self.rules:
            if rule["regex"].search(payload):
                if rule["severity"] > max_sev:
                    max_sev, matched = rule["severity"], rule
        return max_sev, matched

    async def log_threat(self, ip: str, visitor_id: int,
                         threat_type: str, severity: int,
                         payload: str, rule_id: int, action: str):
        pool = await get_pool()
        async with pool.acquire() as c:
            await c.execute("""
                INSERT INTO threat_events
                    (visitor_id, ip_address, threat_type, severity,
                     payload, rule_id, action_taken)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
            """, visitor_id, ip, threat_type, severity,
                 payload[:2000], rule_id, action)

waf_engine = WAF()
