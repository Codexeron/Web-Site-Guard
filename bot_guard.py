import re
from database import get_pool

class BotGuard:
    def __init__(self):
        self.patterns = []

    async def load(self):
        pool = await get_pool()
        async with pool.acquire() as c:
            rows = await c.fetch("SELECT user_agent_regex FROM bot_signatures "
                                 "WHERE is_malicious=TRUE")
        self.patterns = [re.compile(r["user_agent_regex"], re.I) for r in rows]

    def is_bad_bot(self, user_agent: str) -> bool:
        return any(p.search(user_agent or "") for p in self.patterns)

bot_guard = BotGuard()
