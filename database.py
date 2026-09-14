import asyncpg, asyncio
from config import Config

_pool: asyncpg.Pool | None = None

async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            host=Config.DB_HOST, port=Config.DB_PORT,
            database=Config.DB_NAME, user=Config.DB_USER,
            password=Config.DB_PASS, min_size=2, max_size=10,
        )
    return _pool

async def close_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
