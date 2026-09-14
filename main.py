from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from database import get_pool, close_pool
from waf import waf_engine
from rate_limiter import rate_limiter
from ip_manager import ip_manager
from bruteforce import bruteforce
from bot_guard import bot_guard
from csrf import csrf_guard
from geo_guard import geo_guard
from headers_guard import apply_security_headers


@asynccontextmanager
async def lifespan(app: FastAPI):
    await get_pool()
    await waf_engine.load_rules()
    await bot_guard.load()
    await geo_guard.load()
    yield
    await close_pool()

app = FastAPI(title="Web Site Guard", lifespan=lifespan)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    return xff.split(",")[0].strip() if xff else request.client.host


@app.middleware("http")
async def guard_middleware(request: Request, call_next):
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")
    path = request.url.path
    full_payload = f"{path}?{request.url.query}"

    # 1) Whitelist → direkt geç
    if await ip_manager.is_whitelisted(ip):
        return await call_next(request)

    # 2) Blacklist
    if await ip_manager.is_blacklisted(ip):
        return JSONResponse({"error": "IP blocked"}, status_code=403)

    # 3) Rate limit
    if not await rate_limiter.check(ip, path):
        await ip_manager.blacklist(ip, "rate_limit_exceeded", 15)
        return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)

    # 4) Bot kontrolü
    if bot_guard.is_bad_bot(ua):
        await ip_manager.blacklist(ip, "malicious_bot", 1440)
        return JSONResponse({"error": "Bot blocked"}, status_code=403)

    # 5) WAF taraması (URL + body)
    body = ""
    if request.method in ("POST", "PUT", "PATCH"):
        body = (await request.body()).decode(errors="ignore")

    for payload in (full_payload, body, ua):
        score, rule = waf_engine.scan(payload)
        if score >= 7:
            await waf_engine.log_threat(
                ip, None, rule["category"], score,
                payload, rule["id"], "block"
            )
            await ip_manager.blacklist(ip, f"waf:{rule['rule_name']}", 60)
            return JSONResponse({"error": "Request blocked by WAF"},
                                status_code=403)

    # 6) Bruteforce (login endpoint için)
    if path.endswith("/login") and request.method == "POST":
        if await bruteforce.is_locked(ip):
            return JSONResponse({"error": "Too many attempts"}, status_code=429)

    response = await call_next(request)

    # 7) Güvenlik header'ları
    apply_security_headers(response)

    return response


# ---- Yardımcı Endpoint'ler ----

@app.post("/auth/login")
async def login(request: Request, username: str, password: str):
    ip = client_ip(request)
    # ... gerçek doğrulama burada ...
    success = (username == "admin" and password == "secret")
    await bruteforce.record(ip, username, success)
    if not success:
        raise HTTPException(401, "Invalid credentials")
    return {"ok": True, "csrf": await csrf_guard.issue(username, ip)}


@app.get("/honeypot/admin.php")
async def honeypot(request: Request):
    """Tuzak endpoint - botlar buraya gelir."""
    ip = client_ip(request)
    pool = await get_pool()
    async with pool.acquire() as c:
        await c.execute("""
            INSERT INTO honeypot_hits (ip_address, trap_path, method, headers)
            VALUES ($1::inet,$2,$3,$4)
        """, ip, request.url.path, request.method, dict(request.headers))
    await ip_manager.blacklist(ip, "honeypot_triggered", 1440)
    raise HTTPException(404)
