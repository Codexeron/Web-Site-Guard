-- =====================================================
-- WEB SITE GUARD - Veritabanı Şeması
-- =====================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Ziyaretçi / İstek kayıtları
CREATE TABLE IF NOT EXISTS visitors (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET NOT NULL,
    user_agent      TEXT,
    referer         TEXT,
    country_code    VARCHAR(2),
    city            VARCHAR(100),
    asn             VARCHAR(50),
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    total_requests  BIGINT DEFAULT 1,
    is_blocked      BOOLEAN DEFAULT FALSE
);
CREATE INDEX idx_visitors_ip ON visitors(ip_address);

-- 2. İstek Logları
CREATE TABLE IF NOT EXISTS request_logs (
    id              BIGSERIAL PRIMARY KEY,
    visitor_id      BIGINT REFERENCES visitors(id) ON DELETE SET NULL,
    ip_address      INET NOT NULL,
    method          VARCHAR(10),
    path            TEXT,
    query_string    TEXT,
    headers         JSONB,
    body            TEXT,
    status_code     INT,
    response_time   INT,          -- ms
    threat_score    INT DEFAULT 0,
    action_taken    VARCHAR(20),  -- allow / block / challenge
    created_at      TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);
CREATE INDEX idx_reqlog_ip_time ON request_logs(ip_address, created_at DESC);
CREATE INDEX idx_reqlog_action ON request_logs(action_taken);

-- 3. Rate Limit (istek sayacı)
CREATE TABLE IF NOT EXISTS rate_limits (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET NOT NULL,
    endpoint        TEXT NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    request_count   INT DEFAULT 1,
    UNIQUE (ip_address, endpoint, window_start)
);

-- 4. IP Blacklist / Whitelist
CREATE TABLE IF NOT EXISTS ip_lists (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET,
    cidr            CIDR,
    list_type       VARCHAR(10) CHECK (list_type IN ('black','white')),
    reason          TEXT,
    expires_at      TIMESTAMPTZ,
    created_by      VARCHAR(100),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    CHECK (ip_address IS NOT NULL OR cidr IS NOT NULL)
);
CREATE INDEX idx_iplist_type ON ip_lists(list_type);

-- 5. WAF Kuralları
CREATE TABLE IF NOT EXISTS waf_rules (
    id              SERIAL PRIMARY KEY,
    rule_name       VARCHAR(100) UNIQUE NOT NULL,
    category        VARCHAR(30),  -- sqli, xss, rce, lfi, rfi, csrf
    pattern         TEXT NOT NULL, -- regex
    severity        INT DEFAULT 5, -- 1-10
    action          VARCHAR(20) DEFAULT 'block', -- block/challenge/log
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Saldırı / Tehdit Olayları
CREATE TABLE IF NOT EXISTS threat_events (
    id              BIGSERIAL PRIMARY KEY,
    visitor_id      BIGINT REFERENCES visitors(id),
    ip_address      INET,
    threat_type     VARCHAR(50),   -- sqli / xss / ddos / bruteforce...
    severity        INT,
    payload         TEXT,
    rule_id         INT REFERENCES waf_rules(id),
    action_taken    VARCHAR(20),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_threat_type_time ON threat_events(threat_type, created_at DESC);

-- 7. Brute Force Takibi
CREATE TABLE IF NOT EXISTS login_attempts (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET NOT NULL,
    username        VARCHAR(150),
    success         BOOLEAN DEFAULT FALSE,
    attempted_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_login_ip_time ON login_attempts(ip_address, attempted_at DESC);

-- 8. CSRF Token Deposu
CREATE TABLE IF NOT EXISTS csrf_tokens (
    id              BIGSERIAL PRIMARY KEY,
    session_id      VARCHAR(128) UNIQUE NOT NULL,
    token           VARCHAR(128) NOT NULL,
    ip_address      INET,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 9. Geo Blocking
CREATE TABLE IF NOT EXISTS geo_rules (
    id              SERIAL PRIMARY KEY,
    country_code    VARCHAR(2) NOT NULL,
    rule_type       VARCHAR(10) CHECK (rule_type IN ('block','allow')),
    reason          TEXT,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 10. Bot / Crawler
CREATE TABLE IF NOT EXISTS bot_signatures (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100),
    user_agent_regex TEXT,
    is_malicious    BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 11. Dosya Yükleme Taraması
CREATE TABLE IF NOT EXISTS upload_scans (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET,
    filename        TEXT,
    mime_type       VARCHAR(100),
    file_size       BIGINT,
    sha256          CHAR(64),
    scan_result     VARCHAR(20),   -- clean / infected / suspicious
    details         JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 12. SSL/TLS Sertifika İzleme
CREATE TABLE IF NOT EXISTS ssl_certificates (
    id              SERIAL PRIMARY KEY,
    domain          VARCHAR(255) NOT NULL,
    issuer          TEXT,
    valid_from      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    days_left       INT,
    grade           VARCHAR(5),
    checked_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 13. Honeypot Tuzakları
CREATE TABLE IF NOT EXISTS honeypot_hits (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET,
    trap_path       TEXT,
    method          VARCHAR(10),
    headers         JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 14. Sistem Ayarları
CREATE TABLE IF NOT EXISTS settings (
    key             VARCHAR(100) PRIMARY KEY,
    value           JSONB,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 15. Audit Log (yönetici işlemleri)
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    actor           VARCHAR(100),
    action          VARCHAR(100),
    target          TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- Örnek WAF Kuralları
-- =====================================================
INSERT INTO waf_rules (rule_name, category, pattern, severity) VALUES
('sqli_union',      'sqli', '(?i)(union\s+select|select\s+.*\s+from)', 9),
('sqli_comment',    'sqli', '(--|#|/\*.*\*/)', 6),
('sqli_or_1_1',     'sqli', '(?i)(or|and)\s+[\''"]?\d+[\''"]?\s*=\s*[\''"]?\d+', 9),
('xss_script',      'xss',  '(?i)<script[^>]*>.*?</script>', 9),
('xss_event',       'xss',  '(?i)on\w+\s*=\s*["\''][^"\'' ]*', 7),
('xss_javascript',  'xss',  '(?i)javascript\s*:', 6),
('lfi_traversal',   'lfi',  '(\.\./|\.\.\\\\)', 8),
('rce_cmd',         'rce',  '(?i)(;|\||&&)\s*(cat|ls|wget|curl|bash|sh)\s', 9)
ON CONFLICT (rule_name) DO NOTHING;

-- Varsayılan ayarlar
INSERT INTO settings (key, value) VALUES
('rate_limit', '{"per_minute": 120, "per_hour": 3000}'),
('bruteforce', '{"max_attempts": 5, "lock_minutes": 30}'),
('bot_protection', '{"enabled": true, "challenge": true}')
ON CONFLICT (key) DO NOTHING;
