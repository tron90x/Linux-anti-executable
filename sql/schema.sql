-- Linux Anti-Executable Database Schema
-- SQLite3

-- Main whitelist table
-- Stores SHA256 hashes of allowed executables
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL UNIQUE,           -- SHA256 hash (64 hex chars)
    path TEXT NOT NULL,                   -- Original file path (informational)
    added_time INTEGER NOT NULL,          -- Unix timestamp when added
    added_by INTEGER DEFAULT 0,           -- UID of user who approved
    is_system INTEGER DEFAULT 0,          -- 1 if auto-added during scan
    description TEXT,                     -- Optional user description

    CHECK(length(hash) = 64)
);

-- Index for fast hash lookups (primary operation)
CREATE INDEX IF NOT EXISTS idx_whitelist_hash ON whitelist(hash);

-- Index for path-based queries
CREATE INDEX IF NOT EXISTS idx_whitelist_path ON whitelist(path);

-- Denied executables log
-- Stores history of denied execution attempts
CREATE TABLE IF NOT EXISTS denied_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    path TEXT NOT NULL,
    pid INTEGER NOT NULL,                 -- Process ID that attempted execution
    uid INTEGER NOT NULL,                 -- User ID
    parent_path TEXT,                     -- Parent process path
    denied_time INTEGER NOT NULL,         -- Unix timestamp
    cmdline TEXT                          -- Full command line
);

-- Index for querying recent denials
CREATE INDEX IF NOT EXISTS idx_denied_time ON denied_log(denied_time);

-- Allowed executables log (audit trail)
-- Stores history of allowed execution attempts (optional, for auditing)
CREATE TABLE IF NOT EXISTS allowed_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    path TEXT NOT NULL,
    pid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    allowed_time INTEGER NOT NULL
);

-- Configuration table
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_time INTEGER NOT NULL
);

-- Default configuration values
INSERT OR IGNORE INTO config (key, value, updated_time) VALUES
    ('learning_mode', '0', strftime('%s', 'now')),
    ('log_allowed', '0', strftime('%s', 'now')),
    ('log_denied', '1', strftime('%s', 'now')),
    ('scan_complete', '0', strftime('%s', 'now'));

-- Pending decisions (for async GUI approval)
CREATE TABLE IF NOT EXISTS pending_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER UNIQUE NOT NULL,   -- Matches daemon request ID
    hash TEXT NOT NULL,
    path TEXT NOT NULL,
    pid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    parent_path TEXT,
    cmdline TEXT,
    request_time INTEGER NOT NULL,
    expires_time INTEGER NOT NULL         -- Auto-deny after timeout
);

-- View: Recent activity summary
CREATE VIEW IF NOT EXISTS recent_activity AS
SELECT
    'DENIED' as action,
    hash,
    path,
    denied_time as timestamp,
    pid,
    uid
FROM denied_log
WHERE denied_time > strftime('%s', 'now') - 86400
UNION ALL
SELECT
    'ALLOWED' as action,
    hash,
    path,
    allowed_time as timestamp,
    pid,
    uid
FROM allowed_log
WHERE allowed_time > strftime('%s', 'now') - 86400
ORDER BY timestamp DESC
LIMIT 100;

-- View: Whitelist with file info
CREATE VIEW IF NOT EXISTS whitelist_view AS
SELECT
    w.id,
    w.hash,
    w.path,
    datetime(w.added_time, 'unixepoch') as added_date,
    CASE w.is_system WHEN 1 THEN 'System' ELSE 'User' END as source,
    w.description
FROM whitelist w
ORDER BY w.added_time DESC;
