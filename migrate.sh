#!/bin/bash
# Run new security migrations on the existing D1 database
TOKEN=${1:-$CLOUDFLARE_API_TOKEN}
export CLOUDFLARE_API_TOKEN=$TOKEN
export CLOUDFLARE_ACCOUNT_ID="ea0700117a7ad4a28a7d85bdfce9ed54"

echo "Running security migrations..."
npx wrangler d1 execute pensum-planner-db --remote --command "
ALTER TABLE users ADD COLUMN locked_until TEXT DEFAULT NULL;
" 2>/dev/null || echo "(locked_until may already exist)"

npx wrangler d1 execute pensum-planner-db --remote --command "
ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0;
" 2>/dev/null || echo "(failed_attempts may already exist)"

npx wrangler d1 execute pensum-planner-db --remote --command "
ALTER TABLE sessions ADD COLUMN last_active TEXT DEFAULT (datetime('now'));
" 2>/dev/null || echo "(last_active may already exist)"

npx wrangler d1 execute pensum-planner-db --remote --command "
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER DEFAULT 0,
  window_start TEXT NOT NULL
);"

npx wrangler d1 execute pensum-planner-db --remote --command "
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  email TEXT,
  ip TEXT,
  user_agent TEXT,
  detail TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);"

npx wrangler d1 execute pensum-planner-db --remote --command "
CREATE INDEX IF NOT EXISTS idx_audit_email ON audit_log(email);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);"

echo "✅ Migrations complete!"
