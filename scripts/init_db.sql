-- This runs on first postgres startup
-- Creates initial admin user (password: changeme)
-- Argon2id hash of "changeme" - will be replaced by app on startup

-- The app will handle user creation via /api/auth/register endpoint
-- This file is just for DB-level setup
SELECT 1;
