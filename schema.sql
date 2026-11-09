CREATE TABLE IF NOT EXISTS users (
  phone TEXT PRIMARY KEY,
  tier INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  device_id TEXT,
  recovery_hash TEXT,
  recovery_plain TEXT,
  fails INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  device_id TEXT NOT NULL,
  tier INTEGER NOT NULL,
  txn_id TEXT NOT NULL UNIQUE,
  method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  decided_at INTEGER,
  payer_name TEXT,
  payer_last4 TEXT,
  amount REAL
);

CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);

CREATE TABLE IF NOT EXISTS wipes (
  device_id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trials (
  phone TEXT PRIMARY KEY,
  device_id TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_usage (
  phone TEXT NOT NULL,
  day INTEGER NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (phone, day)
);

CREATE TABLE IF NOT EXISTS admin_fails (
  ip TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS codes (
  code TEXT PRIMARY KEY,
  tier INTEGER NOT NULL,
  uses_left INTEGER NOT NULL,
  expires_at INTEGER,
  note TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS code_uses (
  code TEXT NOT NULL,
  phone TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (code, phone)
);
