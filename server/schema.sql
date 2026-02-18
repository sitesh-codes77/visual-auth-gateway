PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  userId TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  createdAt TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS passwords (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId TEXT NOT NULL,
  timeSlot TEXT NOT NULL CHECK (timeSlot IN ('morning','evening','night')),
  originalWord TEXT NOT NULL,
  generatedSentence TEXT NOT NULL,
  matrixConfig TEXT NOT NULL,
  visualPattern TEXT NOT NULL,
  createdAt TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (userId, timeSlot),
  FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  passwordId INTEGER NOT NULL,
  hintLevel INTEGER NOT NULL CHECK (hintLevel BETWEEN 1 AND 3),
  revealedChars TEXT NOT NULL,
  aiGeneratedSentence TEXT NOT NULL,
  matrixPositions TEXT NOT NULL,
  createdAt TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (passwordId) REFERENCES passwords(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId TEXT NOT NULL,
  timeSlot TEXT NOT NULL,
  success INTEGER NOT NULL,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  method TEXT NOT NULL,
  FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId TEXT NOT NULL,
  credentialId TEXT NOT NULL UNIQUE,
  publicKey TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL,
  createdAt TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);
