const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { generateHintBundle, buildHintLevels } = require('./ai-engine');

const DB_PATH = path.join(__dirname, 'visualauth.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function init() {
  const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
  db.exec(schema);
  seedDemoData();
}

function seedDemoData() {
  const insertUser = db.prepare(
    'INSERT OR IGNORE INTO users (userId, name, createdAt) VALUES (@userId, @name, @createdAt)'
  );
  insertUser.run({
    userId: 'U123',
    name: 'Demo User',
    createdAt: new Date().toISOString()
  });

  const demoPasswords = [
    {
      timeSlot: 'morning',
      word: 'Sunrise',
      visualPattern: ['🌅', '🌞', '🌻'],
      sentence: 'Sunrise usually brings new radiant incredible sunny energy.'
    },
    {
      timeSlot: 'evening',
      word: 'Sunset',
      visualPattern: ['🌇', '🌆', '🌉'],
      sentence: 'Sunset unfolds naturally, setting evening tones.'
    },
    {
      timeSlot: 'night',
      word: 'Moon',
      visualPattern: ['🌙', '⭐', '🌠'],
      sentence: 'Moonlight opens our nightly mysteries.'
    }
  ];

  const checkStmt = db.prepare('SELECT id FROM passwords WHERE userId = ? AND timeSlot = ?');
  const insertPassword = db.prepare(`
    INSERT INTO passwords (userId, timeSlot, originalWord, generatedSentence, matrixConfig, visualPattern, createdAt)
    VALUES (@userId, @timeSlot, @originalWord, @generatedSentence, @matrixConfig, @visualPattern, @createdAt)
  `);

  const insertHint = db.prepare(`
    INSERT INTO hints (passwordId, hintLevel, revealedChars, aiGeneratedSentence, matrixPositions, createdAt)
    VALUES (@passwordId, @hintLevel, @revealedChars, @aiGeneratedSentence, @matrixPositions, @createdAt)
  `);

  const tx = db.transaction(() => {
    for (const item of demoPasswords) {
      const exists = checkStmt.get('U123', item.timeSlot);
      if (exists) continue;

      const bundle = generateHintBundle(item.word, 5);
      bundle.sentence = item.sentence;
      const passwordInfo = {
        userId: 'U123',
        timeSlot: item.timeSlot,
        originalWord: item.word,
        generatedSentence: item.sentence,
        matrixConfig: JSON.stringify(bundle.matrixConfig),
        visualPattern: JSON.stringify(item.visualPattern),
        createdAt: new Date().toISOString()
      };

      const result = insertPassword.run(passwordInfo);
      const hints = buildHintLevels(bundle);
      hints.forEach((hint) => {
        insertHint.run({
          passwordId: result.lastInsertRowid,
          hintLevel: hint.hintLevel,
          revealedChars: hint.revealedChars,
          aiGeneratedSentence: hint.aiGeneratedSentence,
          matrixPositions: hint.matrixPositions,
          createdAt: new Date().toISOString()
        });
      });
    }
  });

  tx();
}

function getUser(userId) {
  return db.prepare('SELECT userId, name, createdAt FROM users WHERE userId = ?').get(userId);
}

function getPasswordByTimeSlot(userId, timeSlot) {
  return db
    .prepare(
      'SELECT id, userId, timeSlot, originalWord, generatedSentence, matrixConfig, visualPattern, createdAt FROM passwords WHERE userId = ? AND timeSlot = ?'
    )
    .get(userId, timeSlot);
}

function getAllPasswordsForUser(userId) {
  return db
    .prepare(
      'SELECT id, timeSlot, originalWord, generatedSentence, matrixConfig, visualPattern, createdAt FROM passwords WHERE userId = ? ORDER BY CASE timeSlot WHEN "morning" THEN 1 WHEN "evening" THEN 2 ELSE 3 END'
    )
    .all(userId);
}

function getHint(passwordId, hintLevel) {
  return db
    .prepare(
      'SELECT id, passwordId, hintLevel, revealedChars, aiGeneratedSentence, matrixPositions FROM hints WHERE passwordId = ? AND hintLevel = ?'
    )
    .get(passwordId, hintLevel);
}

function createPasswordWithHints({ userId, timeSlot, word, visualPattern, matrixSize = 5 }) {
  const bundle = generateHintBundle(word, matrixSize);

  const insertPassword = db.prepare(`
    INSERT INTO passwords (userId, timeSlot, originalWord, generatedSentence, matrixConfig, visualPattern, createdAt)
    VALUES (@userId, @timeSlot, @originalWord, @generatedSentence, @matrixConfig, @visualPattern, @createdAt)
    ON CONFLICT(userId, timeSlot) DO UPDATE SET
      originalWord = excluded.originalWord,
      generatedSentence = excluded.generatedSentence,
      matrixConfig = excluded.matrixConfig,
      visualPattern = excluded.visualPattern,
      createdAt = excluded.createdAt
  `);

  const removeHints = db.prepare('DELETE FROM hints WHERE passwordId = ?');
  const fetchPasswordId = db.prepare('SELECT id FROM passwords WHERE userId = ? AND timeSlot = ?');
  const insertHint = db.prepare(`
    INSERT INTO hints (passwordId, hintLevel, revealedChars, aiGeneratedSentence, matrixPositions, createdAt)
    VALUES (@passwordId, @hintLevel, @revealedChars, @aiGeneratedSentence, @matrixPositions, @createdAt)
  `);

  const tx = db.transaction(() => {
    insertPassword.run({
      userId,
      timeSlot,
      originalWord: bundle.word,
      generatedSentence: bundle.sentence,
      matrixConfig: JSON.stringify(bundle.matrixConfig),
      visualPattern: JSON.stringify(visualPattern),
      createdAt: new Date().toISOString()
    });

    const password = fetchPasswordId.get(userId, timeSlot);
    removeHints.run(password.id);

    buildHintLevels(bundle).forEach((hint) => {
      insertHint.run({
        passwordId: password.id,
        hintLevel: hint.hintLevel,
        revealedChars: hint.revealedChars,
        aiGeneratedSentence: hint.aiGeneratedSentence,
        matrixPositions: hint.matrixPositions,
        createdAt: new Date().toISOString()
      });
    });

    return password.id;
  });

  const passwordId = tx();
  return getPasswordWithHints(passwordId);
}

function getPasswordWithHints(passwordId) {
  const password = db
    .prepare(
      'SELECT id, userId, timeSlot, originalWord, generatedSentence, matrixConfig, visualPattern, createdAt FROM passwords WHERE id = ?'
    )
    .get(passwordId);
  if (!password) return null;

  const hints = db
    .prepare(
      'SELECT id, hintLevel, revealedChars, aiGeneratedSentence, matrixPositions FROM hints WHERE passwordId = ? ORDER BY hintLevel ASC'
    )
    .all(passwordId);

  return { password, hints };
}

function logAuth({ userId, timeSlot, success, method }) {
  db.prepare(
    'INSERT INTO auth_logs (userId, timeSlot, success, timestamp, method) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, timeSlot, success ? 1 : 0, new Date().toISOString(), method);
}

function getAuthLogs(userId, limit = 50) {
  return db
    .prepare(
      'SELECT id, userId, timeSlot, success, timestamp, method FROM auth_logs WHERE userId = ? ORDER BY timestamp DESC LIMIT ?'
    )
    .all(userId, limit);
}

function upsertCredential({ userId, credentialId, publicKey, counter, transports }) {
  db.prepare(`
    INSERT INTO webauthn_credentials (userId, credentialId, publicKey, counter, transports, createdAt)
    VALUES (@userId, @credentialId, @publicKey, @counter, @transports, @createdAt)
    ON CONFLICT(credentialId) DO UPDATE SET
      publicKey = excluded.publicKey,
      counter = excluded.counter,
      transports = excluded.transports
  `).run({
    userId,
    credentialId,
    publicKey,
    counter,
    transports: JSON.stringify(transports || []),
    createdAt: new Date().toISOString()
  });
}

function getCredentialsByUser(userId) {
  return db
    .prepare(
      'SELECT credentialId, publicKey, counter, transports FROM webauthn_credentials WHERE userId = ?'
    )
    .all(userId)
    .map((row) => ({ ...row, transports: JSON.parse(row.transports || '[]') }));
}

module.exports = {
  init,
  getUser,
  getPasswordByTimeSlot,
  getAllPasswordsForUser,
  getHint,
  createPasswordWithHints,
  getPasswordWithHints,
  logAuth,
  getAuthLogs,
  upsertCredential,
  getCredentialsByUser
};
