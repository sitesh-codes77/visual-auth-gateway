const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const db = require('./database');
const { generateHintBundle } = require('./ai-engine');

const SaaSPort = Number(process.env.PORT || 3000);
const BANK_PORT = Number(process.env.BANK_PORT || 8080);
const SESSION_TTL_MS = 60_000;

const RP_NAME = 'VisualAuth SaaS';
const RP_ID = process.env.RP_ID || 'localhost';
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || `http://localhost:${SaaSPort}`;

db.init();

const activeChallenges = new Map();

function slotFromDate(date = new Date()) {
  const hour = date.getHours();
  if (hour >= 6 && hour < 14) return 'morning';
  if (hour >= 14 && hour < 22) return 'evening';
  return 'night';
}

function validateUserId(userId) {
  return typeof userId === 'string' && /^[A-Za-z0-9_-]{2,32}$/.test(userId);
}

function sanitizePattern(input) {
  if (!Array.isArray(input) || input.length < 3 || input.length > 8) {
    throw new Error('visualPattern must be an emoji array with 3-8 items.');
  }
  return input.map((item) => String(item).trim()).filter(Boolean);
}

function parsePasswordRecord(password) {
  return {
    ...password,
    matrixConfig: JSON.parse(password.matrixConfig),
    visualPattern: JSON.parse(password.visualPattern)
  };
}

function createSaaSApp() {
  const app = express();
  app.use(
    cors({
      origin: ['http://localhost:8080', `http://localhost:${SaaSPort}`],
      credentials: true
    })
  );
  app.use(express.json({ limit: '500kb' }));
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'replace-me-for-production',
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: SESSION_TTL_MS,
        httpOnly: true,
        sameSite: 'lax'
      }
    })
  );
  app.use(express.static(path.join(__dirname, '../ui')));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'visualauth-saas' });
  });

  app.get('/api/time-slot', (req, res) => {
    const override = req.query.override;
    const allowed = ['morning', 'evening', 'night'];
    const timeSlot = allowed.includes(override) ? override : slotFromDate();
    res.json({
      timeSlot,
      windows: {
        morning: '06:00-14:00',
        evening: '14:00-22:00',
        night: '22:00-06:00'
      }
    });
  });

  app.post('/api/auth/start', (req, res) => {
    try {
      const userId = String(req.body.userId || '');
      const requestedSlot = req.body.timeSlot;
      if (!validateUserId(userId)) {
        return res.status(400).json({ error: 'Invalid userId format.' });
      }

      const user = db.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found.' });
      }

      const timeSlot = ['morning', 'evening', 'night'].includes(requestedSlot)
        ? requestedSlot
        : slotFromDate();
      const password = db.getPasswordByTimeSlot(userId, timeSlot);
      if (!password) {
        return res.status(404).json({ error: 'No password configured for this time slot.' });
      }

      const parsed = parsePasswordRecord(password);
      const challengeId = crypto.randomUUID();
      const expiresAt = Date.now() + SESSION_TTL_MS;

      req.session.authChallenge = {
        challengeId,
        userId,
        timeSlot,
        passwordId: parsed.id,
        attempts: 0,
        expiresAt
      };

      const hints = {
        level: 0,
        max: 3
      };

      res.json({
        challengeId,
        user: { userId: user.userId, name: user.name },
        timeSlot,
        expiresAt,
        visualPattern: parsed.visualPattern,
        sentence: parsed.generatedSentence,
        matrixSize: parsed.matrixConfig.size,
        hints
      });
    } catch (error) {
      return res.status(500).json({ error: 'Unable to start authentication flow.' });
    }
  });

  app.post('/api/auth/hint', (req, res) => {
    const challenge = req.session.authChallenge;
    if (!challenge) {
      return res.status(440).json({ error: 'Session expired. Start again.' });
    }
    if (Date.now() > challenge.expiresAt) {
      req.session.authChallenge = null;
      return res.status(440).json({ error: 'Challenge expired.' });
    }

    const requestedLevel = Number(req.body.hintLevel || 1);
    const safeLevel = Math.min(3, Math.max(1, requestedLevel));
    const hint = db.getHint(challenge.passwordId, safeLevel);
    if (!hint) {
      return res.status(404).json({ error: 'Hint not found.' });
    }

    res.json({
      hintLevel: hint.hintLevel,
      revealedChars: JSON.parse(hint.revealedChars),
      sentence: hint.aiGeneratedSentence,
      matrixPositions: JSON.parse(hint.matrixPositions)
    });
  });

  app.post('/api/auth/verify-visual', (req, res) => {
    const challenge = req.session.authChallenge;
    if (!challenge) return res.status(440).json({ error: 'Session expired. Start again.' });

    if (Date.now() > challenge.expiresAt) {
      req.session.authChallenge = null;
      return res.status(440).json({ error: 'Challenge expired.' });
    }

    const inputPattern = Array.isArray(req.body.pattern)
      ? req.body.pattern.map((item) => String(item).trim())
      : [];

    if (inputPattern.length === 0 || inputPattern.length > 8) {
      return res.status(400).json({ error: 'Invalid visual pattern submission.' });
    }

    const password = db.getPasswordByTimeSlot(challenge.userId, challenge.timeSlot);
    if (!password) return res.status(404).json({ error: 'Password not configured.' });

    const parsed = parsePasswordRecord(password);
    const expected = parsed.visualPattern;

    const isMatch =
      expected.length === inputPattern.length &&
      expected.every((emoji, idx) => emoji === inputPattern[idx]);

    db.logAuth({
      userId: challenge.userId,
      timeSlot: challenge.timeSlot,
      success: isMatch,
      method: 'visual'
    });

    if (isMatch) {
      req.session.authenticated = {
        userId: challenge.userId,
        timeSlot: challenge.timeSlot,
        method: 'visual',
        timestamp: new Date().toISOString()
      };
      req.session.authChallenge = null;
      return res.json({ success: true, redirectUrl: `http://localhost:${BANK_PORT}/dashboard.html?userId=${challenge.userId}` });
    }

    challenge.attempts += 1;
    if (challenge.attempts >= 5) {
      req.session.authChallenge = null;
      return res.status(429).json({ success: false, error: 'Maximum attempts reached. Restart flow.' });
    }

    return res.status(401).json({ success: false, error: 'Incorrect visual pattern.' });
  });

  app.post('/api/auth/webauthn/register/options', async (req, res) => {
    const userId = String(req.body.userId || '');
    if (!validateUserId(userId)) return res.status(400).json({ error: 'Invalid userId.' });

    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const existing = db.getCredentialsByUser(userId).map((cred) => ({
      id: cred.credentialId,
      type: 'public-key',
      transports: cred.transports
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: user.userId,
      userName: user.name,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: existing,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred'
      }
    });

    activeChallenges.set(`reg:${userId}`, options.challenge);
    res.json(options);
  });

  app.post('/api/auth/webauthn/register/verify', async (req, res) => {
    const userId = String(req.body.userId || '');
    const expectedChallenge = activeChallenges.get(`reg:${userId}`);
    if (!expectedChallenge) return res.status(400).json({ error: 'No pending registration challenge.' });

    try {
      const verification = await verifyRegistrationResponse({
        response: req.body.registrationResponse,
        expectedChallenge,
        expectedOrigin: EXPECTED_ORIGIN,
        expectedRPID: RP_ID
      });

      if (verification.verified && verification.registrationInfo) {
        const { credential } = verification.registrationInfo;
        db.upsertCredential({
          userId,
          credentialId: credential.id,
          publicKey: Buffer.from(credential.publicKey).toString('base64url'),
          counter: credential.counter,
          transports: credential.transports
        });
      }

      activeChallenges.delete(`reg:${userId}`);
      return res.json({ verified: verification.verified });
    } catch (error) {
      return res.status(400).json({ verified: false, error: 'Registration verification failed.' });
    }
  });

  app.post('/api/auth/webauthn/login/options', async (req, res) => {
    const userId = String(req.body.userId || '');
    if (!validateUserId(userId)) return res.status(400).json({ error: 'Invalid userId.' });

    const credentials = db.getCredentialsByUser(userId);
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials: credentials.map((cred) => ({
        id: cred.credentialId,
        type: 'public-key',
        transports: cred.transports
      }))
    });

    activeChallenges.set(`auth:${userId}`, options.challenge);
    res.json(options);
  });

  app.post('/api/auth/webauthn/login/verify', async (req, res) => {
    const userId = String(req.body.userId || '');
    const challenge = activeChallenges.get(`auth:${userId}`);
    if (!challenge) return res.status(400).json({ error: 'No pending authentication challenge.' });

    const credentials = db.getCredentialsByUser(userId);
    const authenticator = credentials.find((cred) => cred.credentialId === req.body.authenticationResponse?.id);
    if (!authenticator) return res.status(404).json({ error: 'Authenticator not found.' });

    try {
      const verification = await verifyAuthenticationResponse({
        response: req.body.authenticationResponse,
        expectedChallenge: challenge,
        expectedOrigin: EXPECTED_ORIGIN,
        expectedRPID: RP_ID,
        authenticator: {
          credentialID: authenticator.credentialId,
          credentialPublicKey: Buffer.from(authenticator.publicKey, 'base64url'),
          counter: authenticator.counter,
          transports: authenticator.transports
        }
      });

      db.logAuth({
        userId,
        timeSlot: slotFromDate(),
        success: verification.verified,
        method: 'webauthn'
      });

      activeChallenges.delete(`auth:${userId}`);
      return res.json({ verified: verification.verified });
    } catch (error) {
      return res.status(400).json({ verified: false, error: 'WebAuthn verification failed.' });
    }
  });

  app.post('/api/admin/password', (req, res) => {
    try {
      const userId = String(req.body.userId || '');
      const timeSlot = String(req.body.timeSlot || '');
      const word = String(req.body.word || '');
      const visualPattern = sanitizePattern(req.body.visualPattern || []);

      if (!validateUserId(userId)) return res.status(400).json({ error: 'Invalid userId.' });
      if (!['morning', 'evening', 'night'].includes(timeSlot)) {
        return res.status(400).json({ error: 'timeSlot must be morning/evening/night.' });
      }

      if (!db.getUser(userId)) {
        return res.status(404).json({ error: 'User not found.' });
      }

      const result = db.createPasswordWithHints({ userId, timeSlot, word, visualPattern });
      res.json({
        success: true,
        password: parsePasswordRecord(result.password),
        hints: result.hints.map((hint) => ({
          ...hint,
          revealedChars: JSON.parse(hint.revealedChars),
          matrixPositions: JSON.parse(hint.matrixPositions)
        }))
      });
    } catch (error) {
      res.status(400).json({ error: error.message || 'Unable to save password.' });
    }
  });

  app.get('/api/admin/passwords/:userId', (req, res) => {
    const { userId } = req.params;
    if (!validateUserId(userId)) return res.status(400).json({ error: 'Invalid userId.' });

    const passwords = db.getAllPasswordsForUser(userId).map((password) => parsePasswordRecord(password));
    res.json({ userId, passwords });
  });

  app.post('/api/admin/ai-preview', (req, res) => {
    try {
      const word = String(req.body.word || '');
      const matrixSize = Number(req.body.matrixSize || 5);
      const bundle = generateHintBundle(word, [5, 6].includes(matrixSize) ? matrixSize : 5);
      res.json(bundle);
    } catch (error) {
      res.status(400).json({ error: error.message || 'AI preview failed.' });
    }
  });

  app.get('/api/users/:userId/auth-logs', (req, res) => {
    const { userId } = req.params;
    if (!validateUserId(userId)) return res.status(400).json({ error: 'Invalid userId.' });

    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const logs = db.getAuthLogs(userId);
    res.json({ user, logs });
  });

  app.use((err, _req, res, _next) => {
    console.error('Unhandled SaaS error:', err);
    res.status(500).json({ error: 'Unexpected server error.' });
  });

  return app;
}

function createBankApp() {
  const app = express();
  app.use(express.json());
  app.use(express.static(path.join(__dirname, '../bank')));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'bank-client' });
  });

  app.get('/api/auth-history/:userId', (req, res) => {
    const userId = String(req.params.userId || '');
    if (!validateUserId(userId)) return res.status(400).json({ error: 'Invalid userId.' });

    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const logs = db.getAuthLogs(userId, 20);
    res.json({ user, logs });
  });

  return app;
}

const saasApp = createSaaSApp();
const bankApp = createBankApp();

saasApp.listen(SaaSPort, () => {
  console.log(`VisualAuth SaaS running on http://localhost:${SaaSPort}`);
});

bankApp.listen(BANK_PORT, () => {
  console.log(`Bank client running on http://localhost:${BANK_PORT}`);
});
