const state = {
  userId: 'U123',
  challengeId: null,
  timeSlot: null,
  selectedPattern: [],
  visualPattern: ['🌅', '🌞', '🌻', '🌇', '🌆', '🌉', '🌙', '⭐', '🌠'],
  hintLevel: 0,
  maxHintLevel: 3,
  timerHandle: null,
  expiresAt: 0,
  matrixSize: 5,
  revealedPositions: [],
  returnUrl: ''
};

const els = {
  authForm: document.getElementById('auth-form'),
  userId: document.getElementById('user-id'),
  timeSlotOverride: document.getElementById('time-slot-override'),
  status: document.getElementById('status'),
  challenge: document.getElementById('challenge'),
  slotIndicator: document.getElementById('slot-indicator'),
  sessionTimer: document.getElementById('session-timer'),
  patternPool: document.getElementById('pattern-pool'),
  selectedPattern: document.getElementById('selected-pattern'),
  clearPattern: document.getElementById('clear-pattern'),
  hintBtn: document.getElementById('hint-btn'),
  hintLevel: document.getElementById('hint-level'),
  hintSentence: document.getElementById('hint-sentence'),
  matrixCanvas: document.getElementById('matrix-canvas'),
  verifyVisual: document.getElementById('verify-visual'),
  registerPasskey: document.getElementById('register-passkey'),
  webauthnLogin: document.getElementById('webauthn-login'),
  faceId: document.getElementById('face-id'),
  loadPasswords: document.getElementById('load-passwords'),
  adminOutput: document.getElementById('admin-output')
};

function syncUserFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const fromQuery = (params.get('userId') || '').trim();
  const returnUrl = (params.get('returnUrl') || '').trim();
  if (fromQuery) {
    state.userId = fromQuery;
    els.userId.value = fromQuery;
  }

  if (returnUrl) {
    state.returnUrl = returnUrl;
  }
}

function setStatus(message, type = 'neutral') {
  els.status.textContent = message;
  els.status.classList.toggle('error', type === 'error');
  els.status.classList.toggle('success', type === 'success');
}

function shuffle(array) {
  let currentIndex = array.length;
  let randomIndex;
  while (currentIndex !== 0) {
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex -= 1;
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
  return array;
}

function drawMatrix(size, highlights = []) {
  const ctx = els.matrixCanvas.getContext('2d');
  const width = els.matrixCanvas.width;
  const height = els.matrixCanvas.height;
  const cell = width / size;
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789@$%*?';

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = '#0b1020';
  ctx.fillRect(0, 0, width, height);

  for (let row = 0; row < size; row += 1) {
    for (let col = 0; col < size; col += 1) {
      const x = col * cell;
      const y = row * cell;
      const isHighlight = highlights.some((item) => item.row === row && item.col === col);

      ctx.strokeStyle = '#2e3e65';
      ctx.strokeRect(x, y, cell, cell);

      if (isHighlight) {
        ctx.fillStyle = 'rgba(14, 165, 233, 0.28)';
        ctx.fillRect(x + 1, y + 1, cell - 2, cell - 2);
      }

      const highlightChar = highlights.find((item) => item.row === row && item.col === col)?.char;
      const char = highlightChar || chars[Math.floor(Math.random() * chars.length)];
      ctx.fillStyle = '#dbeafe';
      ctx.font = '600 18px Inter';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(char, x + cell / 2, y + cell / 2);
    }
  }
}

function startTimer() {
  if (state.timerHandle) clearInterval(state.timerHandle);
  state.timerHandle = setInterval(() => {
    const remainingMs = state.expiresAt - Date.now();
    if (remainingMs <= 0) {
      clearInterval(state.timerHandle);
      els.sessionTimer.textContent = 'expired';
      setStatus('Session expired. Start authentication again.', 'error');
      return;
    }
    els.sessionTimer.textContent = `${Math.ceil(remainingMs / 1000)}s`;
  }, 500);
}

function renderPatternPool() {
  els.patternPool.innerHTML = '';
  const pool = shuffle([...state.visualPattern]);

  pool.forEach((emoji) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'emoji-btn';
    btn.textContent = emoji;
    btn.setAttribute('aria-pressed', 'false');

    if (state.selectedPattern.length >= 3) {
      btn.disabled = true;
    }

    if (state.selectedPattern.includes(emoji)) {
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
    }

    btn.addEventListener('click', () => {
      if (state.selectedPattern.length >= 3) return;
      if (state.selectedPattern.includes(emoji)) return;

      state.selectedPattern.push(emoji);
      renderSelectedPattern();
      renderPatternPool();
    });
    els.patternPool.appendChild(btn);
  });
}

function renderSelectedPattern() {
  els.selectedPattern.innerHTML = '';
  state.selectedPattern.forEach((emoji, index) => {
    const chip = document.createElement('div');
    chip.className = 'emoji-pill';
    chip.textContent = emoji;
    chip.title = `Step ${index + 1}`;
    els.selectedPattern.appendChild(chip);
  });
}

function base64UrlToBuffer(base64url) {
  const padLength = (4 - (base64url.length % 4)) % 4;
  const base64 = (base64url + '='.repeat(padLength)).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function normalizeRegistrationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToBuffer(options.user.id)
    },
    excludeCredentials: (options.excludeCredentials || []).map((cred) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id)
    }))
  };
}

function normalizeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((cred) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id)
    }))
  };
}

function serializeCredential(rawCredential) {
  if (typeof rawCredential.toJSON === 'function') {
    return rawCredential.toJSON();
  }

  return {
    id: rawCredential.id,
    rawId: bufferToBase64Url(rawCredential.rawId),
    type: rawCredential.type,
    clientExtensionResults: rawCredential.getClientExtensionResults(),
    response: {
      attestationObject: rawCredential.response.attestationObject
        ? bufferToBase64Url(rawCredential.response.attestationObject)
        : undefined,
      authenticatorData: rawCredential.response.authenticatorData
        ? bufferToBase64Url(rawCredential.response.authenticatorData)
        : undefined,
      clientDataJSON: bufferToBase64Url(rawCredential.response.clientDataJSON),
      signature: rawCredential.response.signature
        ? bufferToBase64Url(rawCredential.response.signature)
        : undefined,
      userHandle: rawCredential.response.userHandle
        ? bufferToBase64Url(rawCredential.response.userHandle)
        : undefined,
      transports: typeof rawCredential.response.getTransports === 'function'
        ? rawCredential.response.getTransports()
        : undefined
    },
    authenticatorAttachment: rawCredential.authenticatorAttachment
  };
}

async function apiJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed with ${response.status}`);
  }
  return payload;
}

els.authForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  try {
    setStatus('Starting authentication...');
    state.userId = els.userId.value.trim();

    const payload = {
      userId: state.userId,
      timeSlot: els.timeSlotOverride.value || undefined,
      returnUrl: state.returnUrl || undefined
    };

    const data = await apiJson('/api/auth/start', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    state.challengeId = data.challengeId;
    state.timeSlot = data.timeSlot;
    state.selectedPattern = [];
    state.hintLevel = 0;
    state.maxHintLevel = data.hints.max;
    state.expiresAt = data.expiresAt;
    state.matrixSize = data.matrixSize;
    state.revealedPositions = [];

    els.slotIndicator.textContent = data.timeSlot.toUpperCase();
    els.hintSentence.textContent = data.sentence;
    els.hintLevel.textContent = `TRC Lvl: ${state.hintLevel}/${state.maxHintLevel}`;
    els.challenge.classList.remove('hidden');

    drawMatrix(state.matrixSize);
    renderPatternPool();
    renderSelectedPattern();
    startTimer();

    setStatus('Challenge active. Select visual pattern sequence (3 emojis).', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

els.clearPattern.addEventListener('click', () => {
  state.selectedPattern = [];
  renderSelectedPattern();
  renderPatternPool();
});

els.hintBtn.addEventListener('click', async () => {
  try {
    if (state.hintLevel >= state.maxHintLevel) {
      setStatus('Maximum hint level reached.');
      return;
    }

    const nextLevel = state.hintLevel + 1;
    const hint = await apiJson('/api/auth/hint', {
      method: 'POST',
      body: JSON.stringify({ hintLevel: nextLevel })
    });

    state.hintLevel = hint.hintLevel;
    state.revealedPositions = hint.matrixPositions || [];

    els.hintLevel.textContent = `Level ${state.hintLevel} / ${state.maxHintLevel}`;

    const reveal = (hint.revealedChars || []).join('');
    els.hintSentence.textContent = `${hint.sentence} ${reveal ? ` | Revealed: ${reveal}` : ''}`;

    drawMatrix(state.matrixSize, state.hintLevel >= 2 ? state.revealedPositions : []);
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

els.verifyVisual.addEventListener('click', async () => {
  try {
    if (state.selectedPattern.length < 3) {
      setStatus('Please select exactly 3 emojis.', 'error');
      return;
    }

    const data = await apiJson('/api/auth/verify-visual', {
      method: 'POST',
      body: JSON.stringify({ pattern: state.selectedPattern })
    });

    setStatus('Visual authentication successful. Redirecting to bank dashboard...', 'success');
    window.location.href = data.redirectUrl;
  } catch (error) {
    setStatus(error.message, 'error');
    state.selectedPattern = [];
    renderSelectedPattern();
    renderPatternPool();
  }
});

els.registerPasskey.addEventListener('click', async () => {
  if (!window.PublicKeyCredential) {
    setStatus('Passkeys are not supported in this browser.', 'error');
    return;
  }

  try {
    state.userId = els.userId.value.trim();
    setStatus('Preparing passkey registration. If you have an NFC keychain, choose Security Key.');

    const options = await apiJson('/api/auth/webauthn/register/options', {
      method: 'POST',
      body: JSON.stringify({
        userId: state.userId,
        authenticatorType: 'cross-platform'
      })
    });

    const credential = await navigator.credentials.create({
      publicKey: normalizeRegistrationOptions(options)
    });

    if (!credential) throw new Error('Passkey registration was cancelled.');

    const verify = await apiJson('/api/auth/webauthn/register/verify', {
      method: 'POST',
      body: JSON.stringify({
        userId: state.userId,
        registrationResponse: serializeCredential(credential)
      })
    });

    if (!verify.verified) throw new Error('Passkey registration could not be verified.');
    setStatus('Passkey registered successfully. Your NFC keychain can now be used for login.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

els.webauthnLogin.addEventListener('click', async () => {
  if (!window.PublicKeyCredential) {
    setStatus('WebAuthn not supported on this browser.', 'error');
    return;
  }

  try {
    state.userId = els.userId.value.trim();
    const options = await apiJson('/api/auth/webauthn/login/options', {
      method: 'POST',
      body: JSON.stringify({ userId: state.userId })
    });

    setStatus('Touch your passkey. For NFC keychain, tap it when your phone/browser prompts.');

    const assertion = await navigator.credentials.get({
      publicKey: normalizeAuthenticationOptions(options)
    });

    if (!assertion) throw new Error('Passkey login was cancelled.');

    const verification = await apiJson('/api/auth/webauthn/login/verify', {
      method: 'POST',
      body: JSON.stringify({
        userId: state.userId,
        authenticationResponse: serializeCredential(assertion)
      })
    });

    if (!verification.verified) {
      throw new Error('Passkey authentication failed.');
    }

    setStatus('Passkey verified. Redirecting...', 'success');
    const redirectUrl = state.returnUrl || `http://localhost:8080/dashboard.html?userId=${encodeURIComponent(state.userId)}`;
    setTimeout(() => {
      window.location.href = redirectUrl;
    }, 600);
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

els.faceId.addEventListener('click', async () => {
  if (!navigator.mediaDevices?.getUserMedia) {
    setStatus('Face ID demo unavailable in this browser.', 'error');
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    setStatus('Face ID demo camera check passed. Redirecting...', 'success');
    setTimeout(() => {
      stream.getTracks().forEach((track) => track.stop());
      window.location.href = `http://localhost:8080/dashboard.html?userId=${encodeURIComponent(state.userId)}`;
    }, 1200);
  } catch (_error) {
    setStatus('Camera access denied.', 'error');
  }
});

els.loadPasswords.addEventListener('click', async () => {
  try {
    const data = await apiJson(`/api/admin/passwords/${encodeURIComponent(state.userId || 'U123')}`);
    els.adminOutput.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

(async () => {
  syncUserFromQuery();

  try {
    const slotData = await apiJson('/api/time-slot');
    els.slotIndicator.textContent = slotData.timeSlot.toUpperCase();
    drawMatrix(5);
  } catch (_error) {
    drawMatrix(5);
  }
})();
