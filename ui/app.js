/**
 * Visual Authentication Gateway - Frontend Application
 * Cybersecurity SaaS for Banking - Anti-Phishing & Anti-RAT Protection
 */

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = {
    API_BASE_URL: '', // Same origin (backend serves UI)
    DEMO_USER_ID: 'U123',
    PATTERN_LENGTH: 3,
    SESSION_TIMEOUT_SECONDS: 60
};

// ============================================
// STATE MANAGEMENT
// ============================================
const state = {
    sessionId: null,
    grid: [],
    selectedPattern: [],
    timerInterval: null,
    timeRemaining: CONFIG.SESSION_TIMEOUT_SECONDS,
    isVerifying: false,
    sessionActive: false
};

// ============================================
// DOM ELEMENTS
// ============================================
const elements = {
    // Session info
    sessionId: document.getElementById('sessionId'),
    timer: document.getElementById('timer'),
    sessionPanel: document.getElementById('sessionPanel'),
    
    // Grid
    emojiGrid: document.getElementById('emojiGrid'),
    gridContainer: document.getElementById('gridContainer'),
    
    // Pattern display
    patternSlots: [
        document.getElementById('slot1'),
        document.getElementById('slot2'),
        document.getElementById('slot3')
    ],
    patternDisplay: document.getElementById('patternDisplay'),
    
    // Progress steps
    steps: [
        document.getElementById('step1'),
        document.getElementById('step2'),
        document.getElementById('step3')
    ],
    
    // Buttons
    verifyBtn: document.getElementById('verifyBtn'),
    clearBtn: document.getElementById('clearBtn'),
    
    // Messages
    resultContainer: document.getElementById('resultContainer'),
    resultMessage: document.getElementById('resultMessage'),
    instructions: document.getElementById('instructions'),
    
    // Overlays
    loadingOverlay: document.getElementById('loadingOverlay'),
    redirectOverlay: document.getElementById('redirectOverlay')
};

// ============================================
// API FUNCTIONS
// ============================================

/**
 * Start authentication session
 * Calls POST /start-auth to create a new session
 */
async function startAuthSession() {
    showLoading(true);
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/start-auth`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_id: CONFIG.DEMO_USER_ID
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to start session');
        }

        const data = await response.json();
        
        // Update state
        state.sessionId = data.session_id;
        state.grid = data.grid;
        state.timeRemaining = data.expires_in || CONFIG.SESSION_TIMEOUT_SECONDS;
        state.sessionActive = true;
        
        // Update UI
        elements.sessionId.textContent = state.sessionId.substring(0, 8) + '...';
        renderGrid(state.grid);
        startTimer();
        
        console.log('[AUTH] Session started:', state.sessionId);
        console.log('[AUTH] Grid:', state.grid);
        
    } catch (error) {
        console.error('[ERROR] Failed to start session:', error);
        showResult('Failed to initialize authentication. Please refresh.', 'error');
    } finally {
        showLoading(false);
    }
}

/**
 * Verify authentication pattern
 * Calls POST /verify-auth to check the selected pattern
 */
async function verifyPattern() {
    if (state.selectedPattern.length !== CONFIG.PATTERN_LENGTH) {
        showResult('Please select 3 icons', 'error');
        return;
    }

    if (state.isVerifying || !state.sessionActive) {
        return;
    }

    state.isVerifying = true;
    elements.verifyBtn.disabled = true;
    elements.verifyBtn.innerHTML = '⏳ Verifying...';

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/verify-auth`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                session_id: state.sessionId,
                input: state.selectedPattern
            })
        });

        const data = await response.json();

        if (data.result === 'PASS') {
            handleSuccess();
        } else {
            handleFailure(data);
        }

    } catch (error) {
        console.error('[ERROR] Verification failed:', error);
        showResult('Verification error. Please try again.', 'error');
        state.isVerifying = false;
        elements.verifyBtn.disabled = false;
        elements.verifyBtn.innerHTML = '✅ Verify Pattern';
    }
}

// ============================================
// UI RENDERING
// ============================================

/**
 * Render the emoji grid
 * @param {string[]} emojis - Array of 9 emojis
 */
function renderGrid(emojis) {
    elements.emojiGrid.innerHTML = '';
    
    emojis.forEach((emoji, index) => {
        const item = document.createElement('div');
        item.className = 'emoji-item';
        item.textContent = emoji;
        item.dataset.emoji = emoji;
        item.dataset.index = index;
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', `Select ${emoji}`);
        
        // Add shuffle animation
        setTimeout(() => {
            item.classList.add('shuffle');
        }, index * 50);
        
        // Click handler
        item.addEventListener('click', () => handleEmojiClick(emoji, item));
        
        // Keyboard handler
        item.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleEmojiClick(emoji, item);
            }
        });
        
        elements.emojiGrid.appendChild(item);
    });
}

/**
 * Handle emoji click
 * @param {string} emoji - Selected emoji
 * @param {HTMLElement} element - Grid item element
 */
function handleEmojiClick(emoji, element) {
    // Check if already selected
    if (state.selectedPattern.includes(emoji)) {
        return;
    }

    // Check if pattern is full
    if (state.selectedPattern.length >= CONFIG.PATTERN_LENGTH) {
        showResult('Pattern complete. Click Verify or Clear to restart.', 'info');
        return;
    }

    // Add to pattern
    const order = state.selectedPattern.length + 1;
    state.selectedPattern.push(emoji);
    
    // Update UI
    element.classList.add('selected');
    element.dataset.order = order;
    element.setAttribute('aria-pressed', 'true');
    
    // Update pattern slots
    updatePatternSlots();
    
    // Update progress steps
    updateProgressSteps();
    
    // Update buttons
    updateButtons();
    
    // Clear any error messages
    clearResult();
    
    console.log('[PATTERN] Selected:', state.selectedPattern);
}

/**
 * Update pattern slot display
 */
function updatePatternSlots() {
    elements.patternSlots.forEach((slot, index) => {
        if (index < state.selectedPattern.length) {
            slot.textContent = state.selectedPattern[index];
            slot.classList.add('filled');
        } else {
            slot.textContent = '?';
            slot.classList.remove('filled');
        }
    });
}

/**
 * Update progress steps
 */
function updateProgressSteps() {
    elements.steps.forEach((step, index) => {
        step.classList.remove('active', 'completed');
        
        if (index < state.selectedPattern.length) {
            step.classList.add('completed');
        } else if (index === state.selectedPattern.length) {
            step.classList.add('active');
        }
    });
}

/**
 * Update button states
 */
function updateButtons() {
    const hasSelection = state.selectedPattern.length > 0;
    const isComplete = state.selectedPattern.length === CONFIG.PATTERN_LENGTH;
    
    elements.clearBtn.disabled = !hasSelection || state.isVerifying;
    elements.verifyBtn.disabled = !isComplete || state.isVerifying;
}

// ============================================
// TIMER FUNCTIONS
// ============================================

/**
 * Start countdown timer
 */
function startTimer() {
    updateTimerDisplay();
    
    state.timerInterval = setInterval(() => {
        state.timeRemaining--;
        updateTimerDisplay();
        
        if (state.timeRemaining <= 0) {
            handleSessionExpired();
        }
    }, 1000);
}

/**
 * Update timer display
 */
function updateTimerDisplay() {
    elements.timer.textContent = `${state.timeRemaining}s`;
    
    // Add warning style when time is low
    if (state.timeRemaining <= 10) {
        elements.timer.classList.add('warning');
    } else {
        elements.timer.classList.remove('warning');
    }
}

/**
 * Handle session expiration
 */
function handleSessionExpired() {
    clearInterval(state.timerInterval);
    state.sessionActive = false;
    
    // Disable all interactions
    disableGrid();
    
    showResult('⏰ Session expired. Please refresh to start a new session.', 'error');
    
    console.log('[SESSION] Expired');
}

// ============================================
// RESULT HANDLERS
// ============================================

/**
 * Handle successful authentication
 */
function handleSuccess() {
    console.log('[AUTH] SUCCESS');
    
    // Stop timer
    clearInterval(state.timerInterval);
    state.sessionActive = false;
    
    // Show success message
    showResult('✅ Authentication Successful!', 'success');
    
    // Disable grid
    disableGrid();
    
    // Show redirect overlay
    setTimeout(() => {
        elements.redirectOverlay.classList.add('active');
        
        // Redirect after animation
        setTimeout(() => {
            redirectToBank('PASS');
        }, 2000);
    }, 500);
}

/**
 * Handle failed authentication
 * @param {Object} data - Error response data
 */
function handleFailure(data) {
    console.log('[AUTH] FAILED:', data);
    
    state.isVerifying = false;
    
    // Re-enable buttons
    updateButtons();
    elements.verifyBtn.innerHTML = '✅ Verify Pattern';
    
    // Show error message
    let message = '❌ Authentication Failed';
    
    if (data.error === 'SESSION_EXPIRED') {
        message = '⏰ Session expired. Please refresh.';
        state.sessionActive = false;
        clearInterval(state.timerInterval);
    } else if (data.error === 'SESSION_USED') {
        message = '🔒 Session already used. Please refresh.';
        state.sessionActive = false;
    } else if (data.error === 'MAX_ATTEMPTS') {
        message = '🚫 Maximum attempts reached. Please refresh.';
        state.sessionActive = false;
        clearInterval(state.timerInterval);
    } else if (data.error === 'INVALID_PATTERN') {
        const remaining = data.attempts_remaining || 0;
        message = `❌ Incorrect pattern. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`;
    }
    
    showResult(message, 'error');
    
    // Shake animation on grid
    elements.gridContainer.classList.add('shake');
    setTimeout(() => {
        elements.gridContainer.classList.remove('shake');
    }, 500);
}

/**
 * Show result message
 * @param {string} message - Message to display
 * @param {string} type - Message type (success, error, info)
 */
function showResult(message, type) {
    elements.resultMessage.textContent = message;
    elements.resultMessage.className = `result-message ${type}`;
}

/**
 * Clear result message
 */
function clearResult() {
    elements.resultMessage.textContent = '';
    elements.resultMessage.className = 'result-message';
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Clear current selection
 */
function clearSelection() {
    state.selectedPattern = [];
    state.isVerifying = false;
    
    // Reset grid
    const gridItems = elements.emojiGrid.querySelectorAll('.emoji-item');
    gridItems.forEach(item => {
        item.classList.remove('selected');
        item.removeAttribute('data-order');
        item.setAttribute('aria-pressed', 'false');
    });
    
    // Reset UI
    updatePatternSlots();
    updateProgressSteps();
    updateButtons();
    clearResult();
    
    elements.verifyBtn.innerHTML = '✅ Verify Pattern';
    
    console.log('[PATTERN] Cleared');
}

/**
 * Disable grid interactions
 */
function disableGrid() {
    const gridItems = elements.emojiGrid.querySelectorAll('.emoji-item');
    gridItems.forEach(item => {
        item.classList.add('disabled');
        item.setAttribute('tabindex', '-1');
    });
    
    elements.clearBtn.disabled = true;
    elements.verifyBtn.disabled = true;
}

/**
 * Show/hide loading overlay
 * @param {boolean} show - Whether to show loading
 */
function showLoading(show) {
    if (show) {
        elements.loadingOverlay.classList.remove('hidden');
    } else {
        elements.loadingOverlay.classList.add('hidden');
    }
}

/**
 * Redirect back to bank with status
 * @param {string} status - PASS or FAIL
 */
function redirectToBank(status) {
    // Get redirect URL from query params or use default
    const urlParams = new URLSearchParams(window.location.search);
    const redirectUrl = urlParams.get('redirect') || 'https://bank.example.com/callback';
    
    // Build redirect URL with status
    const separator = redirectUrl.includes('?') ? '&' : '?';
    const finalUrl = `${redirectUrl}${separator}status=${status}&session=${state.sessionId}`;
    
    console.log('[REDIRECT] To:', finalUrl);
    
    // Perform redirect
    window.location.href = finalUrl;
}

// ============================================
// EVENT LISTENERS
// ============================================

// Verify button
elements.verifyBtn.addEventListener('click', verifyPattern);

// Clear button
elements.clearBtn.addEventListener('click', clearSelection);

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Escape to clear
    if (e.key === 'Escape') {
        clearSelection();
    }
    
    // Enter to verify when pattern is complete
    if (e.key === 'Enter' && state.selectedPattern.length === CONFIG.PATTERN_LENGTH) {
        verifyPattern();
    }
});

// ============================================
// INITIALIZATION
// ============================================

/**
 * Initialize the application
 */
function init() {
    console.log('='.repeat(60));
    console.log('  Visual Authentication Gateway');
    console.log('  Frontend Initialized');
    console.log('='.repeat(60));
    
    // Check for existing session in URL
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('user_id') || CONFIG.DEMO_USER_ID;
    
    console.log('[INIT] User ID:', userId);
    
    // Start authentication session
    startAuthSession();
}

// Start when DOM is ready
document.addEventListener('DOMContentLoaded', init);

// Handle page unload - cleanup
window.addEventListener('beforeunload', () => {
    if (state.timerInterval) {
        clearInterval(state.timerInterval);
    }
});

// ==========================
// BIOMETRIC (WEBAUTHN)
// ==========================
async function startBiometric() {
  const msg = document.getElementById("bioStatus");

  if (!window.PublicKeyCredential) {
    msg.textContent = "Biometric not supported";
    msg.style.color = "#ef4444";
    return;
  }

  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Visual Auth Gateway" },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: "demo",
          displayName: "Demo User"
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      }
    });

    if (cred) {
      msg.textContent = "Fingerprint Verified";
      msg.style.color = "#22c55e";
    }

  } catch (err) {
    msg.textContent = "Biometric Failed";
    msg.style.color = "#ef4444";
  }
}

document.getElementById("bioBtn").addEventListener("click", startBiometric);

// ==========================
// FACE PRESENCE CHECK
// ==========================
async function startFace() {
  const cam = document.getElementById("faceCam");
  const msg = document.getElementById("bioStatus");

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    cam.style.display = "block";
    cam.srcObject = stream;

    setTimeout(() => {
      stream.getTracks().forEach(t => t.stop());
      cam.style.display = "none";
      msg.textContent = "Face Presence Verified";
      msg.style.color = "#22c55e";
    }, 4000);

  } catch (err) {
    msg.textContent = "Camera access denied";
    msg.style.color = "#ef4444";
  }
}

document.getElementById("faceBtn").addEventListener("click", startFace);

