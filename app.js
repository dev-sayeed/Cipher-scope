/* =========================================================
   CIPHERSCOPE — CLIENT-SIDE CRYPTOGRAPHIC & ENTROPY ENGINE
   ========================================================= */

document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.getAttribute('data-page');

  if (page === 'analyzer') {
    initAnalyzerPage();
  } else if (page === 'generator') {
    initGeneratorPage();
  }
});

/* =========================================================
   1. SHARED ENTROPY & PATTERN HEURISTICS ENGINE
   ========================================================= */

const COMMON_WEAK_TOKENS = [
  'password', 'admin', 'welcome', 'qwerty', 'asdfgh', 'zxcvbn',
  '123456', '12345678', '111111', 'letmein', 'iloveyou', 'dragon',
  'master', 'monkey', 'shadow', 'sunshine', 'princess', 'football',
  'india', 'assam', 'google', 'login', 'secret', 'passw0rd'
];

const KEYBOARD_WALKS = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', '0987654321',
  'qazwsx', '1qaz2wsx', 'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz'
];

function analyzePassword(pwd) {
  const length = pwd.length;
  if (length === 0) {
    return {
      length: 0,
      poolSize: 0,
      hasLower: false,
      hasUpper: false,
      hasDigit: false,
      hasSymbol: false,
      rawEntropy: 0,
      effectiveEntropy: 0,
      combinations: '0',
      diagnostics: []
    };
  }

  // Detect active character sets
  const hasLower = /[a-z]/.test(pwd);
  const hasUpper = /[A-Z]/.test(pwd);
  const hasDigit = /[0-9]/.test(pwd);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pwd);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSymbol) poolSize += 33;

  // Raw Shannon Entropy: H = L * log2(N)
  const rawEntropy = length * Math.log2(poolSize || 1);

  // Heuristic Penalty Engine (Models real-world password cracker rules)
  let penaltyBits = 0;
  const diagnostics = [];
  const lowerPwd = pwd.toLowerCase();

  // Normalize basic leet-speak (e.g., P@ssw0rd -> password) for dictionary checks
  const deLeeted = lowerPwd
    .replace(/@/g, 'a')
    .replace(/4/g, 'a')
    .replace(/3/g, 'e')
    .replace(/1/g, 'i')
    .replace(/!/g, 'i')
    .replace(/0/g, 'o')
    .replace(/\$/g, 's')
    .replace(/5/g, 's')
    .replace(/7/g, 't');

  // Check 1: Dictionary / leaked word matches
  const matchedWord = COMMON_WEAK_TOKENS.find(
    (word) => lowerPwd.includes(word) || deLeeted.includes(word)
  );
  if (matchedWord) {
    penaltyBits += 26;
    diagnostics.push({
      level: 'danger',
      icon: '🚨',
      text: `Predictable dictionary or leaked token detected ("${matchedWord}") — even with symbol substitutions, rule-based crackers test this within seconds.`
    });
  }

  // Check 2: Keyboard walks
  const hasWalk = KEYBOARD_WALKS.some((row) => {
    for (let i = 0; i <= row.length - 4; i++) {
      const slice = row.slice(i, i + 4);
      if (lowerPwd.includes(slice)) return true;
    }
    return false;
  });
  if (hasWalk) {
    penaltyBits += 18;
    diagnostics.push({
      level: 'warn',
      icon: '⌨️',
      text: 'Adjacent keyboard walk detected (e.g., "qwer", "1234", "asdf"). Attackers prioritize spatial keyboard patterns early.'
    });
  }

  // Check 3: Repeated characters (e.g., "aaa" or "111")
  if (/(.)\1{2,}/.test(pwd)) {
    penaltyBits += 14;
    diagnostics.push({
      level: 'warn',
      icon: '🔁',
      text: 'Repeated character run detected (3+ identical characters in a row), reducing effective keyspace randomness.'
    });
  }

  // Check 4: Common years (1950–2039)
  if (/(19[5-9]\d|20[0-3]\d)/.test(pwd)) {
    penaltyBits += 12;
    diagnostics.push({
      level: 'warn',
      icon: '📅',
      text: 'Four-digit year pattern detected. Appending birth years or current years adds minimal security against targeted attacks.'
    });
  }

  // Check 5: Length guidance
  if (length < 12) {
    diagnostics.push({
      level: 'warn',
      icon: '📏',
      text: `Length is ${length} characters. Modern NIST and OWASP guidelines recommend at least 12–16 characters for high-value accounts.`
    });
  } else if (diagnostics.length === 0) {
    diagnostics.push({
      level: 'good',
      icon: '✅',
      text: 'Strong length and high character unpredictability. No common dictionary words, keyboard walks, or date patterns detected.'
    });
  }

  // Check 6: Multi-word passphrase recognition
  if (length >= 18 && (pwd.includes('-') || pwd.includes('_') || pwd.includes(' '))) {
    diagnostics.push({
      level: 'good',
      icon: '🛡️',
      text: 'Multi-segment passphrase structure detected — high entropy combined with strong human memorability.'
    });
  }

  const effectiveEntropy = Math.max(
    length > 0 ? 4 : 0,
    Math.round((rawEntropy - penaltyBits) * 10) / 10
  );

  // Format total keyspace combinations (2^effectiveEntropy)
  const combinations = formatLargeNumber(Math.pow(2, effectiveEntropy));

  return {
    length,
    poolSize,
    hasLower,
    hasUpper,
    hasDigit,
    hasSymbol,
    rawEntropy: Math.round(rawEntropy * 10) / 10,
    effectiveEntropy,
    combinations,
    diagnostics
  };
}

function formatLargeNumber(num) {
  if (!isFinite(num) || num > 1e33) return '> 10^33 (Astronomical)';
  if (num < 1e6) return Math.round(num).toLocaleString();
  const exp = Math.floor(Math.log10(num));
  const mantissa = (num / Math.pow(10, exp)).toFixed(2);
  return `${mantissa} × 10^${exp}`;
}

function formatDuration(seconds) {
  if (seconds < 0.001) return 'Instant (< 1 ms)';
  if (seconds < 1) return `${Math.round(seconds * 1000)} milliseconds`;
  if (seconds < 60) return `${seconds.toFixed(1)} seconds`;

  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} minutes`;

  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(1)} hours`;

  const days = hours / 24;
  if (days < 365) return `${Math.round(days)} days`;

  const years = days / 365.25;
  if (years < 1000) return `${Math.round(years).toLocaleString()} years`;
  if (years < 1e6) return `${(years / 1000).toFixed(1)} thousand years`;
  if (years < 1e9) return `${(years / 1e6).toFixed(1)} million years`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)} billion years`;
  return 'Trillions of years (Heat Death)';
}

/* =========================================================
   2. PAGE 1: LIVE ANALYZER CONTROLLER
   ========================================================= */

function initAnalyzerPage() {
  const input = document.getElementById('passwordInput');
  const toggleBtn = document.getElementById('toggleVisibilityBtn');
  const clearBtn = document.getElementById('clearInputBtn');

  const meterFill = document.getElementById('meterFill');
  const verdictEl = document.getElementById('strengthVerdict');
  const rawVsEffEl = document.getElementById('rawVsEffective');

  const pillLower = document.getElementById('pillLower');
  const pillUpper = document.getElementById('pillUpper');
  const pillDigit = document.getElementById('pillDigit');
  const pillSymbol = document.getElementById('pillSymbol');

  const metricEntropy = document.getElementById('metricEntropy');
  const metricPool = document.getElementById('metricPool');
  const metricLength = document.getElementById('metricLength');
  const metricCombinations = document.getElementById('metricCombinations');

  const timeOnline = document.getElementById('timeOnline');
  const timeCpu = document.getElementById('timeCpu');
  const timeGpu = document.getElementById('timeGpu');
  const timeCluster = document.getElementById('timeCluster');

  const diagnosticsList = document.getElementById('diagnosticsList');

  function updateUI() {
    const pwd = input.value;
    const res = analyzePassword(pwd);

    // Toggle character pills
    pillLower.classList.toggle('active', res.hasLower);
    pillUpper.classList.toggle('active', res.hasUpper);
    pillDigit.classList.toggle('active', res.hasDigit);
    pillSymbol.classList.toggle('active', res.hasSymbol);

    // Update Telemetry Cards
    metricEntropy.textContent = `${res.effectiveEntropy.toFixed(1)} bits`;
    metricPool.textContent = res.poolSize;
    metricLength.textContent = `${res.length} chars`;
    metricCombinations.textContent = res.combinations;
    rawVsEffEl.textContent = `Raw: ${res.rawEntropy.toFixed(1)} bits | Effective: ${res.effectiveEntropy.toFixed(1)} bits`;

    if (res.length === 0) {
      document.documentElement.style.setProperty('--state-color', '#06B6D4');
      document.documentElement.style.setProperty('--state-glow', 'rgba(6, 182, 212, 0.2)');
      meterFill.style.width = '0%';
      verdictEl.textContent = 'Awaiting Input';
      timeOnline.textContent = '—';
      timeCpu.textContent = '—';
      timeGpu.textContent = '—';
      timeCluster.textContent = '—';
      diagnosticsList.innerHTML = `
        <li class="diag-item">
          <span>ℹ️</span>
          <span>Enter a password above to run real-time pattern detection (keyboard walks, common years, repeated sequences, and leet-speak checks).</span>
        </li>`;
      return;
    }

    // Determine security tier & theme accent
    const bits = res.effectiveEntropy;
    let verdict = 'Critical / Weak';
    let color = '#EF4444';
    let glow = 'rgba(239, 68, 68, 0.22)';
    let pct = Math.min(100, Math.max(8, (bits / 110) * 100));

    if (bits >= 85) {
      verdict = 'Fortress Grade';
      color = '#10B981';
      glow = 'rgba(16, 185, 129, 0.22)';
    } else if (bits >= 60) {
      verdict = 'Strong';
      color = '#06B6D4';
      glow = 'rgba(6, 182, 212, 0.22)';
    } else if (bits >= 40) {
      verdict = 'Moderate / Fair';
      color = '#F59E0B';
      glow = 'rgba(245, 158, 11, 0.22)';
    }

    document.documentElement.style.setProperty('--state-color', color);
    document.documentElement.style.setProperty('--state-glow', glow);
    meterFill.style.width = `${pct}%`;
    verdictEl.textContent = verdict;

    // Average guesses = 50% of keyspace (2^(bits - 1))
    const avgGuesses = Math.pow(2, Math.max(0, bits - 1));
    timeOnline.textContent = formatDuration(avgGuesses / 100);          // 100/sec
    timeCpu.textContent = formatDuration(avgGuesses / 10000);           // 10K/sec (Argon2/bcrypt)
    timeGpu.textContent = formatDuration(avgGuesses / 100000000000);    // 100B/sec (8x RTX 4090)
    timeCluster.textContent = formatDuration(avgGuesses / 1e13);        // 10T/sec (Supercluster)

    // Render Diagnostics
    diagnosticsList.innerHTML = res.diagnostics
      .map(
        (d) => `
        <li class="diag-item ${d.level}">
          <span>${d.icon}</span>
          <span>${d.text}</span>
        </li>`
      )
      .join('');
  }

  input.addEventListener('input', updateUI);

  toggleBtn.addEventListener('click', () => {
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    toggleBtn.textContent = isHidden ? 'Hide' : 'Show';
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    updateUI();
    input.focus();
  });

  // Check if a password was sent over from the Generator page via URL hash
  if (window.location.hash && window.location.hash.startsWith('#audit=')) {
    const incoming = decodeURIComponent(window.location.hash.replace('#audit=', ''));
    input.value = incoming;
    input.type = 'text';
    toggleBtn.textContent = 'Hide';
    // Clean the URL hash immediately for privacy
    history.replaceState(null, '', window.location.pathname);
    updateUI();
  }
}

/* =========================================================
   3. PAGE 2: CRYPTOGRAPHIC GENERATOR CONTROLLER
   ========================================================= */

const EFF_SAMPLE_WORDS = [
  'anchor', 'aurora', 'beacon', 'breeze', 'canyon', 'cipher', 'cobalt', 'cosmos',
  'crimson', 'crystal', 'dagger', 'dynamo', 'eclipse', 'emerald', 'falcon', 'fjord',
  'fortress', 'galaxy', 'glacier', 'granite', 'harbor', 'horizon', 'impulse', 'ivory',
  'jasper', 'juniper', 'krypton', 'lantern', 'legend', 'magnet', 'marble', 'meteor',
  'mirage', 'monarch', 'nebula', 'neutron', 'obsidian', 'odyssey', 'onyx', 'oracle',
  'orbit', 'paladin', 'panther', 'paradox', 'phantom', 'phoenix', 'pioneer', 'plasma',
  'prism', 'pulsar', 'quantum', 'quartz', 'quasar', 'raven', 'reactor', 'redwood',
  'relic', 'ripple', 'saffron', 'sapphire', 'saturn', 'sentinel', 'shadow', 'sierra',
  'solstice', 'spectra', 'sphinx', 'stardust', 'summit', 'tempest', 'thistle', 'thunder',
  'titanium', 'topaz', 'torrent', 'trident', 'tundra', 'typhoon', 'valkyrie', 'vanguard',
  'velvet', 'vertex', 'vibrant', 'vortex', 'warden', 'wildfire', 'whisper', 'zenith'
];

// Unbiased cryptographically secure random integer in [0, max)
function secureRandomInt(max) {
  const array = new Uint32Array(1);
  const limit = Math.floor(0xffffffff / max) * max;
  let rand;
  do {
    window.crypto.getRandomValues(array);
    rand = array[0];
  } while (rand >= limit);
  return rand % max;
}

function initGeneratorPage() {
  // Random String Controls
  const randomOutput = document.getElementById('randomOutput');
  const genRandomEntropy = document.getElementById('genRandomEntropy');
  const lengthSlider = document.getElementById('lengthSlider');
  const lengthDisplay = document.getElementById('lengthDisplay');
  const chkUpper = document.getElementById('chkUpper');
  const chkLower = document.getElementById('chkLower');
  const chkNumbers = document.getElementById('chkNumbers');
  const chkSymbols = document.getElementById('chkSymbols');
  const chkNoAmbiguous = document.getElementById('chkNoAmbiguous');
  const generateRandomBtn = document.getElementById('generateRandomBtn');
  const copyRandomBtn = document.getElementById('copyRandomBtn');
  const analyzeRandomBtn = document.getElementById('analyzeRandomBtn');

  // Passphrase Controls
  const phraseOutput = document.getElementById('phraseOutput');
  const genPhraseEntropy = document.getElementById('genPhraseEntropy');
  const wordCountSlider = document.getElementById('wordCountSlider');
  const wordCountDisplay = document.getElementById('wordCountDisplay');
  const chkCapitalize = document.getElementById('chkCapitalize');
  const chkAddNumber = document.getElementById('chkAddNumber');
  const generatePhraseBtn = document.getElementById('generatePhraseBtn');
  const copyPhraseBtn = document.getElementById('copyPhraseBtn');
  const analyzePhraseBtn = document.getElementById('analyzePhraseBtn');

  function buildRandomPassword() {
    const len = parseInt(lengthSlider.value, 10);
    lengthDisplay.textContent = `${len} chars`;

    let upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let lower = 'abcdefghijklmnopqrstuvwxyz';
    let nums = '0123456789';
    let syms = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    if (chkNoAmbiguous.checked) {
      upper = upper.replace(/[OI]/g, '');
      lower = lower.replace(/[l]/g, '');
      nums = nums.replace(/[01]/g, '');
    }

    let pool = '';
    if (chkUpper.checked) pool += upper;
    if (chkLower.checked) pool += lower;
    if (chkNumbers.checked) pool += nums;
    if (chkSymbols.checked) pool += syms;

    if (!pool) {
      chkLower.checked = true;
      pool = lower;
    }

    let result = '';
    for (let i = 0; i < len; i++) {
      result += pool[secureRandomInt(pool.length)];
    }

    randomOutput.value = result;
    const entropy = Math.round(len * Math.log2(pool.length));
    genRandomEntropy.textContent = `~${entropy} bits`;
  }

  function buildPassphrase() {
    const count = parseInt(wordCountSlider.value, 10);
    wordCountDisplay.textContent = `${count} words`;

    const chosen = [];
    for (let i = 0; i < count; i++) {
      let word = EFF_SAMPLE_WORDS[secureRandomInt(EFF_SAMPLE_WORDS.length)];
      if (chkCapitalize.checked) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      chosen.push(word);
    }

    let phrase = chosen.join('-');
    let entropy = Math.round(count * Math.log2(EFF_SAMPLE_WORDS.length));

    if (chkAddNumber.checked) {
      const salt = secureRandomInt(90) + 10; // 10–99
      phrase += `-${salt}`;
      entropy += 7;
    }

    phraseOutput.value = phrase;
    genPhraseEntropy.textContent = `~${entropy} bits`;
  }

  function copyWithFeedback(inputEl, btnEl) {
    navigator.clipboard.writeText(inputEl.value).then(() => {
      const orig = btnEl.textContent;
      btnEl.textContent = 'Copied!';
      setTimeout(() => (btnEl.textContent = orig), 1400);
    });
  }

  // Event Listeners
  lengthSlider.addEventListener('input', buildRandomPassword);
  [chkUpper, chkLower, chkNumbers, chkSymbols, chkNoAmbiguous].forEach((el) =>
    el.addEventListener('change', buildRandomPassword)
  );
  generateRandomBtn.addEventListener('click', buildRandomPassword);
  copyRandomBtn.addEventListener('click', () => copyWithFeedback(randomOutput, copyRandomBtn));
  analyzeRandomBtn.addEventListener('click', () => {
    window.location.href = `index.html#audit=${encodeURIComponent(randomOutput.value)}`;
  });

  wordCountSlider.addEventListener('input', buildPassphrase);
  [chkCapitalize, chkAddNumber].forEach((el) =>
    el.addEventListener('change', buildPassphrase)
  );
  generatePhraseBtn.addEventListener('click', buildPassphrase);
  copyPhraseBtn.addEventListener('click', () => copyWithFeedback(phraseOutput, copyPhraseBtn));
  analyzePhraseBtn.addEventListener('click', () => {
    window.location.href = `index.html#audit=${encodeURIComponent(phraseOutput.value)}`;
  });

  // Initial generation on load
  buildRandomPassword();
  buildPassphrase();
}