/**
 * Sentinel AI — Frontend Application Logic
 * Premium Apple-Style Dashboard
 */

// ─── DOM References ────────────────────────────────────────────
const appContainer = document.getElementById('appContainer');
const splashScreen = document.getElementById('splashScreen');
const splashBar = document.getElementById('splashBar');
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const removeFileBtn = document.getElementById('removeFileBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const progressSection = document.getElementById('progressSection');
const progressBar = document.getElementById('progressBar');
const progressTitle = document.getElementById('progressTitle');
const resultsSection = document.getElementById('resultsSection');
const uploadSection = document.getElementById('uploadSection');
const newScanBtn = document.getElementById('newScanBtn');
const exportPdfBtn = document.getElementById('exportPdfBtn');
const historyList = document.getElementById('historyList');

let selectedFile = null;
let lastResult = null;
let scanHistory = [];

// ─── Logical Threat Mapping (Enterprise Grade) ─────────────────
// Highly professional mitigation logic for standard opcodes
const FEATURE_EXPLANATIONS = {
  "INT 0x80": {
    desc: "System Call Invocation: Explicit kernel trap observed.",
    risk: "High Risk — Direct kernel interaction bypasses standardized libc protections, often indicating shellcode execution or obfuscated logic.",
    mitigation: "Ensure execution policies (e.g., DEP/NX) are enforced. Review source code for unsafe inline assembly.",
    cwe: "CWE-284: Improper Access Control"
  },
  "SYSCALL": {
    desc: "Direct Kernel Mode Invocation.",
    risk: "Critical Risk — Bypasses standard user-space APIs. Commonly utilized in advanced payload drops to evade user-land hooking and EDR detection.",
    mitigation: "Implement seccomp-bpf filters to restrict anomalous system calls.",
    cwe: "CWE-693: Protection Mechanism Failure"
  },
  "JMP ESP": {
    desc: "Stack Pointer Execution Control.",
    risk: "Critical Risk — Classic Return-Oriented Programming (ROP) or buffer overflow pivot instruction.",
    mitigation: "Recompile binary with Address Space Layout Randomization (ASLR) and Stack Canaries.",
    cwe: "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer"
  },
  "POP EAX": {
    desc: "Register Manipulation (Potential ROP Gadget).",
    risk: "Medium Risk — When clustered heavily, indicates potential ROP chain setup for arbitrary execution.",
    mitigation: "Enable Control Flow Guard (CFG) during compilation.",
    cwe: "CWE-693: Protection Mechanism Failure"
  },
  "XOR EAX,EAX": {
    desc: "Register Zeroing.",
    risk: "Low-Medium Risk — Often used by polymorphic malware to evade null-byte detection in signature scans.",
    mitigation: "Analyze surrounding context for shellcode signatures.",
    cwe: "CWE-654: Reliance on Magic Numbers"
  },
  "PUSH RBP": {
    desc: "Stack Frame Initialization.",
    risk: "Low Risk — Standard prologue behavior, but anomalous when interspersed dynamically.",
    mitigation: "Standard behavior unless part of a malicious hook.",
    cwe: "None"
  },
  "CALL EAX": {
    desc: "Indirect Function Execution.",
    risk: "High Risk — Executing addresses derived from registers implies dynamically loaded, potentially attacker-controlled payloads.",
    mitigation: "Implement strict Control Flow Integrity (CFI).",
    cwe: "CWE-824: Access of Uninitialized Pointer"
  },
  "RET": {
    desc: "Instruction Return Pivot.",
    risk: "Medium Risk — Anomalous frequency indicates potential exploitation via Return-Oriented Programming (ROP).",
    mitigation: "Recompile with Stack-Smashing Protections (SSP).",
    cwe: "CWE-119: Improper Restriction of Operations"
  }
};

// ─── Initialize ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  runSplashScreen();
  loadSystemStats();
  setupDragAndDrop();
  setupEventListeners();
  loadHistory();
  setupTabs();
  initScrollReveal();
  setupThemeToggle();
});

// ─── Theme Toggle ──────────────────────────────────────────────
function setupThemeToggle() {
  const toggleBtn = document.getElementById('themeToggle');
  if (!toggleBtn) return;

  const savedTheme = localStorage.getItem('sentinelTheme');
  if (savedTheme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  }

  toggleBtn.addEventListener('click', () => {
    if (document.documentElement.getAttribute('data-theme') === 'dark') {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('sentinelTheme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('sentinelTheme', 'dark');
    }
  });
}

// ─── Splash Screen & Names Logic ───────────────────────────────
function runSplashScreen() {
  const names = ['name1', 'name2', 'name3', 'name4', 'name5'];
  let currentNameIdx = 0;

  // Animate names one by one
  function showNextName() {
    if (currentNameIdx > 0) {
      document.getElementById(names[currentNameIdx - 1]).classList.remove('visible');
      document.getElementById(names[currentNameIdx - 1]).classList.add('fade-out');
    }

    if (currentNameIdx < names.length) {
      const el = document.getElementById(names[currentNameIdx]);
      el.classList.add('visible');
      currentNameIdx++;
      setTimeout(showNextName, 700);
    } else {
      // Show supervisor
      const sup = document.getElementById('supervisor');
      sup.style.opacity = '1';
      setTimeout(() => { finishSplash(); }, 1500);
    }
  }

  // Start progress bar and name animation
  let progress = 0;
  const interval = setInterval(() => {
    progress += 2;
    if (progress > 100) progress = 100;
    splashBar.style.width = progress + '%';
    if (progress === 100) clearInterval(interval);
  }, 70);

  setTimeout(showNextName, 500);
}

function finishSplash() {
  splashScreen.style.opacity = '0';
  splashScreen.style.visibility = 'hidden';
  appContainer.style.display = 'block';
  setTimeout(() => appContainer.style.opacity = '1', 50);
  setTimeout(() => window.dispatchEvent(new Event('scroll')), 200);
}

// ─── Scroll Reveal ─────────────────────────────────────────────
function initScrollReveal() {
  const reveals = document.querySelectorAll('.reveal');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('active');
      }
    });
  }, { threshold: 0.1, rootMargin: "0px 0px -50px 0px" });

  reveals.forEach(r => observer.observe(r));
}

// ─── Tab Navigation ────────────────────────────────────────────
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = 'tab-' + btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      document.getElementById(targetId).classList.add('active');

      setTimeout(() => window.dispatchEvent(new Event('scroll')), 100);
    });
  });
}

// ─── Load System Stats ─────────────────────────────────────────
async function loadSystemStats() {
  try {
    const healthRes = await fetch('/health');
    const health = await healthRes.json();
    document.getElementById('statStatus').textContent = health.model_loaded ? 'Active' : 'Offline';

    const metaRes = await fetch('/model-info');
    if (metaRes.ok) {
      const meta = await metaRes.json();
      document.getElementById('statAccuracy').textContent = (meta.accuracy * 100).toFixed(1) + '%';
      document.getElementById('statSamples').textContent = meta.total_samples.toLocaleString();
      document.getElementById('statTrees').textContent = meta.n_estimators.toLocaleString();
    }
  } catch (e) {
    document.getElementById('statStatus').textContent = 'Error';
  }
}

// ─── Drag & Drop ───────────────────────────────────────────────
function setupDragAndDrop() {
  ['dragenter', 'dragover'].forEach(event => {
    uploadZone.addEventListener(event, (e) => {
      e.preventDefault(); e.stopPropagation();
      uploadZone.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(event => {
    uploadZone.addEventListener(event, (e) => {
      e.preventDefault(); e.stopPropagation();
      uploadZone.classList.remove('drag-over');
    });
  });
  uploadZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFileSelection(files[0]);
  });
  uploadZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) handleFileSelection(e.target.files[0]);
  });
}

// ─── Event Listeners ───────────────────────────────────────────
function setupEventListeners() {
  removeFileBtn.addEventListener('click', clearFile);
  analyzeBtn.addEventListener('click', startAnalysis);
  newScanBtn.addEventListener('click', resetUI);
  if (exportPdfBtn) exportPdfBtn.addEventListener('click', exportToPdf);
}

// ─── File Selection ────────────────────────────────────────────
function handleFileSelection(file) {
  const allowedExt = ['.exe', '.o', '.elf', '.dll', '.so', '.bin'];
  const ext = '.' + file.name.split('.').pop().toLowerCase();

  if (!allowedExt.includes(ext)) {
    alert('Invalid file type. Only binary executables are accepted.');
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    alert('File too large. Maximum size is 50 MB.');
    return;
  }

  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatFileSize(file.size);
  fileInfo.classList.add('visible');
  analyzeBtn.classList.add('visible');
  analyzeBtn.disabled = false;
}

function clearFile() {
  selectedFile = null;
  try { fileInput.value = ''; } catch (e) { }
  try { fileInput.value = null; } catch (e) { }
  fileInfo.classList.remove('visible');
  analyzeBtn.classList.remove('visible');
  analyzeBtn.disabled = true;
}

// ─── Analysis Pipeline ────────────────────────────────────────
async function startAnalysis() {
  if (!selectedFile) return;

  analyzeBtn.disabled = true;
  analyzeBtn.querySelector('span').textContent = 'Analyzing...';
  uploadSection.style.display = 'none';
  resultsSection.classList.remove('visible');
  progressSection.classList.add('visible');

  animateProgress();

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const response = await fetch('/analyze', { method: 'POST', body: formData });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail?.message || data.detail || 'Unknown error');
    }

    lastResult = data;
    completeProgress();

    setTimeout(() => {
      progressSection.classList.remove('visible');
      displayResults(data);
      addToHistory(data);
    }, 800);

  } catch (error) {
    progressSection.classList.remove('visible');
    uploadSection.style.display = 'block';
    analyzeBtn.disabled = false;
    analyzeBtn.querySelector('span').textContent = 'Start Analysis';
    alert("Error: " + error.message);
  }
}

// ─── Progress Animation ───────────────────────────────────────
function animateProgress() {
  const steps = [
    { id: 'step1', progress: 15, delay: 0 },
    { id: 'step2', progress: 50, delay: 1500 },
    { id: 'step3', progress: 80, delay: 3000 },
    { id: 'step4', progress: 90, delay: 4000 },
  ];

  steps.forEach(s => document.getElementById(s.id).classList.remove('active', 'done'));
  progressBar.style.width = '0%';

  steps.forEach((step, index) => {
    setTimeout(() => {
      for (let i = 0; i < index; i++) {
        const prevEl = document.getElementById(steps[i].id);
        prevEl.classList.remove('active');
        prevEl.classList.add('done');
        prevEl.querySelector('.progress-step__icon').innerHTML = '✓';
      }
      const el = document.getElementById(step.id);
      el.classList.add('active');
      progressBar.style.width = step.progress + '%';
    }, step.delay);
  });
}

function completeProgress() {
  ['step1', 'step2', 'step3', 'step4'].forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('active');
    el.classList.add('done');
    el.querySelector('.progress-step__icon').innerHTML = '✓';
  });
  progressBar.style.width = '100%';
  progressTitle.textContent = 'Analysis complete.';
}

// ─── Display Results & Logic ──────────────────────────────────
function displayResults(data) {
  const isSafe = data.label === 0;
  const banner = document.getElementById('verdictBanner');

  banner.className = 'verdict-banner reveal ' + (isSafe ? 'verdict-banner--safe' : 'verdict-banner--vulnerable');

  document.getElementById('verdictIcon').innerHTML = isSafe
    ? '<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
    : '<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

  document.getElementById('verdictTitle').textContent = isSafe ? "CLEAN" : "VULNERABLE";
  document.getElementById('verdictSubtitle').textContent = isSafe
    ? 'No significant vulnerability patterns detected. File aligns with known-safe baselines.'
    : 'Critical vulnerability signatures detected. Immediate remediation recommended.';

  const conf = (data.confidence * 100);
  document.getElementById('confidenceFill').style.width = conf + '%';
  document.getElementById('confidenceValue').textContent = conf.toFixed(1) + '%';

  document.getElementById('resFilename').textContent = data.filename;
  document.getElementById('resSha256').textContent = data.sha256;
  document.getElementById('resGhidraTime').textContent = data.timing.ghidra_seconds + 's';
  document.getElementById('resMlTime').textContent = data.timing.ml_seconds + 's';
  document.getElementById('resTotalTime').textContent = data.timing.total_seconds + 's';
  document.getElementById('resTimestamp').textContent = new Date(data.timestamp).toLocaleString();

  // Logical Feature Breakdown
  const featureList = document.getElementById('featureList');
  featureList.innerHTML = '';

  if (data.top_features && data.top_features.length > 0) {
    data.top_features.slice(0, 8).forEach(feat => {
      const isDanger = !isSafe && feat.importance > 0.05;

      let exp = FEATURE_EXPLANATIONS[feat.feature];
      if (!exp) {
        exp = {
          desc: "Unusual Assembly Construct detected.",
          risk: "Unknown Risk — Anomalous pattern outside standard structural baseline.",
          mitigation: "Manual reverse-engineering of this opcode block is suggested.",
          cwe: "N/A"
        };
      }

      const item = document.createElement('div');
      item.className = 'feature-item ' + (isDanger ? 'danger' : '');
      item.innerHTML = `
        <div class="feature-item__head">
          <div class="feature-item__name">${escapeHtml(feat.feature)}</div>
          <div class="feature-item__impact">Relevance: ${(feat.importance * 100).toFixed(2)}%</div>
        </div>
        <div class="feature-item__desc"><strong>Context:</strong> ${exp.desc}</div>
        <div class="feature-item__risk"><strong>Threat Intel:</strong> ${exp.risk}</div>
        <div class="feature-item__risk"><strong>Mitigation:</strong> ${exp.mitigation} <br/> <strong>Standard:</strong> ${exp.cwe}</div>
      `;
      featureList.appendChild(item);
    });
  } else {
    featureList.innerHTML = '<div style="color: #86868b; font-size: 14px;">No critical features extracted.</div>';
  }

  if (exportPdfBtn) exportPdfBtn.style.display = 'block';
  resultsSection.classList.add('visible');
  setTimeout(() => window.dispatchEvent(new Event('scroll')), 100);
}

// ─── PDF Export Fix ────────────────────────────────────────────
function exportToPdf() {
  if (!lastResult) return;
  const element = document.getElementById('pdfExportContainer');
  const btn = document.getElementById('exportPdfBtn');

  // 1. Temporarily disable dark mode so text is black on white
  const wasDark = document.documentElement.getAttribute('data-theme') === 'dark';
  if (wasDark) {
    document.documentElement.removeAttribute('data-theme');
  }

  // 2. Show header for PDF
  const header = element.querySelector('.report-header');
  document.getElementById('reportDate').textContent = "Generated: " + new Date().toLocaleString();
  header.style.display = 'block';

  // 3. Force pure white background and remove animations
  element.style.backgroundColor = '#ffffff';

  const reveals = element.querySelectorAll('.reveal');
  reveals.forEach(el => {
    el.style.transform = 'none';
    el.style.transition = 'none';
    el.style.opacity = '1';
    el.style.animation = 'none';
  });

  const svgs = element.querySelectorAll('svg');
  svgs.forEach(svg => { svg.style.animation = 'none'; });

  const opt = {
    margin: 0.4,
    filename: `Sentinel_Report_${lastResult.filename}.pdf`,
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: {
      scale: 2,
      useCORS: true,
      backgroundColor: '#ffffff',
      scrollY: 0,
      windowY: 0,
      logging: false
    },
    jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
  };

  btn.textContent = 'Generating PDF...';
  btn.disabled = true;

  html2pdf().set(opt).from(element).save().then(() => {
    // Restore everything
    header.style.display = 'none';
    btn.textContent = 'Export Professional Report (PDF)';
    btn.disabled = false;

    reveals.forEach(el => {
      el.style.transform = '';
      el.style.transition = '';
      el.style.opacity = '';
      el.style.animation = '';
    });
    svgs.forEach(svg => { svg.style.animation = ''; });

    if (wasDark) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  }).catch(err => {
    console.error(err);
    header.style.display = 'none';
    btn.textContent = 'Export Professional Report (PDF)';
    btn.disabled = false;
    if (wasDark) document.documentElement.setAttribute('data-theme', 'dark');
    alert("PDF generation failed.");
  });
}

// ─── Scan History ─────────────────────────────────────────────
function addToHistory(data) {
  const entry = {
    filename: data.filename,
    prediction: data.prediction,
    label: data.label,
    confidence: data.confidence,
    timestamp: data.timestamp,
    sha256: data.sha256,
    timing: data.timing,
    top_features: data.top_features
  };
  scanHistory.unshift(entry);
  if (scanHistory.length > 20) scanHistory.pop();
  try { localStorage.setItem('sentinelHistory', JSON.stringify(scanHistory)); } catch (e) { }
  renderHistory();
}

function loadHistory() {
  try {
    const stored = localStorage.getItem('sentinelHistory');
    if (stored) { scanHistory = JSON.parse(stored); renderHistory(); }
  } catch (e) { }
}

function renderHistory() {
  if (scanHistory.length === 0) return;
  historyList.innerHTML = '';
  scanHistory.forEach(entry => {
    const isSafe = entry.label === 0;
    const item = document.createElement('div');
    item.className = 'history-item';
    item.style.cursor = 'pointer'; // Make it look clickable
    item.innerHTML = `
      <div class="history-item__verdict history-item__verdict--${isSafe ? 'safe' : 'vulnerable'}"></div>
      <div class="history-item__name">${escapeHtml(entry.filename)}</div>
      <div class="history-item__confidence" style="color:var(--${isSafe ? 'safe' : 'danger'}-color)">
        ${(entry.confidence * 100).toFixed(1)}%
      </div>
      <div class="history-item__time">${new Date(entry.timestamp).toLocaleTimeString()}</div>
    `;

    // Add click event to view past reports
    item.addEventListener('click', () => {
      // Switch to Scanner tab
      const tabBtns = document.querySelectorAll('.tab-btn');
      const tabContents = document.querySelectorAll('.tab-content');
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      document.querySelector('.tab-btn[data-tab="scanner"]').classList.add('active');
      document.getElementById('tab-scanner').classList.add('active');

      // Hide upload section, show result
      uploadSection.style.display = 'none';
      progressSection.classList.remove('visible');
      lastResult = entry;
      displayResults(entry);
    });

    historyList.appendChild(item);
  });
}

// ─── Reset UI ──────────────────────────────────────────────────
function resetUI() {
  resultsSection.classList.remove('visible');
  progressSection.classList.remove('visible');
  uploadSection.style.display = 'block';
  clearFile();
  analyzeBtn.querySelector('span').textContent = 'Start Analysis';
  if (exportPdfBtn) exportPdfBtn.style.display = 'none';
  ['step1', 'step2', 'step3', 'step4'].forEach((id, i) => {
    const el = document.getElementById(id);
    el.classList.remove('active', 'done');
    el.querySelector('.progress-step__icon').textContent = (i + 1).toString();
  });
  progressBar.style.width = '0%';
  progressTitle.textContent = 'Analyzing binary structure...';
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}
function escapeHtml(str) {
  const div = document.createElement('div'); div.appendChild(document.createTextNode(str)); return div.innerHTML;
}
