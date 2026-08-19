/*
  Cyber Sentinel — sentinel.js
  Single-page app controller for the redesigned threat intelligence UI.
  Design system: Analog Intelligence (neo-brutalist, flat, warm neutral).

  All rendered values (scammer text, agent replies, indicator targets)
  are attacker-controlled and go in via textContent only — never innerHTML
  with attacker data.
*/

/* ================================================================
   STATE
   ================================================================ */
const APP = {
  view: 'operations',
  apiKey: localStorage.getItem('csApiKey') || '',
  sessionId: 'cs-1',
  selectedIncidentId: null,
  incidentFilter: 'ALL',
  analysisTab: 'url',
  taskId: 'ANL-' + Math.floor(Math.random() * 9000 + 1000),
  /* cache */
  summary: null,
  sessions: [],
  incidents: [],
  models: null,
};

/* ================================================================
   HELPERS
   ================================================================ */

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function byId(id) {
  return document.getElementById(id);
}

function apiHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (APP.apiKey) h['x-api-key'] = APP.apiKey;
  return h;
}

async function apiCall(method, path, body) {
  const opts = { method, headers: apiHeaders() };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${text.slice(0, 200)}`);
  }
  return res.json();
}

function providerLabel(p) {
  if (!p || p === 'rules') return 'Rule engine';
  if (p === 'openrouter') return 'AI (OpenRouter)';
  return p;
}

function formatDuration(s) {
  if (!s || s < 60) return `${s || 0}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m ${r}s`;
}

function severityTextClass(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'text-cs-error';
  if (s === 'HIGH')     return 'text-cs-warning';
  if (s === 'MEDIUM')   return 'text-cs-warning';
  return 'text-cs-outline';
}

function severityBorderClass(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'border-cs-error';
  if (s === 'HIGH')     return 'border-cs-warning';
  if (s === 'MEDIUM')   return 'border-cs-warning';
  return 'border-cs-outline-v';
}

function severityBgClass(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'score-tint-error';
  if (s === 'HIGH')     return 'score-tint-error';
  if (s === 'MEDIUM')   return 'score-tint-warning';
  return 'score-tint-low';
}

function chipClass(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'chip chip-critical';
  if (s === 'HIGH')     return 'chip chip-high';
  if (s === 'MEDIUM')   return 'chip chip-medium';
  if (s === 'LOW')      return 'chip chip-low';
  if (s === 'BENIGN')   return 'chip chip-benign';
  if (s === 'HONEYPOT' || s === 'HONEYTRAPS') return 'chip chip-honeypot';
  if (s === 'TECHNICAL') return 'chip chip-technical';
  if (s === 'MIXED')    return 'chip chip-mixed';
  return 'chip chip-neutral';
}

function setStatus(ok, msg) {
  const dot  = byId('status-dot');
  const text = byId('status-text');
  if (dot)  dot.style.background = ok ? '#000f22' : '#ba1a1a';
  if (text) text.textContent = msg;
}

/* ================================================================
   NAVIGATION
   ================================================================ */

function navigate(view) {
  /* "url" and "email" are scanner aliases — both show v-analysis */
  const SCANNER_TITLES = {
    url:   { title: 'URL / Domain Scanner', sub: 'Check if a link or domain is used in phishing or malware campaigns. Analysis is fully offline — no data leaves your machine.' },
    email: { title: 'Email Phishing Analyzer', sub: 'Paste a suspicious email to detect spoofing, malicious links, and social engineering tactics.' },
  };
  const isScanner = view in SCANNER_TITLES;
  const resolvedView = isScanner ? 'analysis' : view;

  APP.view = resolvedView;

  /* Show the correct section */
  document.querySelectorAll('.view').forEach(s => s.classList.remove('active'));
  const target = byId('v-' + resolvedView);
  if (target) target.classList.add('active');

  /* Scanner: update page title/subtitle, show correct input panel, hide results */
  if (isScanner) {
    const info = SCANNER_TITLES[view];
    const titleEl = byId('analysis-page-title');
    const subEl   = byId('analysis-page-sub');
    if (titleEl) titleEl.textContent = info.title;
    if (subEl)   subEl.textContent   = info.sub;

    APP.analysisTab = view;
    const urlSec   = byId('url-input-section');
    const emailSec = byId('email-input-section');
    if (urlSec)   urlSec.style.display   = view === 'url'   ? '' : 'none';
    if (emailSec) emailSec.style.display = view === 'email' ? '' : 'none';

    const res  = byId('analysis-results');
    const edet = byId('email-details');
    if (res)  res.classList.add('hidden');
    if (edet) edet.classList.add('hidden');
  }

  /* Top nav — highlight the button matching the original view name */
  document.querySelectorAll('.nav-btn').forEach(btn => {
    const active = btn.dataset.nav === view;
    btn.classList.toggle('nav-active', active);
    btn.style.borderBottom = active ? '2px solid #000f22' : '';
  });

  /* Trigger refresh for the active view */
  refresh();
}

/* ================================================================
   DATA FETCHING
   ================================================================ */

async function fetchAll() {
  const [summary, sessions, incidents] = await Promise.all([
    apiCall('GET', '/dashboard/api/summary').catch(() => null),
    apiCall('GET', '/dashboard/api/sessions?limit=50').catch(() => []),
    apiCall('GET', '/dashboard/api/incidents').catch(() => []),
  ]);
  if (summary)   APP.summary   = summary;
  if (sessions)  APP.sessions  = sessions;
  if (incidents) APP.incidents = incidents;
}

async function loadModels() {
  try {
    APP.models = await apiCall('GET', '/dashboard/api/models');
    if (APP.view === 'architecture') renderArch(APP.models);
  } catch (_) { /* silent */ }
}

/* ================================================================
   AUTO-REFRESH
   ================================================================ */

async function refresh() {
  try {
    setStatus(true, 'refreshing…');
    if (APP.view === 'operations') {
      await fetchAll();
      renderOps();
    } else if (APP.view === 'honeypot') {
      const threat = await apiCall('GET', '/api/report/threat').catch(() => null);
      if (threat) renderHpIncidents(threat.incidents || []);
    } else if (APP.view === 'incidents') {
      await fetchAll();
      renderIncidentList(APP.incidents);
    } else if (APP.view === 'architecture') {
      await loadModels();
    }
    setStatus(true, 'ok');
  } catch (err) {
    setStatus(false, err.message);
  }
}

/* ================================================================
   OPERATIONS VIEW
   ================================================================ */

function renderOps() {
  renderMetricTiles(APP.summary, APP.incidents, APP.sessions);
  renderFunnel(APP.summary ? APP.summary.funnel : null);
  renderOpsIncidents(APP.incidents);
  renderOpsSessions(APP.sessions);
}

function renderMetricTiles(summary, incidents, sessions) {
  const container = byId('metric-tiles');
  if (!container) return;
  clear(container);

  const s = summary || {};
  const funnel = s.funnel || {};
  const intel  = s.totalIntel || {};
  const src    = s.sourceBreakdown || {};

  const activeSessions = sessions.filter(x => !x.engagementComplete).length;

  const tiles = [
    {
      label: 'Incidents',
      value: incidents.length,
      sub: incidents.filter(i => i.triage === 'ACTION_REQUIRED').length + ' action required',
    },
    {
      label: 'Active Sessions',
      value: activeSessions,
      sub: (s.totalSessions || 0) + ' total',
    },
    {
      label: 'Raw Events',
      value: funnel.rawEvents || 0,
      sub: (funnel.noiseReductionPercent || 0).toFixed(1) + '% noise reduced',
    },
    {
      label: 'Time Wasted',
      value: formatDuration(s.totalTimeWastedSeconds || 0),
      sub: 'scammer engagement',
    },
    {
      label: 'Messages',
      value: s.totalMessages || 0,
      sub: 'total across sessions',
    },
    {
      label: 'Intel Collected',
      value: (intel.upiIds || 0) + (intel.phishingLinks || 0) + (intel.phoneNumbers || 0) + (intel.bankAccounts || 0),
      sub: `UPI:${intel.upiIds||0} Links:${intel.phishingLinks||0} Ph:${intel.phoneNumbers||0}`,
    },
    {
      label: 'Source Mix',
      value: (src.honeypot || 0) + '/' + (src.technical || 0) + '/' + (src.mixed || 0),
      sub: 'honeypot / tech / mixed',
    },
    {
      label: 'Action Required',
      value: funnel.actionRequired || 0,
      sub: (funnel.openActions || 0) + ' open actions',
    },
  ];

  tiles.forEach(t => {
    const tile = el('div', 'metric-tile flex-1');
    tile.style.minWidth = '120px';
    tile.appendChild(el('div', 'metric-tile-label', t.label));
    tile.appendChild(el('div', 'metric-tile-value', t.value));
    tile.appendChild(el('div', 'metric-tile-sub', t.sub));
    container.appendChild(tile);
  });
}

function renderFunnel(funnel) {
  const box = byId('ops-funnel');
  if (!box) return;
  clear(box);
  if (!funnel) { box.appendChild(el('div', 'font-mono text-xs text-cs-outline', 'No data.')); return; }

  const steps = [
    ['Raw Events',     funnel.rawEvents     || 0, 100],
    ['Sessions',       funnel.sessions      || 0, funnel.rawEvents],
    ['Incidents',      funnel.incidents     || 0, funnel.rawEvents],
    ['Action Required',funnel.actionRequired|| 0, funnel.rawEvents],
    ['Open Actions',   funnel.openActions   || 0, funnel.rawEvents],
  ];

  steps.forEach(([label, value, base]) => {
    const pct = base > 0 ? Math.round((value / base) * 100) : 0;
    const row = el('div', 'funnel-step-row');

    const meta = el('div', 'flex items-center justify-between mb-1');
    meta.appendChild(el('span', 'font-mono text-xs text-cs-secondary', label));
    const right = el('span', 'font-mono text-xs font-semibold text-cs-primary');
    right.textContent = value + (base && base !== value ? ` (${pct}%)` : '');
    meta.appendChild(right);
    row.appendChild(meta);

    const track = el('div', 'funnel-bar-track');
    const fill  = el('div', 'funnel-bar-fill');
    fill.style.width = pct + '%';
    track.appendChild(fill);
    row.appendChild(track);

    box.appendChild(row);
  });
}

function renderOpsIncidents(incidents) {
  const box = byId('ops-incidents');
  if (!box) return;
  clear(box);

  if (!incidents || !incidents.length) {
    box.appendChild(el('div', 'font-mono text-xs text-cs-outline', 'No incidents declared yet.'));
    return;
  }

  incidents.slice(0, 8).forEach(inc => {
    const row = el('div', 'incident-row flex items-center gap-2');
    row.appendChild(el('span', chipClass(inc.severity), inc.severity));
    const name = el('span', 'font-mono text-xs flex-1 text-cs-on-surf');
    name.textContent = inc.name;
    row.appendChild(name);
    row.appendChild(el('span', 'font-mono text-xs text-cs-outline', inc.severityScore));
    const sessions = el('span', 'font-mono text-xs text-cs-outline');
    sessions.textContent = inc.sessionCount + 's';
    row.appendChild(sessions);
    row.addEventListener('click', () => navigate('incidents'));
    box.appendChild(row);
  });
}

function renderOpsSessions(sessions) {
  const box = byId('ops-sessions');
  if (!box) return;
  clear(box);

  if (!sessions || !sessions.length) {
    box.appendChild(el('div', 'font-mono text-xs text-cs-outline px-3 py-4', 'No sessions yet.'));
    return;
  }

  sessions.slice(0, 15).forEach(sess => {
    const row = el('div', 'session-row');

    const sourceChip = el('span', chipClass(sess.sourceType || 'honeypot'), (sess.sourceType || 'HONEYPOT').toUpperCase());
    sourceChip.style.width = '90px';
    sourceChip.style.textAlign = 'center';
    row.appendChild(sourceChip);

    const cat = el('span', 'font-mono text-xs flex-1 text-cs-secondary');
    cat.textContent = (sess.category || 'UNKNOWN').replace(/_/g, ' ');
    row.appendChild(cat);

    const id = el('span', 'font-mono text-xs text-cs-outline');
    id.style.width = '180px';
    id.textContent = sess.sessionId;
    row.appendChild(id);

    const score = el('span', 'font-mono text-xs font-semibold');
    score.style.width = '80px';
    const scoreVal = sess.score || 0;
    score.textContent = scoreVal.toFixed ? scoreVal.toFixed(1) : scoreVal;
    score.style.color = scoreVal >= 70 ? '#ba1a1a' : scoreVal >= 40 ? '#d97706' : '#43474d';
    row.appendChild(score);

    const sev = sess.isScam ? (sess.score >= 70 ? 'CRITICAL' : 'HIGH') : 'LOW';
    row.appendChild(el('span', chipClass(sev), sev));

    box.appendChild(row);
  });
}

/* ================================================================
   HONEYPOT VIEW
   ================================================================ */

const QUICK_SENDS = [
  ['Hindi (romanized)', 'aapka account band ho jayega, turant KYC karo'],
  ['Hindi + UPI',       'paise bhejo is UPI par: mule.pay@ybl, warna jurmana lagega'],
  ['Hindi (native)',    'आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें'],
  ['Bengali',           'আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে, এখনই ওটিপি পাঠান'],
  ['Tamil',             'உங்கள் கணக்கு முடக்கப்படும், உடனடியாக ஓடிபி அனுப்பு'],
  ['Telugu',            'మీ ఖాతా బ్లాక్ అవుతుంది, వెంటనే ఓటీపీ పంపండి'],
  ['Marathi',           'तुमचे खाते बंद होईल, ताबडतोब ओटीपी पाठवा'],
  ['Digital arrest',    'This is CBI. A narcotics parcel in your name. Warrant issued, call 9812345670 now.'],
  ['Phishing link',     'Verify your KYC at http://sbi-secure.example/verify before 6pm.'],
  ['Benign',            'Hey, are we still on for lunch tomorrow?'],
];

function userList(count) {
  return Array.from({ length: count }, (_, i) => `user${i}`);
}

function authEvent(eventId, ip, users, count, { succeeded = false, domain = null } = {}) {
  const indicators = { ip: [ip], user: users };
  if (domain) indicators.domain = [domain];
  return {
    eventId,
    timestamp: Date.now() / 1000,
    eventType: 'AUTH_FAILURE_BURST',
    sourceIdentifier: ip,
    targetIdentifiers: users,
    indicators,
    count,
    confidence: 0.9,
    detectionSource: 'operator-console',
    succeededAfterFailures: succeeded,
  };
}

const SCENARIOS = [
  {
    id: 'upi-campaign',
    name: 'UPI mule campaign',
    blurb: '4 sessions, 3 funnelling to same UPI handle. Should collapse into one incident.',
    events: [
      ['camp-a1', 'Your KYC expired. Pay the ₹499 re-verification to mule.pay@ybl immediately.'],
      ['camp-a2', 'Account suspended. Transfer to mule.pay@ybl now or it stays blocked.'],
      ['camp-a3', 'Final warning: send ₹499 to mule.pay@ybl, reference SBI-8891.'],
      ['camp-a4', 'Congratulations, you won a prize! Claim at http://prize-claim.example/win'],
    ],
  },
  {
    id: 'multilingual',
    name: 'Multi-language burst',
    blurb: 'Same operation, five languages. Detection must not depend on English.',
    events: [
      ['camp-b1', 'aapka account band ho jayega, turant otp bhejo, paise bhejo scam.desk@ybl'],
      ['camp-b2', 'আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে, টাকা পাঠান scam.desk@ybl'],
      ['camp-b3', 'உங்கள் கணக்கு முடக்கப்படும், பணம் அனுப்பு scam.desk@ybl'],
      ['camp-b4', 'మీ ఖాతా బ్లాక్ అవుతుంది, డబ్బు పంపండి scam.desk@ybl'],
      ['camp-b5', 'तुमचे खाते बंद होईल, पैसे पाठवा scam.desk@ybl'],
    ],
  },
  {
    id: 'digital-arrest',
    name: 'Digital arrest ring',
    blurb: 'Highest-weight attack type, shared callback number across victims.',
    events: [
      ['camp-c1', 'CBI here. Narcotics parcel in your name. Warrant issued. Call 9812345670.'],
      ['camp-c2', 'Police case registered against you. Avoid arrest, call 9812345670 immediately.'],
      ['camp-c3', 'Custody warrant pending. Pay the penalty to 918823456789012 or face arrest.'],
    ],
  },
  {
    id: 'noise',
    name: 'Benign noise',
    blurb: 'Ordinary traffic. Should produce no actionable incident — that is the point.',
    events: [
      ['noise-1', 'Hi, your Amazon order ships tomorrow.'],
      ['noise-2', 'Team standup moved to 10:30.'],
      ['noise-3', 'Can you send the quarterly report by Friday?'],
      ['noise-4', 'Happy birthday! See you at dinner.'],
    ],
  },
  {
    id: 'credential-stuffing',
    name: 'Credential stuffing',
    blurb: 'One source IP, 12 accounts, 50 failures, one success. No conversation involved.',
    technicalEvents: [authEvent('cred-stuffing', '203.0.113.9', userList(12), 50, { succeeded: true })],
  },
  {
    id: 'password-spray',
    name: 'Password spray',
    blurb: 'Reverse fan-out: 8 source IPs, one target account. Should still be ONE incident.',
    technicalEvents: Array.from({ length: 8 }, (_, i) =>
      authEvent(`spray-${i + 1}`, `198.51.100.${i + 1}`, ['a.sharma'], 20)
    ),
  },
  {
    id: 'cross-source',
    name: 'Cross-source: honeypot + auth feed',
    blurb:
      'Scammer hands us a phishing domain; auth feed reports attack from same domain. ' +
      'Both halves land in one Mixed incident.',
    events: [['cross-chat', 'Urgent: verify your KYC at http://secure-kyc-verify.tk/login or account is blocked.']],
    technicalEvents: [
      authEvent('cross-auth', '203.0.113.9', ['a.sharma', 'v.rao'], 40, { domain: 'secure-kyc-verify.tk' }),
    ],
  },
];

function buildEvents(scenario) {
  const chat = (scenario.events || []).map(([sessionId, text]) => ({
    sessionId,
    message: { sender: 'scammer', text, timestamp: Date.now() },
    conversationHistory: [],
    metadata: { channel: 'SMS', locale: 'IN' },
  }));
  return chat.concat(scenario.technicalEvents || []);
}

function eventCount(scenario) {
  return (scenario.events || []).length + (scenario.technicalEvents || []).length;
}

function scenarioType(scenario) {
  const hasChat = (scenario.events || []).length > 0;
  const hasTech = (scenario.technicalEvents || []).length > 0;
  if (hasChat && hasTech) return 'MIXED';
  if (hasTech) return 'TECHNICAL';
  return 'HONEYPOT';
}

function renderCampaigns() {
  const container = byId('hp-campaigns');
  if (!container) return;
  clear(container);

  SCENARIOS.forEach(scenario => {
    const card = el('div', 'campaign-card');

    const header = el('div', 'flex items-center gap-2 mb-1');
    header.appendChild(el('span', 'font-mono text-xs font-semibold text-cs-primary flex-1', scenario.name));
    const type = scenarioType(scenario);
    header.appendChild(el('span', chipClass(type), type));
    card.appendChild(header);

    card.appendChild(el('div', 'font-mono text-xs text-cs-secondary mb-2', scenario.blurb));

    const btn = el('button', 'btn-secondary text-xs w-full', `Replay ${eventCount(scenario)} events`);
    btn.type = 'button';
    btn.addEventListener('click', () => runScenario(scenario, btn));
    card.appendChild(btn);

    container.appendChild(card);
  });
}

async function runScenario(scenario, btn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Sending…';
  try {
    setStatus(true, `Ingesting ${eventCount(scenario)} events…`);
    const result = await apiCall('POST', '/api/ingest', { events: buildEvents(scenario) });
    showIngestResult(scenario, result);
    renderHpIncidents(result.incidents || []);
    setStatus(true, 'ok');
  } catch (err) {
    setStatus(false, err.message);
    const box = byId('hp-ingest-result');
    if (box) { clear(box); box.appendChild(el('span', 'text-cs-error font-mono text-xs', 'Ingest failed: ' + err.message)); }
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function showIngestResult(scenario, result) {
  const box = byId('hp-ingest-result');
  if (!box) return;
  clear(box);
  const campaigns = (result.incidents || []).filter(i => i.sessionCount > 1);
  const line1 = el('div', 'font-mono text-xs text-cs-secondary');
  line1.textContent = `${scenario.name}: accepted ${result.accepted}, failed ${(result.failed||[]).length}`;
  box.appendChild(line1);
  const line2 = el('div', 'font-mono text-xs text-cs-outline mt-1');
  line2.textContent = campaigns.length
    ? `${campaigns.length} multi-session campaign(s): ${campaigns.map(i => i.sessionCount + ' sessions').join(', ')}`
    : 'No multi-session correlation in this batch.';
  box.appendChild(line2);
}

function renderHpIncidents(incidents) {
  const box = byId('hp-incidents');
  if (!box) return;
  clear(box);
  if (!incidents || !incidents.length) {
    box.appendChild(el('div', 'font-mono text-xs text-cs-outline', 'No incidents correlated yet.'));
    return;
  }
  incidents.slice(0, 5).forEach(inc => {
    const row = el('div', 'session-row');
    row.appendChild(el('span', chipClass(inc.severity), inc.severity));
    const name = el('span', 'font-mono text-xs flex-1');
    name.textContent = inc.name;
    row.appendChild(name);
    row.appendChild(el('span', 'font-mono text-xs text-cs-outline', `Score: ${inc.severityScore}`));
    box.appendChild(row);
  });
}

function setupHoneypot() {
  const sessionInput = byId('hp-session-input');
  const newSessionBtn = byId('hp-new-session-btn');
  const sendBtn = byId('hp-send-btn');
  const msgInput = byId('hp-message-input');

  if (sessionInput) {
    sessionInput.value = APP.sessionId;
    sessionInput.addEventListener('change', () => {
      APP.sessionId = sessionInput.value.trim() || 'cs-1';
      const chat = byId('hp-chat');
      if (chat) { clear(chat); }
    });
  }

  if (newSessionBtn) {
    newSessionBtn.addEventListener('click', () => {
      const newId = 'cs-' + Date.now().toString().slice(-6);
      APP.sessionId = newId;
      if (sessionInput) sessionInput.value = newId;
      const chat = byId('hp-chat');
      if (chat) { clear(chat); }
    });
  }

  if (sendBtn) {
    sendBtn.addEventListener('click', async () => {
      const text = msgInput ? msgInput.value.trim() : '';
      if (!text) return;
      if (msgInput) msgInput.value = '';
      await sendMessage(text);
    });
  }

  if (msgInput) {
    msgInput.addEventListener('keydown', async e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const text = msgInput.value.trim();
        if (!text) return;
        msgInput.value = '';
        await sendMessage(text);
      }
    });
  }

  /* Quick sends */
  const quickBox = byId('hp-quick-sends');
  if (quickBox) {
    QUICK_SENDS.forEach(([label, text]) => {
      const btn = el('button', 'sample-btn', label);
      btn.type = 'button';
      btn.addEventListener('click', () => sendMessage(text));
      quickBox.appendChild(btn);
    });
  }

  renderCampaigns();
}

async function sendMessage(text) {
  appendChatMsg('scammer', text);
  try {
    setStatus(true, 'sending…');
    const result = await apiCall('POST', '/api/message', {
      sessionId: APP.sessionId,
      message: { sender: 'scammer', text, timestamp: Date.now() },
      conversationHistory: [],
      metadata: { channel: 'SMS', locale: 'IN' },
    });
    appendChatMsg('honeypot', result.reply, providerLabel(result.replyProvider));
    setStatus(true, 'ok');

    /* Update msg count */
    const countEl = byId('hp-msg-count');
    const chat = byId('hp-chat');
    if (countEl && chat) countEl.textContent = chat.childElementCount + ' messages';

    /* Refresh detection */
    try {
      const report = await apiCall('GET', `/api/report/session/${encodeURIComponent(APP.sessionId)}`);
      renderHpDetection(report);
    } catch (_) { /* silent */ }
  } catch (err) {
    setStatus(false, err.message);
    appendChatMsg('honeypot', `[request failed: ${err.message}]`, 'error');
  }
}

function appendChatMsg(sender, text, note) {
  const chat = byId('hp-chat');
  if (!chat) return;

  /* Remove placeholder */
  const placeholder = chat.querySelector('.text-center');
  if (placeholder) placeholder.remove();

  const isScammer = sender === 'scammer';
  const bubble = el('div', isScammer ? 'chat-scammer' : 'chat-honeypot');
  const meta   = el('div', 'chat-meta', note || (isScammer ? 'scammer' : 'honey-pot'));
  const body   = el('div', 'chat-text', text);
  bubble.appendChild(meta);
  bubble.appendChild(body);
  chat.appendChild(bubble);
  chat.scrollTop = chat.scrollHeight;
}

function renderHpDetection(report) {
  const box = byId('hp-live-detection');
  if (!box) return;
  clear(box);
  if (!report) return;

  const det = report.detection || {};
  const lang = report.language || {};
  const eng  = report.engagement || {};

  const row = el('div', 'flex flex-wrap gap-1 mb-2');
  const scamChip = el('span', det.scamDetected ? 'chip chip-critical' : 'chip chip-low',
    det.scamDetected ? 'SCAM' : 'CLEAN');
  row.appendChild(scamChip);
  if (det.category) row.appendChild(el('span', 'chip chip-neutral', det.category.replace(/_/g,' ')));
  if (lang.name)    row.appendChild(el('span', 'chip chip-neutral', lang.name));
  if (report.incident) row.appendChild(el('span', chipClass(report.incident.severity), report.incident.severity));
  box.appendChild(row);

  const facts = el('div', 'flex flex-wrap gap-x-4 gap-y-1');
  [
    ['Risk', det.riskScore || 0],
    ['Confidence', Math.round((det.confidence || 0) * 100) + '%'],
    ['Strategy', det.strategyState || '—'],
    ['Turns', eng.agentTurns || 0],
    ['Reply via', providerLabel(eng.replyProvider)],
  ].forEach(([label, value]) => {
    const s = el('span', 'font-mono text-xs text-cs-secondary');
    s.appendChild(document.createTextNode(label + ': '));
    s.appendChild(el('b', 'text-cs-primary', value));
    facts.appendChild(s);
  });
  box.appendChild(facts);

  const indicators = Object.entries(report.indicators || {}).filter(([, v]) => v && v.length);
  if (indicators.length) {
    const tags = el('div', 'flex flex-wrap gap-1 mt-2');
    indicators.forEach(([kind, values]) => {
      values.slice(0, 3).forEach(v => {
        const tag = el('span', 'chip chip-neutral', `${kind}: ${v}`);
        tags.appendChild(tag);
      });
    });
    box.appendChild(tags);
  }
}

/* ================================================================
   ANALYSIS VIEW
   ================================================================ */

const URL_SAMPLES = [
  ['Phishing (CRITICAL)', 'http://sbi-kyc-verify.tk/login'],
  ['Brand lookalike',     'https://hdfc-secure-banking.xyz/otp-verify'],
  ['IP host',             'http://203.0.113.5:8080/pay'],
  ['Benign',              'https://www.google.com'],
];

const EMAIL_SAMPLES = [
  [
    'Display-name spoof',
    `From: SBI Bank <sbi.support@gmail.com>\nTo: customer@example.com\nSubject: Urgent KYC Update Required\n\nDear customer, your account will be suspended. Verify now at http://sbi-verify.tk/kyc`,
  ],
  [
    'Reply-To mismatch',
    `From: HDFC Alert <noreply@hdfcbank.com>\nReply-To: collect@gmail.com\nSubject: Account blocked\n\nYour HDFC account is blocked. Unblock at http://hdfc-unblock.xyz`,
  ],
  [
    'SPF fail',
    `From: Income Tax <refund@incometax.gov.in>\nAuthentication-Results: mx.example.com; spf=fail\nSubject: Tax refund Rs 18,500 pending\n\nSubmit bank details at http://incometax-refund.tk/claim`,
  ],
];

function setupAnalysis() {
  /* Task ID */
  const taskEl = byId('analysis-task-id');
  if (taskEl) taskEl.textContent = 'TASK_ID: ' + APP.taskId;

  /* Tab switching is handled by navigate() — no tab buttons in the DOM */

  /* URL samples */
  const urlSamplesBox = byId('url-samples');
  if (urlSamplesBox) {
    URL_SAMPLES.forEach(([label, url]) => {
      const btn = el('button', 'sample-btn', label);
      btn.type = 'button';
      btn.addEventListener('click', () => {
        const inp = byId('url-input');
        if (inp) inp.value = url;
        runUrlScan();
      });
      urlSamplesBox.appendChild(btn);
    });
  }

  /* Email samples */
  const emailSamplesBox = byId('email-samples');
  if (emailSamplesBox) {
    EMAIL_SAMPLES.forEach(([label, raw]) => {
      const btn = el('button', 'sample-btn', label);
      btn.type = 'button';
      btn.addEventListener('click', () => {
        const inp = byId('email-input');
        if (inp) inp.value = raw;
        runEmailScan();
      });
      emailSamplesBox.appendChild(btn);
    });
  }

  /* Analyze buttons */
  const urlBtn   = byId('url-analyze-btn');
  const emailBtn = byId('email-analyze-btn');
  if (urlBtn)   urlBtn.addEventListener('click',   () => runUrlScan());
  if (emailBtn) emailBtn.addEventListener('click',  () => runEmailScan());

  /* URL input: Enter key */
  const urlInput = byId('url-input');
  if (urlInput) {
    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') runUrlScan();
    });
  }

  /* Add to case */
  const addBtn = byId('add-to-case-btn');
  if (addBtn) {
    addBtn.addEventListener('click', () => {
      navigate('incidents');
    });
  }
}

async function runUrlScan() {
  const input = byId('url-input');
  const url = input ? input.value.trim() : '';
  if (!url) return;

  const btn = byId('url-analyze-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing…'; }
  setStatus(true, 'scanning URL…');
  try {
    const data = await apiCall('POST', '/api/scan/url', { url });
    renderScanResult(data.scan, data.sessionId, 'url');
    setStatus(true, 'ok');
  } catch (err) {
    setStatus(false, err.message);
    showAnalysisError(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Analyze'; }
  }
}

async function runEmailScan() {
  const input = byId('email-input');
  const rawEmail = input ? input.value.trim() : '';
  if (!rawEmail) return;

  const btn = byId('email-analyze-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing…'; }
  setStatus(true, 'analyzing email…');
  try {
    const data = await apiCall('POST', '/api/scan/email', { rawEmail });
    renderScanResult(data.scan, data.sessionId, 'email');
    setStatus(true, 'ok');
  } catch (err) {
    setStatus(false, err.message);
    showAnalysisError(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Analyze'; }
  }
}

function showAnalysisError(msg) {
  const results = byId('analysis-results');
  if (!results) return;
  results.classList.remove('hidden');
  const indList = byId('indicators-list');
  if (indList) {
    clear(indList);
    indList.appendChild(el('div', 'font-mono text-xs text-cs-error py-3', 'Scan failed: ' + msg));
  }
}

function parseIndicator(text) {
  if (/TLD/i.test(text))                               return { icon: 'priority_high', label: 'Suspicious TLD',       color: 'error'   };
  if (/impersonat|lookalike/i.test(text))              return { icon: 'gpp_bad',       label: 'Brand Impersonation',  color: 'error'   };
  if (/keyword/i.test(text))                           return { icon: 'key',           label: 'Target Keyword',       color: 'error'   };
  if (/subdomain/i.test(text))                         return { icon: 'dns',           label: 'Subdomain Depth',      color: 'warning' };
  if (/hyphen/i.test(text))                            return { icon: 'account_tree',  label: 'URL Structure',        color: 'warning' };
  if (/IP address/i.test(text))                        return { icon: 'router',        label: 'IP-as-Host',           color: 'error'   };
  if (/port/i.test(text))                              return { icon: 'settings_ethernet', label: 'Non-Standard Port', color: 'warning' };
  if (/long URL|Unusually/i.test(text))                return { icon: 'straighten',    label: 'URL Length',           color: 'info'    };
  if (/spoofing|display.name|Display-name/i.test(text))return { icon: 'person_off',   label: 'Header Spoofing',      color: 'error'   };
  if (/Reply-To/i.test(text))                          return { icon: 'reply',         label: 'Reply-To Mismatch',    color: 'error'   };
  if (/SPF/i.test(text))                               return { icon: 'shield',        label: 'SPF Failure',          color: 'error'   };
  if (/DKIM/i.test(text))                              return { icon: 'verified',      label: 'DKIM Failure',         color: 'error'   };
  if (/DMARC/i.test(text))                             return { icon: 'policy',        label: 'DMARC Failure',        color: 'error'   };
  if (/urgency/i.test(text))                           return { icon: 'warning',       label: 'Urgency Language',     color: 'warning' };
  if (/URL in body|Suspicious URL/i.test(text))        return { icon: 'link_off',      label: 'Suspicious URL in Body', color: 'error' };
  if (/Not a valid email|No email headers|looks like a URL|multiple lines|Invalid/i.test(text))
                                                       return { icon: 'error',         label: 'Invalid Input',        color: 'info'    };
  return { icon: 'info', label: 'Indicator', color: 'info' };
}

function riskColorInfo(riskLevel) {
  const rl = (riskLevel || '').toUpperCase();
  if (rl === 'CRITICAL' || rl === 'HIGH') {
    return { colorClass: 'text-cs-error', verdictClass: 'verdict-bar-error', scoreClass: 'score-error', panelClass: 'score-tint-error', badgeText: rl === 'CRITICAL' ? 'CRITICAL RISK' : 'HIGH RISK', badgeChip: 'chip chip-critical' };
  }
  if (rl === 'MEDIUM') {
    return { colorClass: 'text-cs-warning', verdictClass: 'verdict-bar-warning', scoreClass: 'score-warning', panelClass: 'score-tint-warning', badgeText: 'ELEVATED RISK', badgeChip: 'chip chip-high' };
  }
  if (rl === 'LOW') {
    return { colorClass: 'text-cs-secondary', verdictClass: 'verdict-bar-low', scoreClass: 'score-low', panelClass: 'score-tint-low', badgeText: 'LOW RISK', badgeChip: 'chip chip-low' };
  }
  if (rl === 'BENIGN') {
    return { colorClass: 'text-cs-outline', verdictClass: 'verdict-bar-benign', scoreClass: 'score-low', panelClass: 'score-tint-benign', badgeText: 'BENIGN', badgeChip: 'chip chip-benign' };
  }
  /* INVALID / fallback */
  return { colorClass: 'text-cs-outline', verdictClass: '', scoreClass: 'score-low', panelClass: '', badgeText: 'INVALID', badgeChip: 'chip chip-neutral' };
}

function renderScanResult(scan, sessionId, mode) {
  /* Show results container */
  const results = byId('analysis-results');
  if (results) results.classList.remove('hidden');

  const rl = (scan.riskLevel || '').toUpperCase();
  const info = riskColorInfo(rl);

  /* Score panel */
  const scorePanel = byId('score-panel');
  if (scorePanel) {
    scorePanel.className = `border-r border-cs-outline-v p-6 flex flex-col items-center justify-center ${info.panelClass}`;
    scorePanel.style.width = '33.333%';
    scorePanel.style.minHeight = '220px';
  }

  const scoreVal = byId('score-value');
  if (scoreVal) {
    scoreVal.className = `score-number ${info.scoreClass}`;
    scoreVal.textContent = (rl === 'INVALID' || scan.riskScore === undefined) ? '—' : scan.riskScore;
  }

  const scoreLabel = byId('score-label');
  if (scoreLabel) scoreLabel.textContent = rl === 'INVALID' ? 'N/A' : '/100';

  const scoreBadge = byId('score-badge');
  if (scoreBadge) {
    scoreBadge.className = info.badgeChip;
    scoreBadge.textContent = info.badgeText;
  }

  /* Indicators list */
  const indList = byId('indicators-list');
  if (indList) {
    clear(indList);
    const inds = scan.indicators || [];
    if (!inds.length) {
      const none = el('div', 'indicator-row');
      const iconEl = el('div', 'indicator-icon');
      iconEl.appendChild(el('span', 'material-symbols-outlined text-cs-outline', 'check_circle'));
      const labelEl = el('div', 'indicator-label', 'No indicators');
      const descEl  = el('div', 'indicator-desc text-cs-outline', 'No suspicious signals detected.');
      none.appendChild(iconEl);
      none.appendChild(labelEl);
      none.appendChild(descEl);
      indList.appendChild(none);
    } else {
      inds.forEach(indText => {
        const parsed = parseIndicator(indText);
        const row = el('div', 'indicator-row');

        const iconEl = el('div', 'indicator-icon');
        const iconSpan = el('span', 'material-symbols-outlined');
        iconSpan.textContent = parsed.icon;
        if (parsed.color === 'error')   iconSpan.style.color = '#ba1a1a';
        else if (parsed.color === 'warning') iconSpan.style.color = '#d97706';
        else if (parsed.color === 'info')    iconSpan.style.color = '#0a2540';
        else                                 iconSpan.style.color = '#74777e';
        iconEl.appendChild(iconSpan);

        const labelEl = el('div', 'indicator-label', parsed.label);

        const descEl = el('div', 'indicator-desc');
        descEl.textContent = indText;

        row.appendChild(iconEl);
        row.appendChild(labelEl);
        row.appendChild(descEl);
        indList.appendChild(row);
      });
    }
  }

  /* Verdict bar */
  const verdictBar  = byId('verdict-bar');
  const verdictIcon = byId('verdict-icon');
  const verdictText = byId('verdict-text');
  if (verdictBar) {
    verdictBar.className = `verdict-bar ${info.verdictClass}`;
  }
  if (verdictIcon) {
    verdictIcon.textContent =
      (rl === 'CRITICAL' || rl === 'HIGH') ? 'gpp_bad' :
      rl === 'MEDIUM' ? 'warning' :
      rl === 'LOW' ? 'shield' :
      rl === 'BENIGN' ? 'verified' : 'info';
    verdictIcon.style.color =
      (rl === 'CRITICAL' || rl === 'HIGH') ? '#ba1a1a' :
      rl === 'MEDIUM' ? '#d97706' : '#74777e';
  }
  if (verdictText) {
    const cat = scan.category ? ` — ${scan.category.replace(/_/g,' ')}` : '';
    verdictText.textContent =
      (rl === 'CRITICAL' || rl === 'HIGH') ? `HIGH-RISK ${mode === 'email' ? 'PHISHING EMAIL' : 'PHISHING DOMAIN'}${cat}` :
      rl === 'MEDIUM' ? `SUSPICIOUS ${mode === 'email' ? 'EMAIL' : 'DOMAIN'} — REVIEW REQUIRED${cat}` :
      rl === 'LOW'    ? `LOW RISK${cat}` :
      rl === 'BENIGN' ? `BENIGN — NO THREATS DETECTED` : `INVALID INPUT — UNABLE TO ANALYZE`;
  }

  /* Add to case button */
  const addBtn = byId('add-to-case-btn');
  if (addBtn) {
    const show = sessionId && rl !== 'BENIGN' && rl !== 'INVALID';
    addBtn.classList.toggle('hidden', !show);
  }

  /* Correlated chip */
  const corrChip = byId('correlated-chip');
  if (corrChip) {
    corrChip.classList.toggle('hidden', !sessionId);
    if (sessionId) corrChip.textContent = 'Correlated: ' + sessionId.slice(0, 12) + (sessionId.length > 12 ? '…' : '');
  }

  /* Email header details */
  const emailDetails = byId('email-details');
  const emailGrid    = byId('email-header-grid');
  if (emailDetails && emailGrid) {
    if (mode === 'email' && rl !== 'INVALID') {
      emailDetails.classList.remove('hidden');
      clear(emailGrid);
      const headerItems = [
        ['From Domain', scan.fromDomain  || '—'],
        ['Display Name', scan.displayName || '—'],
        ['Subject',     scan.subject      || '—'],
        ['SPF',         scan.spfResult    || '—'],
        ['DKIM',        scan.dkimResult   || '—'],
        ['DMARC',       scan.dmarcResult  || '—'],
      ];
      headerItems.forEach(([label, value]) => {
        const cell = el('div', 'border border-cs-outline-v p-3');
        cell.appendChild(el('div', 'section-label mb-1', label));
        const val = el('div', 'font-mono text-xs font-semibold text-cs-primary');
        val.textContent = value;
        /* Color auth failures */
        if (['SPF','DKIM','DMARC'].includes(label) && value.toLowerCase() === 'fail') {
          val.style.color = '#ba1a1a';
        }
        cell.appendChild(val);
        emailGrid.appendChild(cell);
      });
    } else {
      emailDetails.classList.add('hidden');
    }
  }
}

/* ================================================================
   INCIDENTS VIEW
   ================================================================ */

function setupIncidentFilters() {
  document.querySelectorAll('.incident-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      APP.incidentFilter = btn.dataset.filter;
      /* Active style */
      document.querySelectorAll('.incident-filter-btn').forEach(b => {
        b.style.background = b.dataset.filter === APP.incidentFilter ? '#e3e2e5' : '';
        b.style.fontWeight = b.dataset.filter === APP.incidentFilter ? '700' : '';
      });
      renderIncidentList(APP.incidents);
    });
  });
}

function renderIncidentList(incidents) {
  const list = byId('incident-list');
  if (!list) return;
  clear(list);

  const countEl = byId('incidents-count');
  if (countEl) countEl.textContent = (incidents || []).length + ' incidents';

  if (!incidents || !incidents.length) {
    list.appendChild(el('div', 'font-mono text-xs text-cs-outline px-4 py-6', 'No incidents declared yet.'));
    return;
  }

  let filtered = incidents;
  if (APP.incidentFilter !== 'ALL') {
    filtered = incidents.filter(i => (i.triage || '').toUpperCase() === APP.incidentFilter);
  }

  if (!filtered.length) {
    list.appendChild(el('div', 'font-mono text-xs text-cs-outline px-4 py-6', 'No incidents match this filter.'));
    return;
  }

  filtered.forEach(inc => {
    const row = el('div', 'incident-row');
    if (inc.incidentId === APP.selectedIncidentId) row.classList.add('selected');

    const top = el('div', 'flex items-center gap-2 mb-1');
    top.appendChild(el('span', chipClass(inc.severity), inc.severity));
    const name = el('span', 'font-mono text-xs font-semibold text-cs-primary flex-1');
    name.textContent = inc.name;
    top.appendChild(name);
    row.appendChild(top);

    const meta = el('div', 'flex items-center gap-3');
    meta.appendChild(el('span', 'font-mono text-xs text-cs-outline', `Score: ${inc.severityScore}`));
    meta.appendChild(el('span', 'font-mono text-xs text-cs-outline', `${inc.sessionCount} session${inc.sessionCount !== 1 ? 's' : ''}`));
    row.appendChild(meta);

    row.addEventListener('click', () => selectIncident(inc));
    list.appendChild(row);
  });
}

function selectIncident(incident) {
  APP.selectedIncidentId = incident.incidentId;
  /* Update active state in list */
  document.querySelectorAll('#incident-list .incident-row').forEach((row, idx) => {
    /* Re-render to apply selected class */
  });
  renderIncidentList(APP.incidents);
  renderIncidentDetail(incident);
}

function renderIncidentDetail(incident) {
  const header = byId('incident-detail-header');
  const detail = byId('incident-detail');
  if (!header || !detail) return;

  /* Header */
  clear(header);
  const h = el('div', 'flex items-center gap-3');
  h.appendChild(el('span', 'font-mono text-sm font-bold text-cs-primary', incident.name));
  h.appendChild(el('span', chipClass(incident.severity), incident.severity));
  const scoreBadge = el('span', 'chip chip-neutral font-mono text-xs');
  scoreBadge.textContent = 'Score: ' + incident.severityScore;
  h.appendChild(scoreBadge);
  header.appendChild(h);

  /* Detail body */
  clear(detail);

  /* Metadata grid */
  const metaGrid = el('div', 'grid gap-0 mb-4');
  metaGrid.style.gridTemplateColumns = 'repeat(3, 1fr)';

  const metaItems = [
    ['Source Type', incident.sourceType || 'Honeypot'],
    ['Sessions',    incident.sessionCount],
    ['Rate',        `${incident.sessionsPerMinute || 0}/min`],
    ['Messages',    incident.totalMessages || 0],
    ['Languages',   (incident.languages || []).join(', ') || '—'],
    ['Triage',      incident.triage || '—'],
  ];
  metaItems.forEach(([label, value]) => {
    const cell = el('div', 'border border-cs-outline-v p-3');
    cell.appendChild(el('div', 'section-label mb-1', label));
    const val = el('div', 'font-mono text-xs font-semibold text-cs-primary');
    val.textContent = String(value);
    cell.appendChild(val);
    metaGrid.appendChild(cell);
  });
  detail.appendChild(metaGrid);

  /* Correlated indicators */
  const corr = incident.correlatedOn || [];
  if (corr.length) {
    const corrBlock = el('div', 'mb-4');
    corrBlock.appendChild(el('div', 'section-label mb-2', 'Correlated Indicators'));
    const tags = el('div', 'flex flex-wrap gap-1');
    corr.forEach(ind => tags.appendChild(el('span', 'chip chip-neutral', ind)));
    corrBlock.appendChild(tags);
    detail.appendChild(corrBlock);
  }

  /* Response plan */
  const plan = incident.responsePlan || [];
  if (plan.length) {
    const planBlock = el('div');
    planBlock.appendChild(el('div', 'section-label mb-2', 'Response Plan'));
    const ol = el('ol');
    ol.style.listStyle = 'none';
    ol.style.padding = '0';
    ol.style.margin = '0';
    plan.forEach((step, i) => {
      const li = el('div', 'plan-step');
      const top = el('div', 'flex items-center gap-2 mb-1');
      const num = el('span', 'font-mono text-xs font-bold text-cs-primary');
      num.textContent = (i + 1) + '.';
      top.appendChild(num);
      top.appendChild(el('span', 'font-mono text-xs font-semibold text-cs-primary flex-1', (step.action || '').replace(/_/g,' ')));
      top.appendChild(el('span', 'chip chip-neutral', step.target || ''));
      const sla = el('span', 'chip chip-info');
      sla.textContent = (step.slaMinutes || 0) + 'm SLA';
      top.appendChild(sla);
      li.appendChild(top);
      const meta = el('div', 'font-mono text-xs text-cs-secondary');
      meta.textContent = (step.owner || '') + (step.rationale ? ' — ' + step.rationale : '');
      li.appendChild(meta);
      ol.appendChild(li);
    });
    planBlock.appendChild(ol);
    detail.appendChild(planBlock);
  }
}

/* ================================================================
   ARCHITECTURE VIEW
   ================================================================ */

function renderArch(models) {
  const modelsBox = byId('arch-models');
  const statusBox = byId('arch-status');
  if (!models) return;

  if (modelsBox) {
    clear(modelsBox);

    const health = models.health || {};
    const configured = models.configured || [];
    const live = models.liveFreeModels || [];

    /* Configured chain */
    modelsBox.appendChild(el('div', 'section-label mb-2', 'Configured Model Chain'));
    if (!configured.length) {
      modelsBox.appendChild(el('div', 'font-mono text-xs text-cs-outline mb-4', 'No models configured. Set OPENROUTER_MODELS env var.'));
    } else {
      configured.forEach((model, i) => {
        const row = el('div', 'session-row flex items-center gap-2');
        row.appendChild(el('span', 'font-mono text-xs text-cs-outline', `${i+1}.`));
        const name = el('span', 'font-mono text-xs flex-1 text-cs-primary');
        name.textContent = model;
        row.appendChild(name);
        const isAvail = (models.configuredAvailable || []).includes(model);
        row.appendChild(el('span', isAvail ? 'chip chip-info' : 'chip chip-neutral', isAvail ? 'AVAILABLE' : 'UNAVAILABLE'));
        modelsBox.appendChild(row);
      });
    }

    modelsBox.appendChild(el('div', 'section-label mb-2 mt-4', 'Live Free Models'));
    if (!live.length) {
      modelsBox.appendChild(el('div', 'font-mono text-xs text-cs-outline', 'No free models listed or OpenRouter unavailable.'));
    } else {
      live.slice(0, 10).forEach(m => {
        const row = el('div', 'font-mono text-xs text-cs-secondary py-1 border-b border-cs-outline-v');
        row.textContent = m;
        modelsBox.appendChild(row);
      });
      if (live.length > 10) {
        modelsBox.appendChild(el('div', 'font-mono text-xs text-cs-outline mt-1', `+${live.length - 10} more`));
      }
    }
  }

  if (statusBox) {
    clear(statusBox);
    const health = models.health || {};

    const rows = [
      ['API Key Configured', models.apiKeyConfigured ? 'YES' : 'NO'],
      ['Last Working Model', health.lastWorkingModel || '—'],
      ['Retired Models',    (health.retiredModels || []).length || 0],
      ['Cooldown Models',   (health.cooldownModels || []).length || 0],
    ];
    rows.forEach(([label, value]) => {
      const row = el('div', 'flex items-center justify-between py-2 border-b border-cs-outline-v');
      row.appendChild(el('span', 'font-mono text-xs text-cs-secondary', label));
      const val = el('span', 'font-mono text-xs font-semibold text-cs-primary');
      val.textContent = String(value);
      row.appendChild(val);
      statusBox.appendChild(row);
    });

    /* Sidebar status dots */
    const corrStat = byId('sb-correlator-status');
    if (corrStat) corrStat.textContent = 'ok';
    const llmStat = byId('sb-llm-status');
    if (llmStat) llmStat.textContent = models.apiKeyConfigured ? 'ok' : 'no key';
  }
}

/* ================================================================
   BOOT
   ================================================================ */

function boot() {
  /* Load API key */
  APP.apiKey = localStorage.getItem('csApiKey') || '';
  const archKey = byId('arch-api-key');
  if (archKey) archKey.value = APP.apiKey;

  /* Top nav buttons */
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => navigate(btn.dataset.nav));
  });

  /* RUN DEMO → cross-source scenario */
  const demoBtn = byId('run-demo-btn');
  if (demoBtn) {
    demoBtn.addEventListener('click', async () => {
      const crossSource = SCENARIOS.find(s => s.id === 'cross-source');
      if (!crossSource) return;
      demoBtn.disabled = true;
      demoBtn.textContent = 'Running…';
      try {
        setStatus(true, 'Running cross-source demo…');
        const result = await apiCall('POST', '/api/ingest', { events: buildEvents(crossSource) });
        setStatus(true, 'Demo complete!');
        /* Navigate to incidents to show result */
        APP.incidents = result.incidents || APP.incidents;
        navigate('incidents');
      } catch (err) {
        setStatus(false, err.message);
      } finally {
        demoBtn.disabled = false;
        demoBtn.textContent = 'Run Demo';
      }
    });
  }

  /* Architecture: save API key */
  const saveKeyBtn = byId('arch-save-key');
  if (saveKeyBtn) {
    saveKeyBtn.addEventListener('click', () => {
      const input = byId('arch-api-key');
      APP.apiKey = input ? input.value.trim() : '';
      localStorage.setItem('csApiKey', APP.apiKey);
      const status = byId('arch-key-status');
      if (status) status.textContent = APP.apiKey ? 'Key saved.' : 'Key cleared.';
      setStatus(true, APP.apiKey ? 'API key saved' : 'API key cleared');
    });
  }

  /* Architecture: clear sessions */
  const clearBtn = byId('arch-clear-sessions');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      try {
        clearBtn.disabled = true;
        clearBtn.textContent = 'Clearing…';
        await apiCall('DELETE', '/dashboard/api/debug/sessions');
        APP.sessions = [];
        APP.incidents = [];
        const dbg = byId('arch-debug-status');
        if (dbg) dbg.textContent = 'Sessions cleared.';
        setStatus(true, 'sessions cleared');
      } catch (err) {
        setStatus(false, err.message);
      } finally {
        clearBtn.disabled = false;
        clearBtn.textContent = 'Clear All Sessions';
      }
    });
  }

  /* One-time setups */
  setupAnalysis();
  setupHoneypot();
  setupIncidentFilters();

  /* Initial navigation */
  navigate('honeypot');

  /* Auto-refresh */
  setInterval(refresh, 5000);

  /* Load models once */
  loadModels();
}

window.addEventListener('load', boot);
