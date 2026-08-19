/*
  Operator console.

  Drives the honey-pot from the browser so the correlate -> prioritise -> recommend
  loop can be watched end to end without curl. Shares dashboard.css.

  All rendered values (scammer text, agent replies, indicator targets) are attacker
  controlled and go in via textContent only.
*/

const state = {
  apiKey: localStorage.getItem("honeypotApiKey") || "",
  sessionId: "console-1",
};

/* ---------- helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function byId(id) {
  return document.getElementById(id);
}

function setStatus(ok, message) {
  const node = byId("liveStatus");
  node.className = ok ? "live-dot" : "live-dot stale";
  node.textContent = message;
}

function headers() {
  const base = { "Content-Type": "application/json" };
  if (state.apiKey) base["x-api-key"] = state.apiKey;
  return base;
}

async function api(method, path, body) {
  const options = { method, headers: headers() };
  if (body !== undefined) options.body = JSON.stringify(body);
  const response = await fetch(path, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${text.slice(0, 200)}`);
  }
  return response.json();
}

function prettyLabel(code) {
  return String(code || "")
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function providerLabel(p) {
  if (!p || p === "rules") return "Adaptive rule engine";
  if (p === "openrouter") return "AI model (OpenRouter)";
  return p;
}

/* ---------- conversation ---------- */

function appendChat(sender, text, note) {
  const chat = byId("chat");
  const row = el("div", `msg ${sender === "scammer" ? "scammer" : "user"}`);
  row.appendChild(el("p", "msg-meta", note || (sender === "scammer" ? "scammer" : "honey-pot")));
  row.appendChild(el("div", "msg-text", text));
  chat.appendChild(row);
  chat.scrollTop = chat.scrollHeight;
}

async function sendMessage(text) {
  if (!text.trim()) return;
  appendChat("scammer", text);

  try {
    setStatus(true, "sending…");
    const result = await api("POST", "/api/message", {
      sessionId: state.sessionId,
      message: { sender: "scammer", text, timestamp: Date.now() },
      conversationHistory: [],
      metadata: { channel: "SMS", locale: "IN" },
    });
    appendChat("user", result.reply, "honey-pot");
    setStatus(true, "ok");
    await refreshAll();
  } catch (err) {
    setStatus(false, err.message);
    appendChat("user", `[request failed: ${err.message}]`, "error");
  }
}

const QUICK_SENDS = [
  ["Hindi (romanized)", "aapka account band ho jayega, turant KYC karo"],
  ["Hindi + UPI", "paise bhejo is UPI par: mule.pay@ybl, warna jurmana lagega"],
  ["Hindi (native)", "आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें"],
  ["Bengali", "আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে, এখনই ওটিপি পাঠান"],
  ["Tamil", "உங்கள் கணக்கு முடக்கப்படும், உடனடியாக ஓடிபி அனுப்பு"],
  ["Telugu", "మీ ఖాతా బ్లాక్ అవుతుంది, వెంటనే ఓటీపీ పంపండి"],
  ["Marathi", "तुमचे खाते बंद होईल, ताबडतोब ओटीपी पाठवा"],
  ["Digital arrest", "This is CBI. A narcotics parcel in your name. Warrant issued, call 9812345670 now."],
  ["Phishing link", "Verify your KYC at http://sbi-secure.example/verify before 6pm."],
  ["Benign", "Hey, are we still on for lunch tomorrow?"],
];

/* ---------- campaign scenarios ---------- */

const SCENARIOS = [
  {
    id: "upi-campaign",
    name: "UPI mule campaign",
    blurb: "4 sessions, 3 of them funnelling to the same UPI handle. Should collapse into one incident.",
    events: [
      ["camp-a1", "Your KYC expired. Pay the ₹499 re-verification to mule.pay@ybl immediately."],
      ["camp-a2", "Account suspended. Transfer to mule.pay@ybl now or it stays blocked."],
      ["camp-a3", "Final warning: send ₹499 to mule.pay@ybl, reference SBI-8891."],
      ["camp-a4", "Congratulations, you won a prize! Claim at http://prize-claim.example/win"],
    ],
  },
  {
    id: "multilingual",
    name: "Multi-language burst",
    blurb: "Same operation, five languages. Detection must not depend on English.",
    events: [
      ["camp-b1", "aapka account band ho jayega, turant otp bhejo, paise bhejo scam.desk@ybl"],
      ["camp-b2", "আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে, টাকা পাঠান scam.desk@ybl"],
      ["camp-b3", "உங்கள் கணக்கு முடக்கப்படும், பணம் அனுப்பு scam.desk@ybl"],
      ["camp-b4", "మీ ఖాతా బ్లాక్ అవుతుంది, డబ్బు పంపండి scam.desk@ybl"],
      ["camp-b5", "तुमचे खाते बंद होईल, पैसे पाठवा scam.desk@ybl"],
    ],
  },
  {
    id: "digital-arrest",
    name: "Digital arrest ring",
    blurb: "Highest-weight attack type, shared callback number across victims.",
    events: [
      ["camp-c1", "CBI here. Narcotics parcel in your name. Warrant issued. Call 9812345670."],
      ["camp-c2", "Police case registered against you. Avoid arrest, call 9812345670 immediately."],
      ["camp-c3", "Custody warrant pending. Pay the penalty to 918823456789012 or face arrest."],
    ],
  },
  {
    id: "noise",
    name: "Benign noise",
    blurb: "Ordinary traffic. Should produce no actionable incident — that is the point.",
    events: [
      ["noise-1", "Hi, your Amazon order ships tomorrow."],
      ["noise-2", "Team standup moved to 10:30."],
      ["noise-3", "Can you send the quarterly report by Friday?"],
      ["noise-4", "Happy birthday! See you at dinner."],
    ],
  },
  {
    id: "credential-stuffing",
    name: "Credential stuffing",
    blurb: "One source IP, 12 accounts, 50 failures, one success. No conversation involved.",
    technicalEvents: [authEvent("cred-stuffing", "203.0.113.9", userList(12), 50, { succeeded: true })],
  },
  {
    id: "password-spray",
    name: "Password spray",
    blurb: "Reverse fan-out: 8 source IPs, one target account. Should still be ONE incident.",
    technicalEvents: Array.from({ length: 8 }, (_, i) =>
      authEvent(`spray-${i + 1}`, `198.51.100.${i + 1}`, ["a.sharma"], 20)
    ),
  },
  {
    id: "cross-source",
    name: "Cross-source: honeypot + auth feed",
    blurb:
      "Scammer hands us a phishing domain; the auth feed reports an attack from the same domain. " +
      "Both halves must land in one Mixed incident.",
    events: [["cross-chat", "Urgent: verify your KYC at http://secure-kyc-verify.tk/login or account is blocked."]],
    technicalEvents: [
      authEvent("cross-auth", "203.0.113.9", ["a.sharma", "v.rao"], 40, { domain: "secure-kyc-verify.tk" }),
    ],
  },
];

function userList(count) {
  return Array.from({ length: count }, (_, i) => `user${i}`);
}

/* Mirrors simulator/technical_events.py so the console and the tests fire the
   same shapes through the same endpoint. */
function authEvent(eventId, ip, users, count, { succeeded = false, domain = null } = {}) {
  const indicators = { ip: [ip], user: users };
  if (domain) indicators.domain = [domain];
  return {
    eventId,
    timestamp: Date.now() / 1000,
    eventType: "AUTH_FAILURE_BURST",
    sourceIdentifier: ip,
    targetIdentifiers: users,
    indicators,
    count,
    confidence: 0.9,
    detectionSource: "operator-console",
    succeededAfterFailures: succeeded,
  };
}

function buildEvents(scenario) {
  const chat = (scenario.events || []).map(([sessionId, text]) => ({
    sessionId,
    message: { sender: "scammer", text, timestamp: Date.now() },
    conversationHistory: [],
    metadata: { channel: "SMS", locale: "IN" },
  }));
  // One batch can carry both kinds - that is what makes cross-source correlation
  // visible in a single click.
  return chat.concat(scenario.technicalEvents || []);
}

function eventCount(scenario) {
  return (scenario.events || []).length + (scenario.technicalEvents || []).length;
}

async function runScenario(scenario, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Sending…";
  try {
    setStatus(true, `ingesting ${eventCount(scenario)} events…`);
    const result = await api("POST", "/api/ingest", { events: buildEvents(scenario) });
    renderIngestResult(scenario, result);
    renderFunnel(result.triageFunnel);
    renderIncidents(result.incidents);
    setStatus(true, "ok");
  } catch (err) {
    setStatus(false, err.message);
    const box = byId("ingestResult");
    clear(box);
    box.appendChild(el("div", "error", `Ingest failed: ${err.message}`));
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function scenarioType(scenario) {
  const hasChat = (scenario.events || []).length > 0;
  const hasTech = (scenario.technicalEvents || []).length > 0;
  if (hasChat && hasTech) return "MIXED";
  if (hasTech) return "TECHNICAL";
  return "HONEYPOT";
}

function renderScenarios() {
  const list = byId("scenarioList");
  clear(list);

  SCENARIOS.forEach((scenario) => {
    const card = el("div", "scenario");

    const nameRow = el("div", null);
    nameRow.style.display = "flex";
    nameRow.style.alignItems = "center";
    nameRow.style.gap = "8px";
    nameRow.style.marginBottom = "4px";
    nameRow.appendChild(el("span", "scenario-name", scenario.name));

    const type = scenarioType(scenario);
    const typeChip = el("span", `chip ${type === "MIXED" ? "Mixed" : type === "TECHNICAL" ? "technical" : "honeypot"}`, type);
    nameRow.appendChild(typeChip);
    card.appendChild(nameRow);

    card.appendChild(el("div", "scenario-blurb", scenario.blurb));

    const button = el("button", null, `Replay ${eventCount(scenario)} events`);
    button.type = "button";
    button.addEventListener("click", () => runScenario(scenario, button));
    card.appendChild(button);
    list.appendChild(card);
  });
}

function renderIngestResult(scenario, result) {
  const box = byId("ingestResult");
  clear(box);
  box.appendChild(el("div", null, `${scenario.name}: accepted ${result.accepted}, failed ${result.failed.length}`));
  const campaigns = (result.incidents || []).filter((i) => i.sessionCount > 1);
  box.appendChild(
    el(
      "div",
      null,
      campaigns.length
        ? `${campaigns.length} multi-session campaign(s) correlated: ${campaigns
            .map((i) => `${i.sessionCount} sessions`)
            .join(", ")}`
        : "No multi-session correlation in this batch."
    )
  );
}

function renderFunnel(funnel) {
  const box = byId("funnel");
  clear(box);
  if (!funnel) return;

  const steps = [
    ["Raw events", funnel.rawEvents],
    ["Sessions", funnel.sessions],
    ["Incidents", funnel.incidents],
    ["Action required", funnel.actionRequired],
    ["Open actions", funnel.openActions],
  ];

  steps.forEach(([label, value], index) => {
    const step = el("div", "funnel-step");
    step.appendChild(el("span", "funnel-value", value ?? 0));
    step.appendChild(el("span", "funnel-label", label));
    box.appendChild(step);
    if (index < steps.length - 1) box.appendChild(el("span", "funnel-arrow", "→"));
  });

  box.appendChild(
    el("div", "funnel-note", `${(funnel.noiseReductionPercent ?? 0).toFixed(1)}% of raw volume never reaches an operator`)
  );
}

/* ---------- incidents ---------- */

function renderIncidents(incidents) {
  const list = byId("incidentList");
  clear(list);

  if (!incidents || !incidents.length) {
    list.appendChild(el("li", "empty", "No incidents declared yet. Send a scam message or replay a campaign."));
    return;
  }

  incidents.forEach((incident) => {
    const item = el("li", `incident ${incident.severity}`);

    const head = el("div", "incident-head");
    head.appendChild(el("span", "incident-name", incident.name));
    const chips = el("span");
    chips.appendChild(el("span", `chip ${incident.severity}`, incident.severity));
    chips.appendChild(document.createTextNode(" "));
    chips.appendChild(el("span", "chip neutral", `score ${incident.severityScore}`));
    chips.appendChild(document.createTextNode(" "));
    chips.appendChild(el("span", "chip neutral", `source: ${incident.sourceType || "Honeypot"}`));
    chips.appendChild(document.createTextNode(" "));
    chips.appendChild(el("span", "chip neutral", prettyLabel(incident.triage)));
    head.appendChild(chips);
    item.appendChild(head);

    const meta = el("div", "incident-meta");
    [
      ["Source", incident.sourceType || "Honeypot"],
      ["Sessions", incident.sessionCount],
      ["Rate", `${incident.sessionsPerMinute}/min`],
      ["Messages", incident.totalMessages],
      ["Languages", (incident.languages || []).join(", ") || "-"],
    ].forEach(([label, value]) => {
      const span = el("span");
      span.appendChild(document.createTextNode(`${label} `));
      span.appendChild(el("b", null, value));
      meta.appendChild(span);
    });
    item.appendChild(meta);

    const correlated = incident.correlatedOn || incident.sharedIndicators || [];
    if (correlated.length) {
      const tags = el("div", "indicator-tags");
      tags.appendChild(el("span", "tag-label", "correlated on"));
      correlated.slice(0, 8).forEach((indicator) => tags.appendChild(el("span", "tag", indicator)));
      item.appendChild(tags);
    }

    const plan = incident.responsePlan || [];
    if (plan.length) {
      const ol = el("ol", "response-plan");
      plan.forEach((action) => {
        const step = el("li");
        const line = el("div", "plan-head");
        line.appendChild(el("span", "plan-action", prettyLabel(action.action)));
        line.appendChild(el("span", "tag", action.target));
        line.appendChild(el("span", "chip neutral", `${action.slaMinutes}m`));
        step.appendChild(line);
        step.appendChild(el("div", "plan-meta", `${action.owner} — ${action.rationale}`));
        ol.appendChild(step);
      });
      item.appendChild(ol);
    }

    list.appendChild(item);
  });
}

/* ---------- live detection + report ---------- */

function renderDetection(report) {
  const box = byId("liveDetection");
  clear(box);
  if (!report) return;

  const row = el("div", "session-row");
  row.appendChild(
    el("span", `chip ${report.detection.scamDetected ? "CRITICAL" : "LOW"}`, report.detection.scamDetected ? "SCAM" : "CLEAN")
  );
  row.appendChild(el("span", "chip neutral", prettyLabel(report.detection.category)));
  row.appendChild(el("span", "chip neutral", report.language.name));
  row.appendChild(el("span", "chip neutral", `source: ${report.sourceType || "honeypot"}`));
  if (report.incident) {
    row.appendChild(el("span", `chip ${report.incident.severity}`, report.incident.severity));
  }
  box.appendChild(row);

  const facts = el("div");
  [
    ["Risk", report.detection.riskScore],
    ["Confidence", `${Math.round((report.detection.confidence || 0) * 100)}%`],
    ["Strategy", report.detection.strategyState],
    ["Vernacular", report.language.vernacularScore],
    ["Turns", report.engagement?.agentTurns ?? 0],
    ["Reply via", providerLabel(report.engagement?.replyProvider) ?? "not applicable"],
  ].forEach(([label, value]) => {
    const span = el("span");
    span.appendChild(document.createTextNode(`${label}: `));
    span.appendChild(el("b", null, value));
    facts.appendChild(span);
    facts.appendChild(document.createTextNode("   "));
  });
  box.appendChild(facts);

  const indicators = Object.entries(report.indicators || {}).filter(([, v]) => v && v.length);
  if (indicators.length) {
    const tags = el("div", "indicator-tags");
    indicators.forEach(([kind, values]) => {
      values.forEach((value) => tags.appendChild(el("span", "tag", `${kind}: ${value}`)));
    });
    box.appendChild(tags);
  }
}

async function refreshAll() {
  try {
    const [threat, report] = await Promise.all([
      api("GET", "/api/report/threat"),
      api("GET", `/api/report/session/${encodeURIComponent(state.sessionId)}`).catch(() => null),
    ]);

    renderFunnel(threat.triageFunnel);
    renderIncidents(threat.incidents);

    if (report) {
      renderDetection(report);
      byId("sessionReport").textContent = JSON.stringify(report, null, 2);
    }
  } catch (err) {
    setStatus(false, err.message);
  }
}

/* ---------- setup ---------- */

function setupTheme() {
  const button = byId("themeBtn");
  const stored = localStorage.getItem("honeypotTheme");
  if (stored) document.documentElement.setAttribute("data-theme", stored);

  const isDark = () =>
    document.documentElement.getAttribute("data-theme") === "dark" ||
    (!document.documentElement.getAttribute("data-theme") &&
      window.matchMedia("(prefers-color-scheme: dark)").matches);

  button.textContent = isDark() ? "Light mode" : "Dark mode";
  button.addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("honeypotTheme", next);
    button.textContent = next === "dark" ? "Light mode" : "Dark mode";
  });
}

function setupKey() {
  const input = byId("apiKey");
  input.value = state.apiKey;
  byId("keyForm").addEventListener("submit", (event) => {
    event.preventDefault();
    state.apiKey = input.value.trim();
    localStorage.setItem("honeypotApiKey", state.apiKey);
    setStatus(true, state.apiKey ? "key saved" : "key cleared");
    refreshAll();
  });
}

function setupChat() {
  const form = byId("chatForm");
  const input = byId("chatText");
  const sessionInput = byId("sessionId");

  state.sessionId = sessionInput.value;
  sessionInput.addEventListener("change", () => {
    state.sessionId = sessionInput.value.trim() || "console-1";
    clear(byId("chat"));
    refreshAll();
  });

  byId("newSessionBtn").addEventListener("click", () => {
    sessionInput.value = `console-${Date.now().toString().slice(-6)}`;
    state.sessionId = sessionInput.value;
    clear(byId("chat"));
    refreshAll();
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = input.value;
    input.value = "";
    sendMessage(text);
  });

  const samples = byId("chatSamples");
  QUICK_SENDS.forEach(([label, text]) => {
    const button = el("button", null, label);
    button.type = "button";
    button.addEventListener("click", () => sendMessage(text));
    samples.appendChild(button);
  });
}

/* ---------- scanners (shared with dashboard) ---------- */

const URL_SCAN_SAMPLES = [
  ["Phishing (CRITICAL)", "http://sbi-kyc-verify.tk/login"],
  ["Brand lookalike (HIGH)", "https://hdfc-secure-banking.xyz/otp-verify"],
  ["IP host (CRITICAL)", "http://203.0.113.5:8080/pay"],
  ["Benign", "https://www.google.com"],
];

const EMAIL_SCAN_SAMPLES = [
  [
    "Display-name spoof",
    `From: SBI Bank <sbi.support@gmail.com>\nTo: customer@example.com\nSubject: Urgent KYC Update Required\n\nDear customer, your account will be suspended. Verify now at http://sbi-verify.tk/kyc`,
  ],
  [
    "Reply-To mismatch",
    `From: HDFC Alert <noreply@hdfcbank.com>\nReply-To: collect@gmail.com\nSubject: Account blocked\n\nYour HDFC account is blocked. Unblock at http://hdfc-unblock.xyz`,
  ],
  [
    "SPF fail",
    `From: Income Tax Dept <refund@incometax.gov.in>\nAuthentication-Results: mx.example.com; spf=fail smtp.mailfrom=incometax.gov.in\nSubject: Tax refund of Rs 18,500 pending\n\nSubmit bank details at http://incometax-refund.tk/claim`,
  ],
];

function renderScanResult(container, scan, sessionId, label) {
  clear(container);
  const head = el("div", "session-row");
  head.style.marginBottom = "8px";
  const levelClass = { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INVALID: "neutral" }[scan.riskLevel] || "LOW";
  head.appendChild(el("span", `chip ${levelClass}`, scan.riskLevel));
  head.appendChild(el("span", "chip neutral", scan.category || "—"));
  head.appendChild(el("span", "chip neutral", `score ${scan.riskScore}/100`));
  if (sessionId) head.appendChild(el("span", "chip technical", "→ correlated"));
  container.appendChild(head);

  if (scan.indicators && scan.indicators.length) {
    const list = el("ul");
    list.style.cssText = "margin:6px 0 0;padding-left:18px;font-size:12px;color:var(--text-secondary)";
    scan.indicators.forEach((ind) => {
      const li = el("li", null, ind);
      li.style.marginBottom = "3px";
      list.appendChild(li);
    });
    container.appendChild(list);
  } else {
    container.appendChild(el("div", "meta", `No suspicious signals — ${label} appears clean.`));
  }

  if (scan.subject) {
    const row = el("div", "meta");
    row.style.marginTop = "6px";
    [["From", scan.fromDomain || "—"], ["SPF", scan.spfResult || "?"], ["DKIM", scan.dkimResult || "?"]].forEach(([k, v]) => {
      const s = el("span"); s.appendChild(document.createTextNode(`${k}: `)); s.appendChild(el("b", null, v)); s.style.marginRight = "14px"; row.appendChild(s);
    });
    container.appendChild(row);
  }

  if (sessionId) {
    const note = el("div", "meta");
    note.style.marginTop = "6px";
    note.textContent = "Ingested — check incidents below ↓";
    container.appendChild(note);
    refreshAll();
  }
}

function setupUrlScanner() {
  const form = byId("urlScanForm");
  const input = byId("urlScanInput");
  const result = byId("urlScanResult");
  const samples = byId("urlScanSamples");

  URL_SCAN_SAMPLES.forEach(([label, url]) => {
    const btn = el("button", null, label);
    btn.type = "button";
    btn.addEventListener("click", () => { input.value = url; form.requestSubmit(); });
    samples.appendChild(btn);
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;
    clear(result);
    result.appendChild(el("div", "meta", "Scanning…"));
    try {
      const data = await api("POST", "/api/scan/url", { url });
      renderScanResult(result, data.scan, data.sessionId, "URL");
    } catch (err) {
      clear(result);
      result.appendChild(el("div", "error", `Scan failed: ${err.message}`));
    }
  });
}

function setupEmailScanner() {
  const form = byId("emailScanForm");
  const input = byId("emailScanInput");
  const result = byId("emailScanResult");
  const samples = byId("emailScanSamples");

  EMAIL_SCAN_SAMPLES.forEach(([label], idx) => {
    const btn = el("button", null, label);
    btn.type = "button";
    btn.addEventListener("click", () => { input.value = EMAIL_SCAN_SAMPLES[idx][1]; form.requestSubmit(); });
    samples.appendChild(btn);
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawEmail = input.value.trim();
    if (!rawEmail) return;
    clear(result);
    result.appendChild(el("div", "meta", "Analysing…"));
    try {
      const data = await api("POST", "/api/scan/email", { rawEmail });
      renderScanResult(result, data.scan, data.sessionId, "Email");
    } catch (err) {
      clear(result);
      result.appendChild(el("div", "error", `Analysis failed: ${err.message}`));
    }
  });
}

function start() {
  setupTheme();
  setupKey();
  setupChat();
  renderScenarios();
  setupUrlScanner();
  setupEmailScanner();
  refreshAll();
  setInterval(refreshAll, 8000);
}

window.addEventListener("load", start);
