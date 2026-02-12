const state = {
  key: localStorage.getItem("dashboardKey") || "",
  selectedSessionId: null,
  refreshTimer: null,
};

function authHeaders() {
  return {
    "x-dashboard-key": state.key,
  };
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = String(value);
  }
}

function showError(message) {
  const sessionMeta = document.getElementById("sessionMeta");
  sessionMeta.innerHTML = `<span class="error">${message}</span>`;
}

async function apiGet(path) {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${text}`);
  }
  return response.json();
}

function renderSummary(summary) {
  setText("kpiActive", summary.activeEngagements);
  setText("kpiSessions", summary.totalSessions);
  setText("kpiFinalized", summary.finalizedSessions);
  setText("kpiWasted", summary.totalScammerTimeWastedSeconds);
  setText("kpiBank", summary.totalExtracted.bankAccounts);
  setText("kpiUpi", summary.totalExtracted.upiIds);
  setText("kpiLinks", summary.totalExtracted.phishingLinks);
  setText("kpiPhones", summary.totalExtracted.phoneNumbers);
}

function sessionRowMarkup(item) {
  return `
    <div><strong>${item.sessionId}</strong></div>
    <div>${item.persona}</div>
    <div class="row">
      <span>${item.scamCategory} (${Math.round((item.scamConfidence || 0) * 100)}%)</span>
      <span>provider: ${item.replyProvider || "?"}</span>
    </div>
    <div class="row">
      <span>msgs: ${item.messageCount}</span>
      <span>scam: ${item.scamDetected}</span>
      <span>done: ${item.engagementComplete}</span>
    </div>
  `;
}

function renderSessions(sessions) {
  const list = document.getElementById("sessionList");
  list.innerHTML = "";

  sessions.forEach((item) => {
    const li = document.createElement("li");
    li.innerHTML = sessionRowMarkup(item);
    if (state.selectedSessionId === item.sessionId) {
      li.classList.add("active");
    }
    li.addEventListener("click", () => {
      state.selectedSessionId = item.sessionId;
      renderSessions(sessions);
      loadSessionDetail(item.sessionId);
    });
    list.appendChild(li);
  });

  if (!state.selectedSessionId && sessions.length > 0) {
    state.selectedSessionId = sessions[0].sessionId;
    loadSessionDetail(state.selectedSessionId);
    renderSessions(sessions);
  }
}

function renderSessionDetail(detail) {
  const meta = document.getElementById("sessionMeta");
  const conf = Math.round((detail.scamConfidence || 0) * 100);
  const cb = `callback=${detail.callbackSent} attempts=${detail.callbackAttempts || 0} status=${detail.callbackLastStatus || "-"}`;
  const err = detail.callbackLastError ? ` error=${detail.callbackLastError}` : "";
  meta.textContent = `${detail.sessionId} | ${detail.persona} | ${detail.scamCategory} (${conf}%) | provider=${detail.replyProvider} | ${cb}${err} | wasted=${detail.timeWastedSeconds}s | msgs=${detail.totalMessages}`;

  const transcript = document.getElementById("transcript");
  transcript.innerHTML = "";
  detail.transcript.forEach((msg) => {
    const row = document.createElement("div");
    row.className = `msg ${msg.sender}`;
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = `${msg.sender}${msg.provider ? ` (${msg.provider})` : ""} @ ${msg.timestamp}`;
    const text = document.createElement("div");
    text.textContent = msg.text;
    row.appendChild(meta);
    row.appendChild(text);
    transcript.appendChild(row);
  });

  const intel = document.getElementById("intel");
  intel.textContent = JSON.stringify(detail.extractedIntelligence, null, 2);

  const intelExtended = document.getElementById("intelExtended");
  if (intelExtended) {
    intelExtended.textContent = JSON.stringify(detail.extendedIntelligence || {}, null, 2);
  }
}

function renderMap(points) {
  const body = document.getElementById("mapTableBody");
  body.innerHTML = "";

  points.forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = `<td>${item.countryName}</td><td>${item.countryCode}</td><td>${item.count}</td>`;
    body.appendChild(row);
  });
}

async function loadSessionDetail(sessionId) {
  try {
    const detail = await apiGet(`/dashboard/api/sessions/${encodeURIComponent(sessionId)}`);
    renderSessionDetail(detail);
  } catch (err) {
    showError(`Failed to load session detail: ${err.message}`);
  }
}

async function refresh() {
  if (!state.key) {
    showError("Set dashboard key to load data.");
    return;
  }

  try {
    const [summary, sessions, map] = await Promise.all([
      apiGet("/dashboard/api/summary"),
      apiGet("/dashboard/api/sessions?limit=50"),
      apiGet("/dashboard/api/map"),
    ]);

    renderSummary(summary);
    renderSessions(sessions);
    renderMap(map);

    if (state.selectedSessionId) {
      await loadSessionDetail(state.selectedSessionId);
    }
  } catch (err) {
    showError(`Dashboard refresh failed: ${err.message}`);
  }
}

function setupAuth() {
  const input = document.getElementById("dashboardKey");
  const button = document.getElementById("saveKeyBtn");
  input.value = state.key;

  button.addEventListener("click", () => {
    state.key = input.value.trim();
    localStorage.setItem("dashboardKey", state.key);
    refresh();
  });
}

function start() {
  setupAuth();
  refresh();
  state.refreshTimer = setInterval(refresh, 5000);
}

window.addEventListener("load", start);
