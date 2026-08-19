/*
  Honey-Pot dashboard.

  Charts are hand-rolled SVG: four small forms, no charting library, no CDN
  (the dashboard has to work on a box with no outbound internet).

  Everything rendered from session data - transcripts, session ids, extracted
  indicators - is attacker-controlled text, so it goes in through textContent
  only. No innerHTML on any value that came off the wire.
*/

const REFRESH_MS = 5000;
const CHART_PAD = { top: 8, right: 46, bottom: 18, left: 8 };
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const state = {
  selectedSessionId: null,
  sessions: [],
  lastOk: 0,
  summary: null,
};

/* ---------- tiny DOM helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function svgEl(tag, attrs) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    node.setAttribute(key, String(value));
  }
  return node;
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = String(value);
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function formatDuration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function formatClock(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/* ---------- tooltip ---------- */

const tooltip = document.getElementById("tooltip");

function showTooltip(event, title, rows) {
  clear(tooltip);
  tooltip.appendChild(el("div", "tt-title", title));
  (rows || []).forEach(([label, value, color]) => {
    const row = el("div", "tt-row");
    const left = el("span");
    if (color) {
      const swatch = el("i");
      swatch.style.background = color;
      left.appendChild(swatch);
    }
    left.appendChild(document.createTextNode(label));
    row.appendChild(left);
    row.appendChild(el("span", null, value));
    tooltip.appendChild(row);
  });

  tooltip.classList.add("visible");
  tooltip.setAttribute("aria-hidden", "false");
  moveTooltip(event);
}

function moveTooltip(event) {
  const box = tooltip.getBoundingClientRect();
  let x = event.clientX + 14;
  let y = event.clientY + 14;
  if (x + box.width > window.innerWidth - 8) x = event.clientX - box.width - 14;
  if (y + box.height > window.innerHeight - 8) y = event.clientY - box.height - 14;
  tooltip.style.left = `${Math.max(8, x)}px`;
  tooltip.style.top = `${Math.max(8, y)}px`;
}

function hideTooltip() {
  tooltip.classList.remove("visible");
  tooltip.setAttribute("aria-hidden", "true");
}

/* ---------- chart primitives ---------- */

/** Bar anchored to the baseline with a 4px rounded data-end. */
function barPath(x, y, width, height, radius) {
  if (width <= 0.5) return `M${x},${y} h0.5 v${height} h-0.5 Z`;
  const r = Math.min(radius, width, height / 2);
  return (
    `M${x},${y} H${x + width - r} Q${x + width},${y} ${x + width},${y + r} ` +
    `V${y + height - r} Q${x + width},${y + height} ${x + width - r},${y + height} H${x} Z`
  );
}

/**
 * Horizontal bars: one series, label on the left, value direct-labelled at the
 * end. No legend - a single series is named by the panel title.
 */
function renderBarChart(svg, rows, options) {
  const opts = options || {};
  const rowHeight = 22;
  const rowGap = 8;
  const labelWidth = opts.labelWidth || 116;
  const width = svg.clientWidth || svg.parentElement.clientWidth || 320;
  const height = Math.max(40, rows.length * (rowHeight + rowGap) - rowGap + 4);

  clear(svg);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("height", height);

  if (!rows.length) {
    svg.setAttribute("height", 40);
    svg.setAttribute("viewBox", `0 0 ${width} 40`);
    const empty = svgEl("text", { x: width / 2, y: 24, "text-anchor": "middle" });
    empty.textContent = opts.emptyText || "No data yet";
    empty.setAttribute("class", "axis-label");
    svg.appendChild(empty);
    return;
  }

  const plotLeft = labelWidth;
  const plotWidth = Math.max(20, width - labelWidth - CHART_PAD.right);
  const max = Math.max(1, ...rows.map((r) => r.value));
  const trackFill = cssVar("--surface-2");

  rows.forEach((row, index) => {
    const y = index * (rowHeight + rowGap);
    const barHeight = rowHeight - 8;
    const barY = y + 4;
    const barWidth = (row.value / max) * plotWidth;

    const label = svgEl("text", { x: 0, y: y + rowHeight / 2 + 4 });
    label.textContent = row.label;
    svg.appendChild(label);

    const track = svgEl("rect", {
      x: plotLeft,
      y: barY,
      width: plotWidth,
      height: barHeight,
      rx: 4,
      fill: trackFill,
    });
    svg.appendChild(track);

    if (row.value > 0) {
      const bar = svgEl("path", {
        d: barPath(plotLeft, barY, barWidth, barHeight, 4),
        fill: row.color,
      });
      svg.appendChild(bar);
    }

    const value = svgEl("text", {
      x: plotLeft + plotWidth + 8,
      y: y + rowHeight / 2 + 4,
      class: "value-label",
    });
    value.textContent = opts.formatValue ? opts.formatValue(row.value) : String(row.value);
    svg.appendChild(value);

    // Hit target spans the whole row, not just the drawn bar.
    const hit = svgEl("rect", {
      x: 0,
      y,
      width,
      height: rowHeight + rowGap,
      class: "hit",
    });
    hit.addEventListener("mouseenter", (e) =>
      showTooltip(e, row.label, [[opts.valueLabel || "Sessions", row.value, row.color]].concat(row.extra || []))
    );
    hit.addEventListener("mousemove", moveTooltip);
    hit.addEventListener("mouseleave", hideTooltip);
    svg.appendChild(hit);
  });
}

/**
 * One-series area + line over time with a hover crosshair.
 * Rendered as a small multiple: each measure keeps its own y scale, which is why
 * sessions and messages are two charts and never two scales on one chart.
 */
function renderTimeline(svg, points, options) {
  const opts = options || {};
  const width = svg.clientWidth || svg.parentElement.clientWidth || 320;
  const height = opts.height || 108;
  const plotTop = 20;
  const plotBottom = height - CHART_PAD.bottom;
  const plotLeft = 30;
  const plotRight = width - 8;
  const plotWidth = Math.max(20, plotRight - plotLeft);
  const plotHeight = Math.max(20, plotBottom - plotTop);

  clear(svg);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("height", height);

  const title = svgEl("text", { x: 0, y: 11, class: "axis-label" });
  title.textContent = opts.title || "";
  svg.appendChild(title);

  if (!points.length) return;

  const max = Math.max(1, ...points.map((p) => p.value));
  const stepX = points.length > 1 ? plotWidth / (points.length - 1) : plotWidth;
  const xOf = (i) => plotLeft + i * stepX;
  const yOf = (v) => plotBottom - (v / max) * plotHeight;

  // Recessive grid: just the max and zero rules.
  [0, max].forEach((tick) => {
    const y = yOf(tick);
    svg.appendChild(
      svgEl("line", { x1: plotLeft, x2: plotRight, y1: y, y2: y, class: tick === 0 ? "baseline" : "gridline" })
    );
    const label = svgEl("text", { x: 0, y: y + 4, class: "axis-label" });
    label.textContent = String(tick);
    svg.appendChild(label);
  });

  const linePoints = points.map((p, i) => `${xOf(i)},${yOf(p.value)}`).join(" ");
  const areaPoints = `${plotLeft},${plotBottom} ${linePoints} ${xOf(points.length - 1)},${plotBottom}`;

  svg.appendChild(svgEl("polygon", { points: areaPoints, fill: opts.color, "fill-opacity": 0.14 }));
  svg.appendChild(
    svgEl("polyline", {
      points: linePoints,
      fill: "none",
      stroke: opts.color,
      "stroke-width": 2,
      "stroke-linejoin": "round",
      "stroke-linecap": "round",
    })
  );

  // First and last x labels only - a tick per bucket would collide.
  [0, points.length - 1].forEach((i) => {
    if (i < 0) return;
    const label = svgEl("text", {
      x: xOf(i),
      y: height - 4,
      class: "axis-label",
      "text-anchor": i === 0 ? "start" : "end",
    });
    label.textContent = formatClock(points[i].bucketStart);
    svg.appendChild(label);
  });

  const crosshair = svgEl("line", {
    y1: plotTop,
    y2: plotBottom,
    stroke: cssVar("--axis"),
    "stroke-width": 1,
    opacity: 0,
  });
  svg.appendChild(crosshair);
  const marker = svgEl("circle", {
    r: 4,
    fill: opts.color,
    stroke: cssVar("--surface-1"),
    "stroke-width": 2,
    opacity: 0,
  });
  svg.appendChild(marker);

  const hit = svgEl("rect", { x: plotLeft, y: plotTop, width: plotWidth, height: plotHeight, class: "hit" });
  hit.addEventListener("mousemove", (event) => {
    const box = svg.getBoundingClientRect();
    const scale = width / box.width;
    const localX = (event.clientX - box.left) * scale;
    const index = Math.max(0, Math.min(points.length - 1, Math.round((localX - plotLeft) / stepX)));
    const point = points[index];

    crosshair.setAttribute("x1", xOf(index));
    crosshair.setAttribute("x2", xOf(index));
    crosshair.setAttribute("opacity", 1);
    marker.setAttribute("cx", xOf(index));
    marker.setAttribute("cy", yOf(point.value));
    marker.setAttribute("opacity", 1);

    showTooltip(event, formatClock(point.bucketStart), [[opts.title, point.value, opts.color]]);
  });
  hit.addEventListener("mouseleave", () => {
    crosshair.setAttribute("opacity", 0);
    marker.setAttribute("opacity", 0);
    hideTooltip();
  });
  svg.appendChild(hit);
}

/* ---------- api ---------- */

async function apiGet(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
  return response.json();
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
  return response.json();
}

/* ---------- renderers ---------- */

function renderTiles(summary, incidents, sessions) {
  const intel = summary.totalExtracted;
  const actionable =
    intel.upiIds + intel.phishingLinks + intel.phoneNumbers + intel.bankAccounts +
    (intel.ipAddresses || 0) + (intel.usernames || 0);
  const worst = incidents.length ? incidents[0].severity : null;

  const funnel = summary.triageFunnel || {};

  setText("tileIncidents", funnel.actionRequired ?? 0);
  setText(
    "tileIncidentsSub",
    `${incidents.length} incidents · ${funnel.review ?? 0} to review · ${funnel.suppressed ?? 0} suppressed`
  );
  setText("tileFunnel", `${funnel.rawEvents ?? 0} → ${funnel.actionRequired ?? 0}`);
  setText(
    "tileFunnelSub",
    `${(funnel.noiseReductionPercent ?? 0).toFixed(1)}% noise removed · ${funnel.openActions ?? 0} open actions`
  );
  setText("tileActive", summary.activeEngagements);
  setText("tileActiveSub", `${summary.totalSessions} sessions · ${summary.scamSessions} confirmed scam`);
  void worst;
  setText("tileWasted", formatDuration(summary.totalScammerTimeWastedSeconds));
  setText("tileWastedSub", "across all sessions");
  setText("tileMessages", summary.totalMessages);
  setText("tileMessagesSub", `${summary.finalizedSessions} finalized sessions`);
  setText("tileIntel", actionable);
  setText(
    "tileIntelSub",
    `UPI ${intel.upiIds} · links ${intel.phishingLinks} · phones ${intel.phoneNumbers} · ` +
      `accounts ${intel.bankAccounts} · IPs ${intel.ipAddresses || 0} · users ${intel.usernames || 0}`
  );

  // Source breakdown tile
  const allSessions = sessions || [];
  const honeypotCount = allSessions.filter(s => !s.sourceType || s.sourceType === "honeypot").length;
  const technicalCount = allSessions.filter(s => s.sourceType === "technical").length;
  const mixedCount = allSessions.filter(s => s.sourceType === "Mixed").length;
  const total = Math.max(1, honeypotCount + technicalCount + mixedCount);

  setText("tileSourceValue", total === 1 && honeypotCount === 0 && technicalCount === 0 ? "0" : allSessions.length);
  setText("tileSourceSub", `honeypot ${honeypotCount} · technical ${technicalCount} · mixed ${mixedCount}`);

  const bar = document.getElementById("tileSourceBar");
  if (bar) {
    clear(bar);
    if (honeypotCount > 0) {
      const seg = el("span", "sb-honeypot");
      seg.style.width = `${(honeypotCount / total) * 100}%`;
      bar.appendChild(seg);
    }
    if (technicalCount > 0) {
      const seg = el("span", "sb-technical");
      seg.style.width = `${(technicalCount / total) * 100}%`;
      bar.appendChild(seg);
    }
    if (mixedCount > 0) {
      const seg = el("span", "sb-mixed");
      seg.style.width = `${(mixedCount / total) * 100}%`;
      bar.appendChild(seg);
    }
  }
}

function severityColor(severity) {
  return {
    CRITICAL: cssVar("--status-critical"),
    HIGH: cssVar("--status-serious"),
    MEDIUM: cssVar("--status-warning"),
    LOW: cssVar("--axis"),
  }[severity];
}

function renderIncidents(incidents) {
  const list = document.getElementById("incidentList");
  clear(list);

  if (!incidents.length) {
    list.appendChild(el("li", "empty", "No incidents declared. Incidents appear once a scam is confirmed."));
    return;
  }

  const breakdownColors = {
    attackType: cssVar("--seq-600"),
    breadth: cssVar("--seq-450"),
    velocity: cssVar("--seq-250"),
    intelValue: cssVar("--seq-100"),
    confidence: cssVar("--axis"),
  };

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
    chips.appendChild(el("span", "chip neutral", (incident.triage || "").replace(/_/g, " ").toLowerCase()));
    head.appendChild(chips);
    item.appendChild(head);

    const meta = el("div", "incident-meta");
    const facts = [
      ["ID", incident.incidentId],
      ["Source", incident.sourceType || "Honeypot"],
      ["Sessions", incident.sessionCount],
      ["Rate", `${incident.sessionsPerMinute}/min`],
      ["Duration", formatDuration(incident.durationSeconds)],
      ["Messages", incident.totalMessages],
      ["Languages", incident.languages.join(", ") || "-"],
    ];
    facts.forEach(([label, value]) => {
      const span = el("span");
      span.appendChild(document.createTextNode(`${label} `));
      span.appendChild(el("b", null, value));
      meta.appendChild(span);
    });
    item.appendChild(meta);

    // Stacked score breakdown, 2px gaps between segments.
    const bar = el("div", "score-bar");
    const legend = el("div", "score-legend");
    Object.entries(incident.scoreBreakdown).forEach(([key, value]) => {
      if (value <= 0) return;
      const segment = el("span");
      segment.style.width = `${value}%`;
      segment.style.background = breakdownColors[key] || cssVar("--axis");
      bar.appendChild(segment);

      const entry = el("span");
      const swatch = el("i");
      swatch.style.background = breakdownColors[key] || cssVar("--axis");
      entry.appendChild(swatch);
      entry.appendChild(document.createTextNode(`${key} ${value}`));
      legend.appendChild(entry);
    });
    item.appendChild(bar);
    item.appendChild(legend);

    if (incident.sharedIndicators.length) {
      const tags = el("div", "indicator-tags");
      incident.sharedIndicators.slice(0, 8).forEach((indicator) => {
        tags.appendChild(el("span", "tag", indicator));
      });
      if (incident.sharedIndicators.length > 8) {
        tags.appendChild(el("span", "tag", `+${incident.sharedIndicators.length - 8} more`));
      }
      item.appendChild(tags);
    }

    item.appendChild(el("div", "incident-action", incident.recommendedAction));

    // The actual work: what to do, to which target, by when, by whom.
    if ((incident.responsePlan || []).length) {
      const plan = el("ol", "response-plan");
      incident.responsePlan.forEach((action) => {
        const step = el("li");
        const head = el("div", "plan-head");
        head.appendChild(el("span", "plan-action", action.action.replace(/_/g, " ").toLowerCase()));
        head.appendChild(el("span", "tag", action.target));
        head.appendChild(el("span", "chip neutral", `${action.slaMinutes}m`));
        step.appendChild(head);
        step.appendChild(el("div", "plan-meta", `${action.owner} — ${action.rationale}`));
        plan.appendChild(step);
      });
      item.appendChild(plan);
    }

    list.appendChild(item);
  });
}

function renderCharts(summary) {
  const severityRows = SEVERITY_ORDER.map((severity) => ({
    label: severity,
    value: summary.severityCounts[severity] || 0,
    color: severityColor(severity),
  }));
  renderBarChart(document.getElementById("severityChart"), severityRows, {
    labelWidth: 74,
    valueLabel: "Incidents",
    emptyText: "No incidents yet",
  });

  const blue = cssVar("--series-1");
  renderBarChart(
    document.getElementById("categoryChart"),
    topEntries(summary.categoryBreakdown, 7).map((entry) => ({
      label: prettyCategory(entry.label),
      value: entry.value,
      color: blue,
    })),
    { labelWidth: 128, valueLabel: "Sessions", emptyText: "No confirmed scams yet" }
  );

  renderBarChart(
    document.getElementById("languageChart"),
    topEntries(summary.languageBreakdown, 7).map((entry) => ({
      label: entry.label,
      value: entry.value,
      color: blue,
    })),
    { labelWidth: 84, valueLabel: "Sessions", emptyText: "No sessions yet" }
  );

  const timeline = summary.timeline || [];
  renderTimeline(
    document.getElementById("timelineMessages"),
    timeline.map((p) => ({ bucketStart: p.bucketStart, value: p.messages })),
    { title: "Messages", color: cssVar("--series-1") }
  );
  renderTimeline(
    document.getElementById("timelineSessions"),
    timeline.map((p) => ({ bucketStart: p.bucketStart, value: p.sessions })),
    { title: "New sessions", color: cssVar("--series-2") }
  );
}

function topEntries(entries, limit) {
  const list = (entries || []).slice();
  if (list.length <= limit) return list;
  const head = list.slice(0, limit);
  const rest = list.slice(limit).reduce((sum, entry) => sum + entry.value, 0);
  head.push({ label: "Other", value: rest });
  return head;
}

function prettyCategory(code) {
  return String(code)
    .toLowerCase()
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function renderSessions(sessions) {
  const list = document.getElementById("sessionList");
  clear(list);

  if (!sessions.length) {
    state.selectedSessionId = null;
    list.appendChild(el("li", "empty", "No sessions yet. POST to /api/message to start one."));
    return;
  }

  // A session can expire between dashboard polls. Do not keep requesting the
  // old id forever: select a current row instead of producing a repeated 404.
  if (!sessions.some((item) => item.sessionId === state.selectedSessionId)) {
    state.selectedSessionId = sessions[0].sessionId;
  }

  sessions.forEach((item) => {
    const isTechnical = item.sourceType === "technical";
    const isMixed = item.sourceType === "Mixed";

    const li = el("li");
    if (state.selectedSessionId === item.sessionId) li.classList.add("active");
    if (isTechnical) li.classList.add("session-technical");
    else if (isMixed) li.classList.add("session-mixed");

    li.appendChild(el("div", "session-id", item.sessionId));

    const row1 = el("div", "session-row");
    // Source type badge — first and most prominent
    const sourceLabel = isTechnical ? "technical" : isMixed ? "Mixed" : "honeypot";
    row1.appendChild(el("span", `chip ${sourceLabel}`, sourceLabel.toUpperCase()));
    if (item.incidentSeverity) {
      row1.appendChild(el("span", `chip ${item.incidentSeverity}`, item.incidentSeverity));
    }
    row1.appendChild(el("span", "chip neutral", prettyCategory(item.scamCategory)));
    if (!isTechnical) row1.appendChild(el("span", "chip neutral", item.languageName));
    li.appendChild(row1);

    const row2 = el("div", "session-row");
    if (isTechnical) {
      row2.appendChild(el("span", null, `${item.messageCount} events`));
      row2.appendChild(el("span", null, `conf ${Math.round((item.scamConfidence || 0) * 100)}%`));
      row2.appendChild(el("span", null, item.engagementComplete ? "finalized" : "active"));
    } else {
      row2.appendChild(el("span", null, `risk ${item.rollingScamScore}`));
      row2.appendChild(el("span", null, `conf ${Math.round((item.scamConfidence || 0) * 100)}%`));
      row2.appendChild(el("span", null, `${item.messageCount} msgs`));
      row2.appendChild(el("span", null, item.engagementComplete ? "finalized" : item.strategyState));
    }
    li.appendChild(row2);

    if (!isTechnical) {
      const row3 = el("div", "session-row");
      row3.appendChild(el("span", null, item.persona));
      row3.appendChild(el("span", null, `via ${providerLabel(item.replyProvider)}`));
      li.appendChild(row3);
    }

    li.addEventListener("click", () => {
      state.selectedSessionId = item.sessionId;
      renderSessions(state.sessions);
      loadSessionDetail(item.sessionId);
    });
    list.appendChild(li);
  });

}

function renderSessionDetail(detail) {
  const meta = document.getElementById("sessionMeta");
  clear(meta);

  const isTechnical = detail.sourceType === "technical";
  const intel = detail.extractedIntelligence || {};

  // Source type banner
  const sourceLabel = isTechnical ? "technical" : (detail.sourceType === "Mixed" ? "Mixed" : "honeypot");
  const banner = el("div", "session-row");
  banner.style.marginBottom = "10px";
  banner.appendChild(el("span", `chip ${sourceLabel}`, sourceLabel.toUpperCase()));
  if (detail.incidentSeverity) {
    banner.appendChild(el("span", `chip ${detail.incidentSeverity}`, detail.incidentSeverity));
  }
  meta.appendChild(banner);

  const facts = isTechnical ? [
    ["Session / Event ID", detail.sessionId],
    ["Source", "Technical Feed"],
    ["Attack type", prettyCategory(detail.scamCategory)],
    ["Events ingested", detail.totalMessages],
    ["Confidence", `${Math.round((detail.scamConfidence || 0) * 100)}%`],
    ["Source IPs", (intel.ipAddresses || []).join(", ") || "—"],
    ["Targeted accounts", (intel.usernames || []).join(", ") || "—"],
    ["File hashes", (intel.fileHashes || []).join(", ") || "—"],
  ] : [
    ["Session", detail.sessionId],
    ["Persona", detail.persona],
    ["Source", "Social-engineering honeypot"],
    ["Attack category", prettyCategory(detail.scamCategory)],
    ["Confidence", `${Math.round((detail.scamConfidence || 0) * 100)}%`],
    ["Risk score", detail.rollingScamScore],
    ["Strategy", detail.strategyState],
    ["Language", `${detail.languageName} (${Math.round((detail.languageConfidence || 0) * 100)}%)`],
    ["Vernacular score", detail.vernacularScore],
    ["Reply via", providerLabel(detail.replyProvider)],
    ["Time wasted", formatDuration(detail.timeWastedSeconds)],
    ["Messages", detail.totalMessages],
  ];
  if (detail.incidentId) facts.unshift(["Incident", `${detail.incidentId} — ${detail.incidentName}`]);

  facts.forEach(([label, value]) => {
    const row = el("div");
    row.appendChild(el("span", null, `${label}: `));
    row.appendChild(el("b", null, value));
    meta.appendChild(row);
  });

  if ((detail.responsePlan || []).length) {
    const plan = el("ol", "response-plan");
    detail.responsePlan.forEach((action) => {
      const step = el("li");
      const head = el("div", "plan-head");
      head.appendChild(el("span", "plan-action", action.action.replace(/_/g, " ").toLowerCase()));
      head.appendChild(el("span", "tag", action.target));
      head.appendChild(el("span", "chip neutral", `${action.slaMinutes}m`));
      step.appendChild(head);
      step.appendChild(el("div", "plan-meta", `${action.owner} — ${action.rationale}`));
      plan.appendChild(step);
    });
    meta.appendChild(plan);
  }

  const transcript = document.getElementById("transcript");
  const transcriptLabel = document.getElementById("transcriptLabel");
  clear(transcript);

  if (isTechnical) {
    if (transcriptLabel) transcriptLabel.textContent = "Event summary";
    const notice = el("div", "msg");
    notice.style.borderLeftColor = "var(--series-3)";
    notice.appendChild(el("p", "msg-meta", "technical feed — no conversation"));
    notice.appendChild(el("div", "msg-text",
      `This is a technical security event, not a chat session. ` +
      `Attack type: ${prettyCategory(detail.scamCategory)}. ` +
      `Source IPs: ${(intel.ipAddresses || []).join(", ") || "none captured"}. ` +
      `Targeted accounts: ${(intel.usernames || []).join(", ") || "none captured"}.`
    ));
    transcript.appendChild(notice);
  } else {
    if (transcriptLabel) transcriptLabel.textContent = "Transcript";
    (detail.transcript || []).forEach((msg) => {
      const row = el("div", `msg ${msg.sender === "scammer" ? "scammer" : "user"}`);
      const label = msg.sender === "scammer" ? "scammer" : "honey-pot";
      row.appendChild(el("p", "msg-meta", `${label}${msg.provider ? ` · ${providerLabel(msg.provider)}` : ""}`));
      row.appendChild(el("div", "msg-text", msg.text));
      transcript.appendChild(row);
    });
  }

  setText("intel", JSON.stringify(intel, null, 2));
  setText("intelExtended", JSON.stringify(detail.extendedIntelligence || {}, null, 2));
  setText("finalOutput", JSON.stringify(detail.report || {}, null, 2));
}

function renderMap(points) {
  const body = document.getElementById("mapTableBody");
  clear(body);

  if (!points.length) {
    const row = el("tr");
    const cell = el("td", "empty", "No phone numbers captured yet");
    cell.colSpan = 3;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  points.forEach((item) => {
    const row = el("tr");
    row.appendChild(el("td", null, item.countryName));
    row.appendChild(el("td", null, item.countryCode));
    row.appendChild(el("td", "num", item.count));
    body.appendChild(row);
  });
}

function providerLabel(p) {
  if (!p || p === "rules") return "Adaptive rule engine";
  if (p === "openrouter") return "AI model (OpenRouter)";
  return p;
}

function renderModels(models) {
  const body = document.getElementById("modelTableBody");
  clear(body);

  const health = models.health || {};
  const retired = new Set(health.retiredModels || []);
  const cooling = new Set(health.cooldownModels || []);
  const live = new Set(models.liveFreeModels || []);
  const configured = models.configured || [];

  if (!models.apiKeyConfigured) {
    const row = el("tr");
    const cell = el("td", "empty",
      "OPENROUTER_API_KEY not set — adaptive rule engine handles all replies (multi-turn, multilingual, category-aware)");
    cell.colSpan = 2;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  configured.forEach((model) => {
    const row = el("tr");
    row.appendChild(el("td", null, model));

    let label = "ready";
    if (model === health.lastWorkingModel) label = "✓ active";
    else if (retired.has(model)) label = "unavailable";
    else if (cooling.has(model)) label = "rate-limited (cooling)";
    else if (live.size && !live.has(model)) label = "not listed by OpenRouter";

    row.appendChild(el("td", null, label));
    body.appendChild(row);
  });

  // Banner when every model is unavailable — system still works via rule engine
  const allDown = configured.length > 0 &&
    configured.every((m) => retired.has(m) || cooling.has(m) || (live.size && !live.has(m)));
  if (allDown) {
    const row = el("tr");
    const cell = el("td", "meta",
      "All AI models rate-limited — adaptive rule engine active. " +
      "Replies remain contextual, multilingual, and category-specific.");
    cell.colSpan = 2;
    cell.style.fontStyle = "italic";
    row.appendChild(cell);
    body.appendChild(row);
  }
}

/* ---------- language probe ---------- */

const PROBE_SAMPLES = [
  ["Hindi (romanized)", "aapka account band ho jayega, turant OTP bhejo"],
  ["Hindi", "आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें"],
  ["Bengali", "আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে, এখনই ওটিপি পাঠান"],
  ["Tamil", "உங்கள் கணக்கு முடக்கப்படும், உடனடியாக ஓடிபி அனுப்பு"],
  ["Telugu", "మీ ఖాతా బ్లాక్ అవుతుంది, వెంటనే ఓటీపీ పంపండి"],
  ["Marathi", "तुमचे खाते बंद होईल, ताबडतोब ओटीपी पाठवा"],
  ["English", "URGENT: your account will be blocked. Verify KYC now at http://sbi-verify.example/kyc"],
];

function setupProbe() {
  const form = document.getElementById("probeForm");
  const input = document.getElementById("probeText");
  const result = document.getElementById("probeResult");
  const samples = document.getElementById("probeSamples");

  PROBE_SAMPLES.forEach(([label, text]) => {
    const button = el("button", null, label);
    button.type = "button";
    button.addEventListener("click", () => {
      input.value = text;
      form.requestSubmit();
    });
    samples.appendChild(button);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;

    clear(result);
    result.appendChild(el("div", "meta", "Analysing…"));
    try {
      const data = await apiPost("/dashboard/api/debug/detect-scam", { text });
      clear(result);

      const head = el("div", "session-row");
      head.appendChild(el("span", `chip ${data.isScam ? "CRITICAL" : "LOW"}`, data.isScam ? "SCAM" : "NOT SCAM"));
      head.appendChild(el("span", "chip neutral", data.languageName));
      head.appendChild(el("span", "chip neutral", prettyCategory(data.category)));
      result.appendChild(head);

      const facts = el("div", "meta");
      [
        ["Rule score", data.score],
        ["Vernacular score", data.vernacularScore],
        ["Behaviour score", data.behaviorScore],
        ["Confidence", `${Math.round((data.confidence || 0) * 100)}%`],
        ["Language confidence", `${Math.round((data.languageConfidence || 0) * 100)}%`],
      ].forEach(([label, value]) => {
        const span = el("span");
        span.appendChild(document.createTextNode(`${label}: `));
        span.appendChild(el("b", null, value));
        facts.appendChild(span);
        facts.appendChild(document.createTextNode("  "));
      });
      result.appendChild(facts);

      const matched = (data.vernacularTerms || []).concat(data.behaviorIndicators || []);
      if (matched.length) {
        const tags = el("div", "indicator-tags");
        matched.forEach((term) => tags.appendChild(el("span", "tag", term)));
        result.appendChild(tags);
      }
    } catch (err) {
      clear(result);
      result.appendChild(el("div", "error", `Analysis failed: ${err.message}`));
    }
  });
}

/* ---------- scanners ---------- */

const URL_SCAN_SAMPLES = [
  ["Phishing (CRITICAL)", "http://sbi-kyc-verify.tk/login"],
  ["Brand lookalike (HIGH)", "https://hdfc-secure-banking.xyz/otp-verify"],
  ["IP host (CRITICAL)", "http://203.0.113.5:8080/pay"],
  ["Deep subdomain (MEDIUM)", "https://login.secure.verify.icici-bank.online/account"],
  ["Benign", "https://www.google.com"],
];

const EMAIL_SCAN_SAMPLES = [
  [
    "Display-name spoof",
    `From: SBI Bank <sbi.support@gmail.com>\nTo: customer@example.com\nSubject: Urgent KYC Update Required\n\nDear customer, your account will be suspended. Verify now at http://sbi-verify.tk/kyc`,
  ],
  [
    "Reply-To mismatch",
    `From: HDFC Alert <noreply@hdfcbank.com>\nReply-To: collect@gmail.com\nSubject: Account blocked — action required\n\nYour HDFC account is blocked. Click here to unblock: http://hdfc-unblock.xyz`,
  ],
  [
    "SPF fail + phishing link",
    `From: Income Tax Dept <refund@incometax.gov.in>\nAuthentication-Results: mx.example.com; spf=fail smtp.mailfrom=incometax.gov.in\nSubject: Tax refund of Rs 18,500 pending\n\nYour refund is ready. Submit your bank details at http://incometax-refund.tk/claim`,
  ],
];

function renderScanResult(container, scan, sessionId, label) {
  clear(container);

  const head = el("div", "session-row");
  head.style.marginBottom = "10px";
  const levelClass = { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INVALID: "neutral" }[scan.riskLevel] || "LOW";
  head.appendChild(el("span", `chip ${levelClass}`, scan.riskLevel));
  head.appendChild(el("span", "chip neutral", scan.category || "—"));
  head.appendChild(el("span", "chip neutral", `score ${scan.riskScore}/100`));
  if (sessionId) {
    head.appendChild(el("span", "chip technical", "→ correlated"));
  }
  container.appendChild(head);

  if (scan.indicators && scan.indicators.length) {
    const list = el("ul");
    list.style.cssText = "margin:8px 0 0;padding-left:18px;font-size:12px;color:var(--text-secondary)";
    scan.indicators.forEach((ind) => {
      const li = el("li", null, ind);
      li.style.marginBottom = "3px";
      list.appendChild(li);
    });
    container.appendChild(list);
  } else if (scan.riskScore < 20) {
    container.appendChild(el("div", "meta", `No suspicious signals detected — ${label} appears clean.`));
  }

  // Extra fields for email
  if (scan.subject) {
    const row = el("div", "meta");
    row.style.marginTop = "8px";
    [
      ["Subject", scan.subject],
      ["From domain", scan.fromDomain || "—"],
      ["SPF", scan.spfResult || "not detected"],
      ["DKIM", scan.dkimResult || "not detected"],
      ["DMARC", scan.dmarcResult || "not detected"],
    ].forEach(([k, v]) => {
      const span = el("span");
      span.appendChild(document.createTextNode(`${k}: `));
      span.appendChild(el("b", null, v));
      span.style.marginRight = "16px";
      row.appendChild(span);
    });
    container.appendChild(row);
  }

  // Extracted URLs
  if (scan.suspiciousUrls && scan.suspiciousUrls.length) {
    const tags = el("div", "indicator-tags");
    tags.appendChild(el("span", "tag-label", "suspicious URLs"));
    scan.suspiciousUrls.slice(0, 4).forEach((u) => tags.appendChild(el("span", "tag", u.slice(0, 60))));
    container.appendChild(tags);
  }

  if (sessionId) {
    const note = el("div", "meta");
    note.style.marginTop = "8px";
    note.appendChild(document.createTextNode("Ingested into correlation engine — "));
    const link = el("span", null, "refresh incidents ↑");
    link.style.cursor = "pointer";
    link.style.color = "var(--series-1)";
    link.addEventListener("click", refresh);
    note.appendChild(link);
    container.appendChild(note);
  }
}

function setupUrlScanner(apiKeyFn) {
  const form = document.getElementById("urlScanForm");
  const input = document.getElementById("urlScanInput");
  const result = document.getElementById("urlScanResult");
  const samples = document.getElementById("urlScanSamples");

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
      const headers = { "Content-Type": "application/json" };
      const key = apiKeyFn();
      if (key) headers["x-api-key"] = key;
      const resp = await fetch("/api/scan/url", {
        method: "POST",
        headers,
        body: JSON.stringify({ url }),
      });
      if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
      const data = await resp.json();
      renderScanResult(result, data.scan, data.sessionId, "URL");
      if (data.sessionId) await refresh();
    } catch (err) {
      clear(result);
      result.appendChild(el("div", "error", `Scan failed: ${err.message}`));
    }
  });
}

function setupEmailScanner(apiKeyFn) {
  const form = document.getElementById("emailScanForm");
  const input = document.getElementById("emailScanInput");
  const result = document.getElementById("emailScanResult");
  const samples = document.getElementById("emailScanSamples");

  EMAIL_SCAN_SAMPLES.forEach(([label]) => {
    const btn = el("button", null, label);
    btn.type = "button";
    const idx = EMAIL_SCAN_SAMPLES.findIndex(([l]) => l === label);
    btn.addEventListener("click", () => {
      input.value = EMAIL_SCAN_SAMPLES[idx][1];
      form.requestSubmit();
    });
    samples.appendChild(btn);
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawEmail = input.value.trim();
    if (!rawEmail) return;
    clear(result);
    result.appendChild(el("div", "meta", "Analysing…"));
    try {
      const headers = { "Content-Type": "application/json" };
      const key = apiKeyFn();
      if (key) headers["x-api-key"] = key;
      const resp = await fetch("/api/scan/email", {
        method: "POST",
        headers,
        body: JSON.stringify({ rawEmail }),
      });
      if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
      const data = await resp.json();
      renderScanResult(result, data.scan, data.sessionId, "Email");
      if (data.sessionId) await refresh();
    } catch (err) {
      clear(result);
      result.appendChild(el("div", "error", `Analysis failed: ${err.message}`));
    }
  });
}

/* ---------- loading ---------- */

async function loadSessionDetail(sessionId) {
  try {
    renderSessionDetail(await apiGet(`/dashboard/api/sessions/${encodeURIComponent(sessionId)}`));
  } catch (err) {
    if (String(err.message).startsWith("404")) {
      state.selectedSessionId = null;
    }
    const meta = document.getElementById("sessionMeta");
    clear(meta);
    meta.appendChild(el("span", "error", `Failed to load session: ${err.message}`));
  }
}

function setLiveStatus(ok, message) {
  const node = document.getElementById("liveStatus");
  node.className = ok ? "live-dot" : "live-dot stale";
  node.textContent = message;
}

async function refresh() {
  try {
    const [summary, sessions, incidents, map] = await Promise.all([
      apiGet("/dashboard/api/summary"),
      apiGet("/dashboard/api/sessions?limit=50"),
      apiGet("/dashboard/api/incidents"),
      apiGet("/dashboard/api/map"),
    ]);

    state.summary = summary;
    state.sessions = sessions;

    renderTiles(summary, incidents, sessions);
    renderIncidents(incidents);
    renderCharts(summary);
    renderSessions(sessions);
    renderMap(map);

    state.lastOk = Date.now();
    setLiveStatus(true, `live · ${new Date().toLocaleTimeString()}`);

    if (state.selectedSessionId) await loadSessionDetail(state.selectedSessionId);
  } catch (err) {
    setLiveStatus(false, `disconnected: ${err.message}`);
  }
}

/* Model chain changes rarely and the live listing is a slow outbound call,
   so it is loaded once rather than on every 5s tick. */
async function loadModels() {
  try {
    renderModels(await apiGet("/dashboard/api/models"));
  } catch (err) {
    renderModels({ configured: [], health: {}, liveFreeModels: [], apiKeyConfigured: false });
  }
}

function setupTheme() {
  const button = document.getElementById("themeBtn");
  const stored = localStorage.getItem("honeypotTheme");
  if (stored) document.documentElement.setAttribute("data-theme", stored);

  const sync = () => {
    const dark =
      document.documentElement.getAttribute("data-theme") === "dark" ||
      (!document.documentElement.getAttribute("data-theme") &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    button.textContent = dark ? "Light mode" : "Dark mode";
    return dark;
  };

  sync();
  button.addEventListener("click", () => {
    const dark = sync();
    const next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("honeypotTheme", next);
    sync();
    // Chart colours are read from CSS vars at draw time, so redraw after a swap.
    if (state.summary) renderCharts(state.summary);
  });
}

function start() {
  setupTheme();
  setupProbe();
  document.getElementById("refreshBtn").addEventListener("click", refresh);
  window.addEventListener("resize", () => {
    if (state.summary) renderCharts(state.summary);
  });

  // Scanners read the API key from localStorage (same store as the console).
  const getApiKey = () => localStorage.getItem("honeypotApiKey") || "";
  setupUrlScanner(getApiKey);
  setupEmailScanner(getApiKey);

  refresh();
  loadModels();
  setInterval(refresh, REFRESH_MS);
}

window.addEventListener("load", start);
