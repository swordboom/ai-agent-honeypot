/*
  SOC Console front-end.
  Read-only. Polls /dashboard/api/soc/* every 8s and renders the case queue,
  KPIs, UEBA entity risk, and a per-case investigation drawer. No framework, no
  CDN - hand-rolled DOM so it runs on a box with no outbound internet, matching
  the rest of the UI.
*/
(function () {
  "use strict";

  var REFRESH_MS = 8000;
  var selectedCaseId = null;
  var timer = null;

  function el(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function pill(cls, text) { return '<span class="pill ' + cls + '">' + esc(text) + "</span>"; }
  function fmtDur(s) {
    s = Number(s) || 0;
    if (s < 60) return s + "s";
    if (s < 3600) return Math.round(s / 60) + "m";
    return (s / 3600).toFixed(1) + "h";
  }
  function verdictLabel(v) { return String(v || "").replace(/_/g, " "); }

  function getJSON(url, opts) {
    return fetch(url, opts || {}).then(function (r) {
      if (!r.ok) throw new Error(r.status + " " + url);
      return r.json();
    });
  }

  // ---- KPIs ---------------------------------------------------------------
  function renderKpis(k) {
    var tiles = [
      { label: "Open cases", value: k.openCases, cls: k.openCases ? "crit" : "good", hint: "awaiting an analyst" },
      { label: "Contained", value: k.containedCases, cls: "good", hint: "sessions finalised" },
      { label: "Analyst queue", value: k.analystQueueDepth, cls: k.analystQueueDepth ? "warn" : "good", hint: "action-required cases" },
      { label: "Confirmed threats", value: k.confirmedThreats, cls: "crit", hint: "verdict: true positive" },
      { label: "Automation rate", value: k.automationRatePercent, unit: "%", cls: "accent", hint: "handled without a human" },
      { label: "Noise reduction", value: k.noiseReductionPercent, unit: "%", cls: "accent", hint: "raw volume filtered" },
      { label: "Mean containment", value: fmtDur(k.meanContainmentSeconds), cls: "", hint: "MTTR proxy", raw: true },
      { label: "Tracked entities", value: k.trackedEntities, cls: "", hint: "under UEBA" }
    ];
    el("kpis").innerHTML = tiles.map(function (t) {
      var val = t.raw ? esc(t.value) : esc(t.value) + (t.unit ? '<small>' + t.unit + "</small>" : "");
      return '<div class="kpi ' + t.cls + '">' +
        '<div class="label">' + esc(t.label) + "</div>" +
        '<div class="value">' + val + "</div>" +
        '<div class="hint">' + esc(t.hint) + "</div></div>";
    }).join("");
  }

  // ---- Case queue ---------------------------------------------------------
  function renderCases(cases) {
    el("caseCount").textContent = cases.length + " case" + (cases.length === 1 ? "" : "s");
    if (!cases.length) {
      el("casesWrap").innerHTML = '<div class="empty">No cases yet. Feed events via the console or /api/ingest.</div>';
      return;
    }
    var rows = cases.map(function (c) {
      var sel = c.incidentId === selectedCaseId ? " selected" : "";
      return '<tr class="caserow' + sel + '" data-id="' + esc(c.incidentId) + '">' +
        "<td>" + pill("sev-" + c.severity, c.severity) +
          '<div class="mono" style="margin-top:4px;color:var(--text-muted)">' + esc(c.incidentId) + "</div></td>" +
        "<td>" + esc(c.name || c.scamCategory || "—") +
          '<div style="margin-top:4px">' + pill("src-" + c.sourceType, c.sourceType) +
          " " + pill("verdict-" + c.verdict, verdictLabel(c.verdict)) + "</div></td>" +
        '<td class="mono">' + Math.round((c.investigationConfidence || 0) * 100) + "%</td>" +
        '<td><span class="status-' + c.status + '">' + esc(c.status.replace(/_/g, " ")) + "</span>" +
          '<div class="meta" style="color:var(--text-muted);font-size:11.5px">' + esc(c.owner || "") + "</div></td>" +
        '<td class="mono">' + (c.slaMinutes != null ? c.slaMinutes + "m" : "—") + "</td>" +
        "</tr>";
    }).join("");
    el("casesWrap").innerHTML =
      "<table><thead><tr><th>Severity</th><th>Case</th><th>Conf.</th><th>Status / owner</th><th>SLA</th></tr></thead>" +
      "<tbody>" + rows + "</tbody></table>";
    Array.prototype.forEach.call(document.querySelectorAll(".caserow"), function (tr) {
      tr.addEventListener("click", function () { openCase(tr.getAttribute("data-id")); });
    });
  }

  // ---- Entities (UEBA) ----------------------------------------------------
  function renderEntities(entities) {
    el("entCount").textContent = entities.length;
    if (!entities.length) {
      el("entitiesWrap").innerHTML = '<div class="empty">No entities under analysis yet.</div>';
      return;
    }
    el("entitiesWrap").innerHTML = entities.map(function (e) {
      var sig = (e.signals && e.signals[0]) || "";
      return '<div class="entity">' +
        '<div class="row1"><span class="ename">' + esc(e.entity) + "</span>" +
          pill("band-" + e.riskBand, e.anomalyScore) + "</div>" +
        '<div class="sig">' + esc(sig) + "</div>" +
        '<div class="bar"><i style="width:' + Math.min(100, e.anomalyScore) + '%"></i></div></div>';
    }).join("");
  }

  // ---- Case drawer --------------------------------------------------------
  function openCase(id) {
    selectedCaseId = id;
    Array.prototype.forEach.call(document.querySelectorAll(".caserow"), function (tr) {
      tr.classList.toggle("selected", tr.getAttribute("data-id") === id);
    });
    el("overlay").classList.add("open");
    el("drawer").classList.add("open");
    el("drawer").setAttribute("aria-hidden", "false");
    el("dBody").innerHTML = '<div class="loading">Loading case…</div>';
    el("dTitle").textContent = id;
    el("dTags").innerHTML = "";
    getJSON("/dashboard/api/soc/case/" + encodeURIComponent(id)).then(renderCaseDetail).catch(function (e) {
      el("dBody").innerHTML = '<div class="empty">' + esc(e.message) + "</div>";
    });
  }

  function closeDrawer() {
    selectedCaseId = null;
    el("overlay").classList.remove("open");
    el("drawer").classList.remove("open");
    el("drawer").setAttribute("aria-hidden", "true");
    Array.prototype.forEach.call(document.querySelectorAll(".caserow"), function (tr) {
      tr.classList.remove("selected");
    });
  }

  function renderCaseDetail(c) {
    var inv = c.investigation || {};
    el("dTitle").textContent = c.name || c.incidentId;
    el("dTags").innerHTML =
      pill("sev-" + c.severity, c.severity + " · " + c.severityScore) + " " +
      pill("src-" + c.sourceType, c.sourceType) + " " +
      pill("verdict-" + inv.verdict, verdictLabel(inv.verdict) + " · " + Math.round((inv.confidence || 0) * 100) + "%");

    var html = "";

    html += '<div class="sec"><h4>Automated assessment</h4><div class="narrative">' +
      esc(inv.narrative || "") + "</div></div>";

    html += '<div class="sec"><h4>Case facts</h4><dl class="kv">' +
      "<dt>Status</dt><dd class=\"status-" + c.status + '">' + esc(c.status.replace(/_/g, " ")) + "</dd>" +
      "<dt>Owner</dt><dd>" + esc(c.owner || "—") + "</dd>" +
      "<dt>Category</dt><dd>" + esc(c.scamCategory || "—") + "</dd>" +
      "<dt>Sessions</dt><dd>" + c.sessionCount + "</dd>" +
      "<dt>Duration</dt><dd>" + fmtDur(c.durationSeconds) + "</dd>" +
      "<dt>Feed hits</dt><dd>" + (inv.feedHitCount || 0) + "</dd>" +
      "<dt>Correlated on</dt><dd class=\"mono\">" + esc((c.correlatedOn || []).join(", ") || "—") + "</dd>" +
      "</dl></div>";

    if (inv.timeline && inv.timeline.length) {
      html += '<div class="sec"><h4>Investigation timeline</h4><ul class="tl">' +
        inv.timeline.map(function (t) {
          var d = new Date(t.timestamp * 1000);
          return "<li><span class=\"t\">" + esc(d.toISOString().replace("T", " ").slice(0, 19)) +
            " · " + esc(t.source) + "</span><div>" + esc(t.summary) + "</div></li>";
        }).join("") + "</ul></div>";
    }

    if (inv.enrichments && inv.enrichments.length) {
      html += '<div class="sec"><h4>Indicator enrichment</h4>' +
        inv.enrichments.map(function (e) {
          return '<div class="enr"><div class="r1"><span class="ev">' + esc(e.value) + "</span>" +
            pill("verdict-" + (e.verdict === "MALICIOUS" ? "TRUE_POSITIVE" : e.verdict === "SUSPICIOUS" ? "LIKELY_THREAT" : "INCONCLUSIVE"), e.verdict + " · " + e.score) +
            "</div><div class=\"reasons\">" + esc((e.reasons || []).slice(0, 3).join(" ")) + "</div></div>";
        }).join("") + "</div>";
    }

    if (inv.entityProfiles && inv.entityProfiles.length) {
      html += '<div class="sec"><h4>Entity behaviour</h4>' +
        inv.entityProfiles.slice(0, 6).map(function (p) {
          return '<div class="enr"><div class="r1"><span class="ev">' + esc(p.entity) + "</span>" +
            pill("band-" + p.riskBand, "anomaly " + p.anomalyScore) + "</div>" +
            '<div class="reasons">' + esc((p.signals || []).slice(0, 2).join(" ")) + "</div></div>";
        }).join("") + "</div>";
    }

    if (c.responsePlan && c.responsePlan.length) {
      html += '<div class="sec"><h4>Response plan</h4>' +
        c.responsePlan.map(function (a) {
          return '<div class="action-row"><span class="p">p' + a.priority + "</span>" +
            '<div><span class="a">' + esc(a.action) + "</span> → <span class=\"mono\">" + esc(a.target) + "</span>" +
            '<div class="meta">' + esc(a.owner) + " · SLA " + a.slaMinutes + "m · " + esc(a.rationale) + "</div></div></div>";
        }).join("") + "</div>";
    }

    if (inv.nextSteps && inv.nextSteps.length) {
      html += '<div class="sec"><h4>Next investigative steps</h4><ul class="steps">' +
        inv.nextSteps.map(function (s) { return "<li>" + esc(s) + "</li>"; }).join("") + "</ul></div>";
    }

    el("dBody").innerHTML = html;
  }

  // ---- Enrich box ---------------------------------------------------------
  function runEnrich() {
    var kind = el("enrichKind").value;
    var value = el("enrichValue").value.trim();
    if (!value) return;
    el("enrichResult").textContent = "Enriching…";
    getJSON("/dashboard/api/soc/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: kind, value: value })
    }).then(function (r) {
      el("enrichResult").innerHTML =
        pill("verdict-" + (r.verdict === "MALICIOUS" ? "TRUE_POSITIVE" : r.verdict === "SUSPICIOUS" ? "LIKELY_THREAT" : r.verdict === "BENIGN" ? "LIKELY_BENIGN" : "INCONCLUSIVE"), r.verdict + " · " + r.score) +
        " " + esc((r.reasons || []).join(" "));
    }).catch(function (e) { el("enrichResult").textContent = e.message; });
  }

  // ---- Poll ---------------------------------------------------------------
  function refresh() {
    getJSON("/dashboard/api/soc/overview").then(function (d) {
      renderKpis(d.kpis || {});
      renderCases(d.cases || []);
      renderEntities(d.topEntities || []);
      el("refreshNote").textContent = "updated " + new Date().toLocaleTimeString();
    }).catch(function (e) {
      el("refreshNote").textContent = "offline: " + e.message;
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    el("dClose").addEventListener("click", closeDrawer);
    el("overlay").addEventListener("click", closeDrawer);
    el("enrichBtn").addEventListener("click", runEnrich);
    el("enrichValue").addEventListener("keydown", function (e) { if (e.key === "Enter") runEnrich(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });
    refresh();
    timer = setInterval(refresh, REFRESH_MS);
  });
})();
