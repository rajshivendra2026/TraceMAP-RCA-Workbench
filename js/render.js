/***************************************************************
 * TRACE MAP RCA — RENDER ENGINE v3 (FINAL STABLE)
 *
 * Merged from:
 *   - v2 fixed (all 10 bug fixes)
 *   - your FINAL STABLE attempt (numbered two-line session cards,
 *     RCA label first, _makeSVGEl/_setText helpers)
 *
 * All 14 issues resolved. See inline FIX tags.
 ***************************************************************/

/* FIX [9]: guard — filters belong in state.js, this is a safety net only */
if (typeof STATE !== "undefined" && !STATE.filters) {
  STATE.filters = { sessionType: "ALL", search: "", protocol: "ALL" };
}

/* ════════════════════════════════════════════════════════════════
   PROTOCOL STYLES
   ════════════════════════════════════════════════════════════════ */
const PROTOCOL_STYLE = {
  SIP:      { color: "#3b82f6" },
  DIAMETER: { color: "#ef4444" },
  INAP:     { color: "#10b981" },
  S1AP:     { color: "#f59e0b" },
  NGAP:     { color: "#0ea5e9" },
  GTP:      { color: "#14b8a6" },
  RANAP:    { color: "#22c55e" },
  BSSAP:    { color: "#84cc16" },
  MAP:      { color: "#65a30d" },
  RADIUS:   { color: "#8b5cf6" },
  HTTP:     { color: "#a855f7" },
  DNS:      { color: "#2563eb" },
  ICMP:     { color: "#7c3aed" },
  NAS_EPS:  { color: "#f59e0b" },
  NAS_5GS:  { color: "#06b6d4" },
  TCP:      { color: "#f97316" },
  UDP:      { color: "#eab308" },
  SCTP:     { color: "#0f766e" },
  PFCP:     { color: "#ec4899" },
};

const NODE_TYPE_STYLE = {
  UE:       { background: "#facc15", border: "#f59e0b", text: "#111827" },
  CORE:     { background: "#3b82f6", border: "#1d4ed8", text: "#eff6ff" },
  IMS:      { background: "#8b5cf6", border: "#6d28d9", text: "#f5f3ff" },
  EXTERNAL: { background: "#14b8a6", border: "#0f766e", text: "#ecfeff" },
  UNKNOWN:  { background: "#94a3b8", border: "#64748b", text: "#f8fafc" },
  NODE:     { background: "#60a5fa", border: "#2563eb", text: "#eff6ff" },
};

const FAILURE_COLOR  = "#dc2626";
const LIFELINE_COLOR = "#e2e8f0";
const FONT_FAMILY    = "'JetBrains Mono', 'Consolas', monospace";

/* ════════════════════════════════════════════════════════════════
   VIEW SWITCH
   ════════════════════════════════════════════════════════════════ */
function setView(mode) {
  STATE.viewMode = mode;
  const buttons = document.querySelectorAll(".view-toggle button");
  buttons.forEach(button => {
    const matches = button.textContent.toLowerCase().includes(mode);
    button.classList.toggle("active", matches);
  });

  const lv = document.getElementById("ladderView");
  const gv = document.getElementById("graphView");
  if (lv) lv.style.display = mode === "ladder" ? "block" : "none";
  if (gv) gv.style.display = mode === "ladder" ? "none" : "block";

  if (mode !== "ladder") renderGraph();
}

/* ════════════════════════════════════════════════════════════════
   SESSION LIST
   ════════════════════════════════════════════════════════════════ */
function renderSessions() {
  const list = document.getElementById("sessionList");
  if (!list) return;
  list.innerHTML = "";
  if (typeof window.traceDebug === "function") {
    window.traceDebug("renderSessions.start", {
      total: Array.isArray(STATE.sessions) ? STATE.sessions.length : -1,
      selected: STATE.selected?.call_id || null,
    });
  }

  let sessions = [...(STATE.sessions || [])];
  const isNormal = session => session.rca_label === "NORMAL_CALL";

  if (STATE.filters.sessionType === "FAILED") {
    sessions = sessions.filter(s => !isNormal(s));
  } else if (STATE.filters.sessionType === "SUCCESS") {
    sessions = sessions.filter(isNormal);
  }

  if (STATE.filters.protocol !== "ALL") {
    sessions = sessions.filter(s =>
      (s.protocols || []).some(p => String(p).toUpperCase() === STATE.filters.protocol)
    );
  }

  if (STATE.filters.search) {
    const q = STATE.filters.search.toLowerCase();
    sessions = sessions.filter(s =>
      (s.call_id || "").toLowerCase().includes(q) ||
      (s.imsi || "").toLowerCase().includes(q) ||
      (s.msisdn || "").toLowerCase().includes(q) ||
      (s.rca_title || s.rca_label || "").toLowerCase().includes(q) ||
      (s.details_summary?.call_type || "").toLowerCase().includes(q) ||
      (s.details_summary?.a_party || "").toLowerCase().includes(q) ||
      (s.details_summary?.b_party || "").toLowerCase().includes(q) ||
      (s.protocols || []).some(p => String(p).toLowerCase().includes(q)) ||
      (s.technologies || []).some(t => String(t).toLowerCase().includes(q))
    );
  }

  sessions.sort((left, right) => {
    const priorityDelta = Number(right.priority_score || 0) - Number(left.priority_score || 0);
    if (priorityDelta !== 0) return priorityDelta;
    return Number(right.confidence || 0) - Number(left.confidence || 0);
  });

  if (!sessions.length) {
    list.innerHTML = `<div class="empty-state">No sessions found</div>`;
    if (typeof window.traceDebug === "function") {
      window.traceDebug("renderSessions.empty", {
        filteredTotal: 0,
        stateTotal: Array.isArray(STATE.sessions) ? STATE.sessions.length : -1,
      });
    }
    return;
  }

  /* YOUR UX IMPROVEMENT: numbered two-line cards, RCA label first */
  sessions.slice(0, 100).forEach((s, i) => {
    const div = document.createElement("div");
    div.className = "session" + (STATE.selected?.call_id === s.call_id ? " active" : "");

    const code   = s.final_sip_code || "-";
    const isFail = /^[45]/.test(code);
    const badge  = `<span class="sip-badge ${isFail ? "fail" : "ok"}">${code}</span>`;
    const rca    = s.rca_title || s.rca_label || "Unknown";
    const callId = (s.call_id || "").slice(0, 25);
    const callType = s.details_summary?.call_type || "Generic session";
    const priority = Math.round(Number(s.priority_score || 0));
    const priorityBand = String(s.priority_band || "low").toLowerCase();
    const priorityBadge = `<span class="priority-pill ${priorityBand}">P${priority}</span>`;
    const chips = [
      priorityBadge,
      ...(s.protocols || []).slice(0, 3).map(p => `<span class="chip">${String(p).toUpperCase()}</span>`),
      ...(s.technologies || []).slice(0, 2).map(t => `<span class="chip">${t}</span>`),
    ].join("");

    div.innerHTML = `
      <div class="session-line1">
        <span class="session-index">${i + 1}.</span>
        <span class="rca-label">${rca}</span>
        ${badge}
      </div>
      <div class="session-line2">${callId}</div>
      <div class="session-line2">${callType}</div>
      <div class="session-line2">${s.priority_reason || "baseline inspection"}</div>
      <div class="session-meta">${chips}</div>
    `;

    div.onclick = () => selectSession(s);
    list.appendChild(div);
  });
  if (typeof window.traceDebug === "function") {
    window.traceDebug("renderSessions.done", {
      rendered: Math.min(sessions.length, 100),
      stateTotal: Array.isArray(STATE.sessions) ? STATE.sessions.length : -1,
    });
  }
}

function renderOverview() {
  const sessions = STATE.sessions || [];
  const summary = STATE.summary || {};
  const kpis = summary.kpis || {};
  if (typeof window.traceDebug === "function") {
    window.traceDebug("renderOverview", {
      filename: STATE.filename || "",
      sessions: sessions.length,
      summaryKeys: Object.keys(summary || {}).length,
    });
  }

  _setText("kpiTotalSessions", String(kpis.total_sessions ?? sessions.length));
  _setText("kpiTotalPackets", _formatNumber(kpis.total_packets ?? 0));
  _setText("kpiProtocolsSeen", String(kpis.protocols_seen ?? 0));
  _setText("kpiTechSeen", String(kpis.technologies_seen ?? 0));
  _setText("kpiSuccessSessions", String(kpis.successful_sessions ?? 0));
  _setText("kpiFailedSessions", String(kpis.failed_sessions ?? 0));
  _setText("kpiAvgDuration", `${Math.round(kpis.avg_duration_ms ?? 0)} ms`);
  _setText("kpiTopRca", String(kpis.top_rca ?? "-"));
  _setText("kpiTopProtocol", String(kpis.top_protocol ?? "-"));
  _setText("kpiImsSessions", String(kpis.ims_sessions ?? 0));
  _setText("kpi2g3g", String(kpis.radio_2g_3g ?? 0));
  _setText("kpi4g", String(kpis.radio_4g ?? 0));
  _setText("kpi5g", String(kpis.radio_5g ?? 0));
  _setText("kpiTcpIssues", String(kpis.tcp_issues ?? 0));
  _setText("kpiHttpHttps", String(kpis.http_https_messages ?? 0));
  _setText("kpiSctp", String(kpis.sctp_messages ?? 0));
  _setText("fileName", STATE.filename || "");

  _renderTraceOverview(summary.details || null);
  _renderMetricList("protocolMix", summary.protocol_counts || {});
  _renderMetricList("technologyMix", summary.technology_counts || {});
  _renderEndpointList("topEndpoints", summary.top_endpoints || []);
  _renderMetricList("rcaDistribution", summary.rca_distribution || {});
  _renderExpertFindings(summary.expert_findings || [], sessions);
  _renderErrorAnalysis(summary.error_analysis || null);
  _renderTrafficTrendChart(sessions, summary.protocol_counts || {});
  _renderProtocolShareChart(summary.protocol_counts || {});
  _renderDurationProfileChart(sessions);
}

function hydrateFromState() {
  if (typeof window.traceDebug === "function") {
    window.traceDebug("hydrateFromState.start", {
      filename: STATE.filename || "",
      sessions: Array.isArray(STATE.sessions) ? STATE.sessions.length : -1,
      hydrationPending: Boolean(STATE.hydrationPending),
    });
  }
  STATE.sessions = Array.isArray(STATE.sessions) ? STATE.sessions : [];
  STATE.sessions.sort((left, right) => {
    const priorityDelta = Number(right.priority_score || 0) - Number(left.priority_score || 0);
    if (priorityDelta !== 0) return priorityDelta;
    return Number(right.confidence || 0) - Number(left.confidence || 0);
  });

  renderOverview();
  _renderDetails(STATE.summary?.details || null, true);
  renderSessions();

  if (typeof window.refreshValidationQueue === "function") {
    window.refreshValidationQueue();
  }

  if (STATE.sessions.length) {
    selectSession(STATE.sessions[0]);
  }

  STATE.hydrationPending = false;
  if (typeof window.traceDebug === "function") {
    window.traceDebug("hydrateFromState.done", {
      filename: STATE.filename || "",
      sessions: STATE.sessions.length,
      selected: STATE.selected?.call_id || null,
    });
  }
}

/* ════════════════════════════════════════════════════════════════
   SELECT SESSION
   ════════════════════════════════════════════════════════════════ */
function selectSession(s) {
  if (typeof window.traceDebug === "function") {
    window.traceDebug("selectSession", {
      callId: s?.call_id || null,
      rca: s?.rca_label || null,
    });
  }
  STATE.selected = s;
  STATE.graph = s.graph || STATE.captureGraph || null;

  _setText("rcaTitle",      s.rca_title        || s.rca_label || "Unknown");
  _setText("rcaSummary",    s.rca_summary      || "No session summary available.");
  _setText("rcaPriority",   `Priority P${Math.round(Number(s.priority_score || 0))} · ${String(s.priority_band || "low").toUpperCase()}`);
  _setText("rcaConfidence", `Confidence ${s.confidence || 0}%`);
  _setText("rcaSeverity",   `Severity ${s.severity || "N/A"}`);
  _setText("rcaRule",       s.rule_id || "Rule unavailable");
  _setText("rcaNarrative",  s.analyst_brief || s.rca_detail || "Detailed RCA narrative is not available for this session.");
  _setText("corr",          s.dia_correlation || "No correlation");
  _setText("tech",          (s.technologies || []).join(", ") || "Unknown technology");
  _renderEvidence(s.evidence || []);
  _renderActions(s.recommendations || []);
  _renderDetails(s.details_summary || null, false);
  _renderAgentVotes(s.agentic_analysis || null);
  _renderCausalChain(s.causal_analysis || null);
  _renderConfidenceModel(s.confidence_model || null);
  _renderKnowledgeSignals(s);

  /* FIX [7]: never pass flow_summary (string) to renderLadder */
  renderLadder(Array.isArray(s.flow) ? s.flow : []);
  if (STATE.viewMode !== "ladder") renderGraph();

  renderSessions(); /* refresh active highlight */
}

/* ════════════════════════════════════════════════════════════════
   GRAPH
   ════════════════════════════════════════════════════════════════ */
function renderGraph() {
  const container = document.getElementById("graphContainer");
  if (!container) return;
  const title = document.getElementById("graphTitle");
  const subtitle = document.getElementById("graphSubtitle");
  const isCausal = STATE.viewMode === "causal";

  if (title) title.innerText = isCausal ? "Session Causal Graph" : "Session Interaction Graph";
  if (subtitle) {
    subtitle.innerText = isCausal
      ? "Protocol event chain with weighted causal links and failure propagation"
      : "Analyst-style endpoint topology with aggregated protocol paths";
  }

  _renderGraphStats(null);
  _renderGraphLegend([], []);
  _setGraphSelection(
    isCausal
      ? "Click a causal event or edge to inspect how the RCA chain was formed."
      : "Click a node or protocol path to inspect endpoints, traffic mix, and sample messages."
  );

  const graphPayload = isCausal ? (STATE.selected?.causal_graph || null) : (STATE.graph || null);

  if (!graphPayload?.nodes?.length) {
    if (STATE.graphNetwork) {
      STATE.graphNetwork.destroy();
      STATE.graphNetwork = null;
    }
    container.innerText = isCausal ? "No causal graph data" : "No graph data";
    return;
  }

  container.innerHTML = "";

  if (typeof vis === "undefined") {
    container.innerText = "Graph library (vis.js) not loaded.";
    console.error("vis.js is not available");
    return;
  }

  try {
    const model = isCausal ? _buildCausalGraphModel(graphPayload) : _buildGraphModel(graphPayload);
    const nodes = new vis.DataSet(model.nodes);
    const edges = new vis.DataSet(model.edges);

    if (STATE.graphNetwork) {
      STATE.graphNetwork.destroy();
    }

    STATE.graphNetwork = new vis.Network(
      container,
      { nodes, edges },
      _graphOptions()
    );

    _bindGraphEvents(STATE.graphNetwork, model);
    _bindGraphActions(model);
    _renderGraphStats(model);
    _renderGraphLegend(model.protocols, model.nodeTypes);
  } catch (err) {
    container.innerText = "Graph render error: " + err.message;
    console.error("renderGraph:", err);
  }
}

function _buildGraphModel(graph) {
  const nodeSource = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edgeSource = Array.isArray(graph?.edges) ? graph.edges : [];
  const degree = new Map();
  const edgesByKey = new Map();

  edgeSource.forEach(edge => {
    const from = edge.source;
    const to = edge.target;
    const protocol = String(edge.protocol || "GENERIC").toUpperCase();
    if (!from || !to) return;

    degree.set(from, (degree.get(from) || 0) + 1);
    degree.set(to, (degree.get(to) || 0) + 1);

    const edgeKey = `${from}→${to}::${protocol}`;
    const pairKey = [from, to].sort().join("::");
    if (!edgesByKey.has(edgeKey)) {
      edgesByKey.set(edgeKey, {
        id: edgeKey,
        from,
        to,
        protocol,
        count: 0,
        messages: new Set(),
        sampleTimes: [],
        pairKey,
      });
    }
    const entry = edgesByKey.get(edgeKey);
    entry.count += 1;
    if (edge.label) entry.messages.add(String(edge.label));
    if (edge.time !== undefined && edge.time !== null) entry.sampleTimes.push(edge.time);
  });

  const protocolSet = new Set();
  const nodeTypeSet = new Set();
  const nodes = nodeSource.map(node => {
    const type = String(node.type || "NODE").toUpperCase();
    const style = NODE_TYPE_STYLE[type] || NODE_TYPE_STYLE.NODE;
    const activity = Math.max(node.count || 0, degree.get(node.id) || 0, 1);
    nodeTypeSet.add(type);

    return {
      id: node.id,
      label: _formatGraphNodeLabel(node.label || node.id, type, activity),
      title: `${type}\n${node.label || node.id}\nActivity ${activity}`,
      shape: "dot",
      size: Math.min(46, 18 + activity * 1.8),
      mass: Math.max(1, activity / 2),
      color: {
        background: style.background,
        border: style.border,
        highlight: {
          background: style.background,
          border: "#f8fafc",
        },
        hover: {
          background: style.background,
          border: "#e2e8f0",
        },
      },
      font: {
        color: style.text,
        face: "JetBrains Mono",
        size: 13,
        bold: activity >= 6,
      },
      borderWidth: 2,
      borderWidthSelected: 3,
      shadow: {
        enabled: true,
        color: "rgba(15, 23, 42, 0.35)",
        size: 12,
        x: 0,
        y: 6,
      },
    };
  });

  const pairIndex = new Map();
  const edges = [...edgesByKey.values()].map(edge => {
    protocolSet.add(edge.protocol);
    const style = PROTOCOL_STYLE[edge.protocol] || { color: "#94a3b8" };
    const index = pairIndex.get(edge.pairKey) || 0;
    pairIndex.set(edge.pairKey, index + 1);
    const direction = index % 2 === 0 ? "curvedCW" : "curvedCCW";
    const roundness = Math.min(0.45, 0.14 + Math.floor(index / 2) * 0.07);
    const samples = [...edge.messages].slice(0, 3);
    const suffix = edge.messages.size > 3 ? `\n+${edge.messages.size - 3} more` : "";

    return {
      id: edge.id,
      from: edge.from,
      to: edge.to,
      arrows: { to: { enabled: true, scaleFactor: 0.8 } },
      label: edge.count > 1 ? `${edge.protocol} x${edge.count}` : edge.protocol,
      protocol: edge.protocol,
      count: edge.count,
      messages: [...edge.messages],
      color: {
        color: style.color,
        highlight: style.color,
        hover: style.color,
        opacity: 0.95,
      },
      width: Math.min(8, 1.8 + edge.count * 0.35),
      selectionWidth: 1.5,
      font: {
        color: "#dbeafe",
        size: 12,
        face: "JetBrains Mono",
        strokeWidth: 0,
        background: "rgba(15, 23, 42, 0.75)",
      },
      smooth: {
        enabled: true,
        type: direction,
        roundness,
      },
      title: `${edge.protocol} (${edge.count})\n${edge.from} → ${edge.to}${samples.length ? `\n${samples.join("\n")}${suffix}` : ""}`,
    };
  });

  return {
    kind: "interaction",
    nodes,
    edges,
    protocols: [...protocolSet].sort(),
    nodeTypes: [...nodeTypeSet].sort(),
    stats: {
      nodes: nodes.length,
      edges: edges.length,
      messages: edgeSource.length,
      protocols: protocolSet.size,
    },
    nodeMeta: new Map(nodes.map(node => [node.id, node])),
    edgeMeta: new Map(edges.map(edge => [edge.id, edge])),
  };
}

function _buildCausalGraphModel(graph) {
  const nodeSource = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edgeSource = Array.isArray(graph?.edges) ? graph.edges : [];
  const protocolSet = new Set();

  const nodes = nodeSource.map(node => {
    const protocol = String(node.protocol || "EVENT").toUpperCase();
    const style = PROTOCOL_STYLE[protocol] || { color: "#6366f1" };
    protocolSet.add(protocol);
    return {
      id: node.id,
      label: `${protocol}\n${String(node.message || "Event").slice(0, 28)}\nscore ${Math.round((Number(node.score || 0)) * 100)}%`,
      title: `${node.event || node.id}\n${node.src || "—"} → ${node.dst || "—"}`,
      shape: node.failure ? "diamond" : "box",
      size: node.failure ? 28 : 22,
      color: {
        background: node.failure ? "rgba(220, 38, 38, 0.92)" : `${style.color}dd`,
        border: node.failure ? "#fecaca" : "#e2e8f0",
        highlight: {
          background: node.failure ? "#ef4444" : style.color,
          border: "#f8fafc",
        },
      },
      font: {
        color: "#f8fafc",
        face: "JetBrains Mono",
        size: 12,
      },
      borderWidth: 2,
      margin: 10,
      shadow: {
        enabled: true,
        color: "rgba(15, 23, 42, 0.35)",
        size: 10,
        x: 0,
        y: 6,
      },
      raw: node,
    };
  });

  const edges = edgeSource.map((edge, idx) => ({
    id: edge.id || `causal-${idx}`,
    from: edge.source,
    to: edge.target,
    arrows: { to: { enabled: true, scaleFactor: 0.8 } },
    label: `${Math.round((Number(edge.weight || 0)) * 100)}%`,
    width: Math.max(1.5, Number(edge.weight || 0) * 6),
    color: {
      color: "rgba(96, 165, 250, 0.92)",
      highlight: "#93c5fd",
      hover: "#bfdbfe",
      opacity: 0.95,
    },
    dashes: Number(edge.weight || 0) < 0.35,
    font: {
      color: "#dbeafe",
      size: 11,
      face: "JetBrains Mono",
      background: "rgba(15, 23, 42, 0.75)",
      strokeWidth: 0,
    },
    smooth: {
      enabled: true,
      type: "cubicBezier",
      roundness: 0.18,
    },
    title: `${edge.type || "precedes"}\nweight ${(Number(edge.weight || 0) * 100).toFixed(1)}%\ngap ${Number(edge.gap_ms || 0).toFixed(1)} ms`,
    raw: edge,
  }));

  return {
    kind: "causal",
    nodes,
    edges,
    protocols: [...protocolSet].sort(),
    nodeTypes: ["EVENT", "FAILURE"],
    stats: {
      nodes: nodes.length,
      edges: edges.length,
      messages: nodes.length,
      protocols: protocolSet.size,
    },
    nodeMeta: new Map(nodes.map(node => [node.id, node])),
    edgeMeta: new Map(edges.map(edge => [edge.id, edge])),
  };
}

function _graphOptions() {
  return {
    autoResize: true,
    layout: {
      improvedLayout: true,
      randomSeed: 14,
    },
    interaction: {
      hover: true,
      multiselect: false,
      navigationButtons: true,
      keyboard: true,
      tooltipDelay: 120,
    },
    nodes: {
      shape: "dot",
    },
    edges: {
      arrows: "to",
      chosen: {
        edge(values) {
          values.width += 1.2;
        },
      },
    },
    physics: {
      enabled: STATE.graphPhysicsEnabled !== false,
      barnesHut: {
        gravitationalConstant: -12000,
        centralGravity: 0.15,
        springLength: 185,
        springConstant: 0.04,
        damping: 0.18,
        avoidOverlap: 0.9,
      },
      stabilization: {
        enabled: true,
        iterations: 280,
        fit: true,
      },
    },
  };
}

function _bindGraphEvents(network, model) {
  network.once("stabilizationIterationsDone", () => {
    network.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
  });

  network.on("click", params => {
    if (params.nodes?.length) {
      const node = model.nodeMeta.get(params.nodes[0]);
      if (node) {
        if (model.kind === "causal") _showCausalNodeDetails(node);
        else _showGraphNodeDetails(node, model);
      }
      return;
    }
    if (params.edges?.length) {
      const edge = model.edgeMeta.get(params.edges[0]);
      if (edge) {
        if (model.kind === "causal") _showCausalEdgeDetails(edge);
        else _showGraphEdgeDetails(edge);
      }
      return;
    }
    _setGraphSelection(
      model.kind === "causal"
        ? "Click a causal event or edge to inspect how the RCA chain was formed."
        : "Click a node or protocol path to inspect endpoints, traffic mix, and sample messages."
    );
  });

  network.on("doubleClick", params => {
    if (params.nodes?.length) {
      network.focus(params.nodes[0], {
        scale: 1.1,
        animation: { duration: 300, easingFunction: "easeInOutQuad" },
      });
    }
  });
}

function _bindGraphActions(model) {
  const fitBtn = document.getElementById("graphFitBtn");
  const physicsBtn = document.getElementById("graphPhysicsBtn");

  if (fitBtn) {
    fitBtn.onclick = () => {
      if (STATE.graphNetwork) {
        STATE.graphNetwork.fit({ animation: { duration: 350, easingFunction: "easeInOutQuad" } });
      }
    };
  }

  if (physicsBtn) {
    physicsBtn.innerText = STATE.graphPhysicsEnabled ? "Pause Physics" : "Resume Physics";
    physicsBtn.onclick = () => {
      STATE.graphPhysicsEnabled = !STATE.graphPhysicsEnabled;
      if (STATE.graphNetwork) {
        STATE.graphNetwork.setOptions({ physics: { enabled: STATE.graphPhysicsEnabled } });
      }
      physicsBtn.innerText = STATE.graphPhysicsEnabled ? "Pause Physics" : "Resume Physics";
      if (STATE.graphPhysicsEnabled && STATE.graphNetwork) {
        STATE.graphNetwork.stabilize(120);
      }
    };
  }
}

function _renderGraphStats(model) {
  const el = document.getElementById("graphStats");
  if (!el) return;
  if (!model) {
    el.innerHTML = "";
    return;
  }

  const stats = [
    ["Endpoints", model.stats.nodes],
    ["Paths", model.stats.edges],
    ["Messages", model.stats.messages],
    ["Protocols", model.stats.protocols],
  ];

  el.innerHTML = stats
    .map(([label, value]) => `<span class="graph-stat"><strong>${value}</strong>${label}</span>`)
    .join("");
}

function _renderGraphLegend(protocols, nodeTypes) {
  const el = document.getElementById("graphLegend");
  if (!el) return;

  const protocolHtml = (protocols || [])
    .slice(0, 10)
    .map(protocol => {
      const color = (PROTOCOL_STYLE[protocol] || { color: "#94a3b8" }).color;
      return `<div class="graph-legend-item"><span class="graph-legend-swatch" style="background:${color}"></span>${protocol}</div>`;
    })
    .join("");

  const nodeTypeHtml = (nodeTypes || [])
    .map(type => {
      const style = NODE_TYPE_STYLE[type] || NODE_TYPE_STYLE.NODE;
      return `<div class="graph-legend-item"><span class="graph-legend-swatch" style="background:${style.background}"></span>${type}</div>`;
    })
    .join("");

  el.innerHTML = `
    <div class="graph-legend-section">
      <div class="graph-legend-title">Node Roles</div>
      ${nodeTypeHtml || '<div class="graph-legend-item">No node types</div>'}
    </div>
    <div class="graph-legend-section">
      <div class="graph-legend-title">Protocol Paths</div>
      ${protocolHtml || '<div class="graph-legend-item">No protocol edges</div>'}
    </div>
  `;
}

function _showGraphNodeDetails(node, model) {
  const connected = model.edges.filter(edge => edge.from === node.id || edge.to === node.id);
  const protocolCounts = {};
  connected.forEach(edge => {
    protocolCounts[edge.protocol] = (protocolCounts[edge.protocol] || 0) + edge.count;
  });
  const topProtocols = Object.entries(protocolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([protocol, count]) => `${protocol} x${count}`);

  const details = [
    `${node.id}`,
    "",
    `Role          ${_nodeTypeFromLabel(node.label)}`,
    `Activity      ${connected.reduce((sum, edge) => sum + edge.count, 0)} messages`,
    `Paths         ${connected.length}`,
    `Top Protocols ${topProtocols.join(", ") || "None"}`,
  ].join("\n");

  _setGraphSelection(details);
  const detailsEl = document.getElementById("nodeDetails");
  if (detailsEl) detailsEl.innerText = details;
}

function _showGraphEdgeDetails(edge) {
  const samples = edge.messages.slice(0, 5);
  const details = [
    `${edge.protocol} path`,
    "",
    `From      ${edge.from}`,
    `To        ${edge.to}`,
    `Messages  ${edge.count}`,
    `Samples   ${samples.join(" | ") || "No sample labels"}`,
  ].join("\n");

  _setGraphSelection(details);
  const detailsEl = document.getElementById("nodeDetails");
  if (detailsEl) detailsEl.innerText = details;
}

function _showCausalNodeDetails(node) {
  const raw = node.raw || {};
  const details = [
    `${raw.event || node.id}`,
    "",
    `Protocol    ${raw.protocol || "—"}`,
    `Message     ${raw.message || "—"}`,
    `Source      ${raw.src || "—"}`,
    `Destination ${raw.dst || "—"}`,
    `Time        ${raw.timestamp_ms != null ? `${raw.timestamp_ms.toFixed(1)} ms` : "—"}`,
    `Failure     ${raw.failure ? "Yes" : "No"}`,
    `Score       ${raw.score != null ? `${Math.round(raw.score * 100)}%` : "—"}`,
  ].join("\n");

  _setGraphSelection(details);
  const detailsEl = document.getElementById("nodeDetails");
  if (detailsEl) detailsEl.innerText = details;
}

function _showCausalEdgeDetails(edge) {
  const raw = edge.raw || {};
  const details = [
    "Causal Link",
    "",
    `From      ${edge.from}`,
    `To        ${edge.to}`,
    `Type      ${raw.type || "precedes"}`,
    `Weight    ${Math.round((Number(raw.weight || 0)) * 100)}%`,
    `Gap       ${Number(raw.gap_ms || 0).toFixed(1)} ms`,
  ].join("\n");

  _setGraphSelection(details);
  const detailsEl = document.getElementById("nodeDetails");
  if (detailsEl) detailsEl.innerText = details;
}

function _setGraphSelection(text) {
  const el = document.getElementById("graphSelection");
  if (!el) return;
  el.innerText = text;
}

function _formatGraphNodeLabel(label, type, activity) {
  const shortLabel = String(label).length > 26 ? `${String(label).slice(0, 23)}...` : String(label);
  return `${type}\n${shortLabel}\nmsgs ${activity}`;
}

function _nodeTypeFromLabel(label) {
  return String(label || "NODE").split("\n", 1)[0] || "NODE";
}

function _parseNodeLabel(nodeLabel) {
  const raw = String(nodeLabel || "").trim();
  const parts = raw.split("\n").map(part => part.trim()).filter(Boolean);
  const first = parts[0] || raw || "NODE";
  const second = parts[1] || "";
  const looksLikeAddress = value => /^[0-9a-f:.]+$/i.test(String(value || ""));

  return {
    raw,
    type: parts.length > 1 ? first : (looksLikeAddress(first) ? "NODE" : first),
    address: parts.length > 1 ? second : (looksLikeAddress(first) ? first : ""),
  };
}

function _isGenericNodeRole(value) {
  return ["NODE", "UNKNOWN", "CORE", "EXT", "EXTERNAL", "IMS", "UE"].includes(String(value || "").toUpperCase());
}

function _buildLadderNodeIntelligence(flow) {
  const flowNodes = new Set();
  (flow || []).forEach(item => {
    if (item?.src) flowNodes.add(item.src);
    if (item?.dst) flowNodes.add(item.dst);
  });

  const graphNodes = [
    ...(Array.isArray(STATE.selected?.graph?.nodes) ? STATE.selected.graph.nodes : []),
    ...(Array.isArray(STATE.graph?.nodes) ? STATE.graph.nodes : []),
    ...(Array.isArray(STATE.captureGraph?.nodes) ? STATE.captureGraph.nodes : []),
  ];
  const inventoryNodes = [
    ...(Array.isArray(STATE.selected?.details_summary?.node_inventory) ? STATE.selected.details_summary.node_inventory : []),
    ...(Array.isArray(STATE.summary?.details?.node_inventory) ? STATE.summary.details.node_inventory : []),
    ...(Array.isArray(STATE.summary?.details?.topology?.nodes) ? STATE.summary.details.topology.nodes : []),
  ];

  const inventoryByIp = new Map();
  inventoryNodes.forEach(item => {
    const address = String(item.ip || item.address || "").trim();
    if (!address) return;
    inventoryByIp.set(address, item);
  });

  const graphById = new Map();
  const graphByAddress = new Map();
  graphNodes.forEach(node => {
    if (!node?.id) return;
    graphById.set(node.id, node);
    const parsed = _parseNodeLabel(node.id);
    const address = String(node.label || parsed.address || "").trim();
    if (address) graphByAddress.set(address, node);
  });

  const inferred = new Map();
  flowNodes.forEach(nodeLabel => {
    const parsed = _parseNodeLabel(nodeLabel);
    const graphNode = graphById.get(nodeLabel) || graphByAddress.get(parsed.address) || null;
    const inventoryNode = inventoryByIp.get(parsed.address) || null;
    const graphType = String(graphNode?.type || "").trim();
    const inventoryRole = String(inventoryNode?.role || inventoryNode?.label || "").trim();
    const rawType = String(parsed.type || "").trim();

    let role = inventoryRole || "";
    if (!role && graphType && !_isGenericNodeRole(graphType)) role = graphType;
    if (!role && rawType && !_isGenericNodeRole(rawType)) role = rawType;
    if (!role) role = rawType || graphType || "NODE";

    const address = parsed.address || String(graphNode?.label || inventoryNode?.ip || inventoryNode?.address || "").trim();
    const zone = rawType && role.toUpperCase() !== rawType.toUpperCase() ? rawType : "";

    inferred.set(nodeLabel, {
      raw: nodeLabel,
      role,
      zone,
      address,
      confidence: inventoryNode?.confidence || "",
      evidence: inventoryNode?.evidence || "",
      protocols: inventoryNode?.protocols || [],
    });
  });

  return inferred;
}

function _resolveLadderNode(nodeLabel) {
  return _buildLadderNodeIntelligence([{ src: nodeLabel, dst: nodeLabel }]).get(nodeLabel) || _parseNodeLabel(nodeLabel);
}

/* ════════════════════════════════════════════════════════════════
   LADDER DIAGRAM
   ════════════════════════════════════════════════════════════════ */
function renderLadder(flow) {
  const container = document.getElementById("timeline");
  if (!container) return;

  container.innerHTML      = "";
  container.style.overflow = "auto";
  container.style.position = "relative";

  if (!Array.isArray(flow) || !flow.length) {
    container.innerHTML = `<div class="empty-state">No flow data for this session</div>`;
    return;
  }

  /* FIX [2]: filter events missing src or dst before any node collection */
  const validFlow = flow.filter(f => f.src && f.dst);
  if (!validFlow.length) {
    container.innerHTML = `<div class="empty-state">Flow events have no node information</div>`;
    return;
  }

  /* FIX [12]: apply protocol filter — was removed in your rewrite */
  const filteredFlow = STATE.filters.protocol === "ALL"
    ? validFlow
    : validFlow.filter(f => f.protocol === STATE.filters.protocol);

  if (!filteredFlow.length) {
    container.innerHTML = `<div class="empty-state">No events match the selected protocol filter</div>`;
    return;
  }

  /* Collect unique nodes in first-seen order */
  const nodeSet = new Set();
  filteredFlow.forEach(f => { nodeSet.add(f.src); nodeSet.add(f.dst); });
  const nodes = [...nodeSet];
  const nodeIntel = _buildLadderNodeIntelligence(filteredFlow);

  /* Layout constants */
  const LEFT_MARGIN = 76;
  const RIGHT_MARGIN = 44;
  const TOP_HEADER  = 74;
  const ROW_HEIGHT  = 52;
  const SELF_RADIUS = 20;
  const containerWidth = Math.max(760, container.clientWidth || 1200);
  const baseWidth = Math.max(760, containerWidth - 24);
  const minimumGap = 180;
  const requiredWidth = LEFT_MARGIN + RIGHT_MARGIN + Math.max(0, nodes.length - 1) * minimumGap + 160;
  const svgWidth  = Math.max(baseWidth, requiredWidth);
  const svgHeight = TOP_HEADER + filteredFlow.length * ROW_HEIGHT + 56;

  const svg = _makeSVGEl("svg");
  svg.setAttribute("width",       svgWidth);
  svg.setAttribute("height",      svgHeight);
  svg.setAttribute("font-family", FONT_FAMILY);

  /* ── Defs: per-color forward + reverse markers
     FIX [3]: arrowhead color matches protocol color
     FIX [4]: reverse marker uses auto-start-reverse            */
  const defs = _makeSVGEl("defs");
  const markerColors = new Set([
    ...Object.values(PROTOCOL_STYLE).map(s => s.color),
    FAILURE_COLOR,
    "#4f46e5",
  ]);
  markerColors.forEach(color => {
    defs.appendChild(_makeArrowMarker(color.replace("#", "mc") + "-fwd", color, "auto"));
    defs.appendChild(_makeArrowMarker(color.replace("#", "mc") + "-rev", color, "auto-start-reverse"));
  });
  svg.appendChild(defs);

  /* ── Node X positions ── */
  const nodeX = {};
  const usableWidth = Math.max(220, svgWidth - LEFT_MARGIN - RIGHT_MARGIN);
  const nodeGap = nodes.length > 1
    ? Math.max(minimumGap, Math.min(320, usableWidth / (nodes.length - 1)))
    : 0;
  const nodeSpan = nodeGap * Math.max(0, nodes.length - 1);
  const startX = LEFT_MARGIN + (usableWidth - nodeSpan) / 2;
  nodes.forEach((node, i) => { nodeX[node] = startX + i * nodeGap; });

  /* ── Node headers + lifelines ── */
  nodes.forEach(node => {
    const x     = nodeX[node];
    const intel = nodeIntel.get(node) || _parseNodeLabel(node);
    const type  = intel.role || "NODE";
    const ip    = intel.address || "";
    const zone  = intel.zone || "";

    const typeEl = _makeSVGEl("text");
    typeEl.setAttribute("x",              x);
    typeEl.setAttribute("y",              20);
    typeEl.setAttribute("text-anchor",    "middle");
    typeEl.setAttribute("font-size",      "12");
    typeEl.setAttribute("font-weight",    "600");
    typeEl.setAttribute("fill",           "#64748b");
    typeEl.setAttribute("letter-spacing", "0.08em");
    typeEl.textContent = type;
    svg.appendChild(typeEl);

    const ipEl = _makeSVGEl("text");
    ipEl.setAttribute("x",           x);
    ipEl.setAttribute("y",           38);
    ipEl.setAttribute("text-anchor", "middle");
    ipEl.setAttribute("font-size",   "11");
    ipEl.setAttribute("fill",        "#94a3b8");
    ipEl.textContent = zone ? [zone, ip].filter(Boolean).join(" · ") : ip;
    svg.appendChild(ipEl);

    /* FIX [11]: lifeline ends at svgHeight — not hardcoded 2000 */
    const lifeline = _makeSVGEl("line");
    lifeline.setAttribute("x1",               x);
    lifeline.setAttribute("y1",               TOP_HEADER);
    lifeline.setAttribute("x2",               x);
    lifeline.setAttribute("y2",               svgHeight - 10);
    lifeline.setAttribute("stroke",           LIFELINE_COLOR);
    lifeline.setAttribute("stroke-width",     "1");
    lifeline.setAttribute("stroke-dasharray", "4 4");
    svg.appendChild(lifeline);
  });

  /* ── Flow events ── */
  filteredFlow.forEach((f, i) => {
    /* FIX [1]: pure index-based Y — no broken dual-mode scaling */
    const y         = TOP_HEADER + i * ROW_HEIGHT + ROW_HEIGHT / 2;
    const x1        = nodeX[f.src];
    const x2        = nodeX[f.dst];
    const isSelf    = x1 === x2;
    const isFail    = Boolean(f.failure) || /^[45]\d\d$/.test(String(f.message));

    let color = PROTOCOL_STYLE[f.protocol]?.color || "#4f46e5";
    if (isFail) color = FAILURE_COLOR;

    const safeId = color.replace("#", "mc");
    const markFwd = `url(#${safeId}-fwd)`;

    const band = _makeSVGEl("rect");
    band.setAttribute("x", LEFT_MARGIN - 4);
    band.setAttribute("y", y - ROW_HEIGHT / 2 + 6);
    band.setAttribute("width", svgWidth - LEFT_MARGIN - RIGHT_MARGIN + 8);
    band.setAttribute("height", ROW_HEIGHT - 10);
    band.setAttribute("rx", "10");
    band.setAttribute("fill", i % 2 === 0 ? "rgba(241, 245, 249, 0.55)" : "rgba(255, 255, 255, 0.92)");
    svg.appendChild(band);

    /* Timestamp delta in left margin */
    if (f.time != null) {
      const delta = (parseFloat(f.time) - (parseFloat(filteredFlow[0].time) || 0)).toFixed(3);
      const tsEl  = _makeSVGEl("text");
      tsEl.setAttribute("x",           LEFT_MARGIN + 36);
      tsEl.setAttribute("y",           y + 4);
      tsEl.setAttribute("text-anchor", "end");
      tsEl.setAttribute("font-size",   "10");
      tsEl.setAttribute("fill",        "#94a3b8");
      tsEl.textContent = `+${delta}s`;
      svg.appendChild(tsEl);
    }

    /* Arrow: self-call arc or straight line */
    if (isSelf) {
      const arc = _makeSVGEl("path");
      arc.setAttribute("d",
        `M${x1},${y - SELF_RADIUS} ` +
        `C${x1 + 60},${y - SELF_RADIUS} ${x1 + 60},${y + SELF_RADIUS} ` +
        `${x1},${y + SELF_RADIUS}`
      );
      arc.setAttribute("fill",          "none");
      arc.setAttribute("stroke",        color);
      arc.setAttribute("stroke-width",  "2.2");
      arc.setAttribute("marker-end",    markFwd);
      arc.setAttribute("data-flow",     JSON.stringify(f));
      if (isFail) arc.setAttribute("stroke-dasharray", "5,3");
      svg.appendChild(arc);
    } else {
      const arrow = _makeSVGEl("line");
      arrow.setAttribute("x1",             x1);
      arrow.setAttribute("y1",             y);
      arrow.setAttribute("x2",             x2);
      arrow.setAttribute("y2",             y);
      arrow.setAttribute("stroke",         color);
      arrow.setAttribute("stroke-width",   "2.2");
      arrow.setAttribute("stroke-linecap", "round");
      /* Always place the arrowhead at the message destination.
         SVG auto orientation handles both left→right and right→left lines. */
      arrow.setAttribute("marker-end", markFwd);
      if (isFail) arrow.setAttribute("stroke-dasharray", "5,3");
      arrow.setAttribute("data-flow", JSON.stringify(f));
      svg.appendChild(arrow);
    }

    /* Message label */
    const label  = _ladderLabel(f);
    const midX   = isSelf ? x1 + 68 : (x1 + x2) / 2;
    const labelY = isSelf ? y        : y - 7;

    const msgEl = _makeSVGEl("text");
    msgEl.setAttribute("x",           midX);
    msgEl.setAttribute("y",           labelY);
    msgEl.setAttribute("text-anchor", "middle");
    msgEl.setAttribute("font-size",   "12");
    msgEl.setAttribute("fill",        isFail ? FAILURE_COLOR : color);
    msgEl.setAttribute("font-weight", isFail ? "700" : "500");
    msgEl.textContent = label;
    svg.appendChild(msgEl);

    /* Protocol badge pill */
    if (f.protocol) {
      const pillWidth = f.protocol.length * 5.5 + 8;
      const px = isSelf
        ? x1 + 4
        : x1 < x2
          ? x1 + 6
          : x1 - pillWidth - 6;
      const pill = _makeSVGEl("rect");
      pill.setAttribute("x",       px - 2);
      pill.setAttribute("y",       y + 4);
      pill.setAttribute("width",   pillWidth);
      pill.setAttribute("height",  12);
      pill.setAttribute("rx",      "3");
      pill.setAttribute("fill",    color);
      pill.setAttribute("opacity", "0.15");
      svg.appendChild(pill);

      const pEl = _makeSVGEl("text");
      pEl.setAttribute("x",             px + pillWidth / 2 - 2);
      pEl.setAttribute("y",             y + 13);
      pEl.setAttribute("text-anchor",   "middle");
      pEl.setAttribute("font-size",     "8.5");
      pEl.setAttribute("fill",          color);
      pEl.setAttribute("font-weight",   "600");
      pEl.setAttribute("letter-spacing","0.05em");
      pEl.textContent = f.protocol;
      svg.appendChild(pEl);
    }
  });

  /* ── Event delegation: click + tooltip
     FIX [13]: restored — was removed in your rewrite
     FIX [14]: showDetails now reachable via click             */
  let _tooltipTimer = null;

  svg.addEventListener("click", e => {
    const el = e.target.closest("[data-flow]");
    if (!el) return;
    try { showDetails(JSON.parse(el.getAttribute("data-flow"))); } catch (_) {}
  });

  svg.addEventListener("mousemove", e => {
    const el = e.target.closest("[data-flow]");
    if (!el) {
      /* FIX [6]: hide stale tooltip immediately on miss */
      _hideTooltip();
      return;
    }
    clearTimeout(_tooltipTimer);
    _tooltipTimer = setTimeout(() => {
      try { showTooltip(e, JSON.parse(el.getAttribute("data-flow"))); } catch (_) {}
    }, 60);
  });

  svg.addEventListener("mouseleave", _hideTooltip);

  container.appendChild(svg);
}

/* ════════════════════════════════════════════════════════════════
   TOOLTIP
   ════════════════════════════════════════════════════════════════ */
function showTooltip(e, f) {
  let tt = document.getElementById("tt-flow");

  if (!tt) {
    tt = document.createElement("div");
    tt.id = "tt-flow";
    tt.style.cssText = [
      "position:absolute",
      "z-index:9999",
      "background:#0f172a",
      "color:#e2e8f0",
      "border:1px solid #334155",
      "border-radius:6px",
      "padding:8px 10px",
      "font-size:11px",
      `font-family:${FONT_FAMILY}`,
      "line-height:1.6",
      "pointer-events:none",
      "white-space:pre",
      "max-width:320px",
    ].join(";");
    document.body.appendChild(tt);
  }

  /* FIX [5]: pageX/pageY — correct on scrolled pages */
  tt.style.top     = (e.pageY + 14) + "px";
  tt.style.left    = (e.pageX + 14) + "px";
  tt.style.display = "block";

  tt.innerText = _formatLadderDetails(f);
}

function _hideTooltip() {
  const t = document.getElementById("tt-flow");
  if (t) t.style.display = "none";
}

/* ════════════════════════════════════════════════════════════════
   DETAILS PANEL
   ════════════════════════════════════════════════════════════════ */
function showDetails(f) {
  const el = document.getElementById("nodeDetails");
  if (!el) return;
  el.innerText = _formatLadderDetails(f);
}

function _ladderLabel(f) {
  const base = f.short_label || f.message || f.protocol || "Message";
  return f.protocol === "DIAMETER" ? `[D] ${base}` : base;
}

function _formatLadderDetails(f) {
  const srcIntel = _resolveLadderNode(f.src);
  const dstIntel = _resolveLadderNode(f.dst);
  const details = f.details || {};
  const lines = [
    `${f.protocol || "UNKNOWN"}  ${f.short_label || f.message || "Message"}`,
    "────────────────────────────",
    `Source       ${srcIntel.role || f.src || "—"}${srcIntel.address ? ` (${srcIntel.address})` : ""}`,
    `Destination  ${dstIntel.role || f.dst || "—"}${dstIntel.address ? ` (${dstIntel.address})` : ""}`,
    `Time         ${f.time ?? "—"}`,
    `Frame        ${f.frame_number ?? "—"}`,
    `Session      ${f.call_id || "—"}`,
  ];

  if (srcIntel.zone || dstIntel.zone) {
    lines.push(`Node Class    ${srcIntel.zone || srcIntel.role || "—"} → ${dstIntel.zone || dstIntel.role || "—"}`);
  }
  if (srcIntel.confidence || dstIntel.confidence) {
    lines.push(`Inference     ${String(srcIntel.confidence || "low").toUpperCase()} / ${String(dstIntel.confidence || "low").toUpperCase()}`);
  }

  if (f.protocol === "DIAMETER") {
    lines.push(`Command      ${details.command_name || "—"} (${details.command_code || "—"})`);
    lines.push(`Meaning      ${details.command_long_name || "Diameter"}`);
    lines.push(`Direction    ${details.is_request ? "Request" : "Answer"}`);
    if (details.result_code || details.result_text) {
      lines.push(`Result       ${details.result_code || "—"} ${details.result_text || ""}`.trim());
    }
    if (details.cc_request_type || details.cc_request_number != null) {
      lines.push(`CC Request   ${(details.cc_request_type ?? "—")} #${details.cc_request_number ?? "—"}`);
    }
    if (details.diameter_interface) lines.push(`Interface    ${details.diameter_interface}`);
    if (details.origin_host || details.origin_realm) {
      lines.push(`Origin       ${(details.origin_host || "—")} / ${(details.origin_realm || "—")}`);
    }
    if (details.destination_host || details.destination_realm) {
      lines.push(`Destination  ${(details.destination_host || "—")} / ${(details.destination_realm || "—")}`);
    }
    if (details.imsi) lines.push(`IMSI         ${details.imsi}`);
    if (details.msisdn) lines.push(`MSISDN       ${details.msisdn}`);
    if (details.apn) lines.push(`APN          ${details.apn}`);
    if (details.rating_group) lines.push(`Rating Group ${details.rating_group}`);
    if (details.service_identifier) lines.push(`Service ID   ${details.service_identifier}`);
    if (f.failure) lines.push("Failure      Diameter answer indicates rejection/failure");
  } else {
    if (details.procedure) lines.push(`Procedure    ${details.procedure}`);
    if (details.cause_code) lines.push(`Cause        ${details.cause_code}`);
    if (details.stream_id) lines.push(`Stream       ${details.stream_id}`);
    if (details.transaction_id) lines.push(`Transaction  ${details.transaction_id}`);
    if (details.transport) lines.push(`Transport    ${details.transport}`);
    if (details.src_port != null || details.dst_port != null) {
      lines.push(`Ports        ${details.src_port ?? "—"} -> ${details.dst_port ?? "—"}`);
    }
    if (details.status_code) lines.push(`Status       ${details.status_code}`);
    if (details.dns_query) lines.push(`DNS Query    ${details.dns_query}`);
    if (details.dns_answer) lines.push(`DNS Answer   ${details.dns_answer}`);
    if (details.dns_rcode) lines.push(`DNS RCode    ${details.dns_rcode}`);
    if (details.icmp_type || details.icmp_code) {
      lines.push(`ICMP         type=${details.icmp_type || "—"} code=${details.icmp_code || "—"}`);
    }
    if (details.imsi) lines.push(`IMSI         ${details.imsi}`);
    if (details.msisdn) lines.push(`MSISDN       ${details.msisdn}`);
    if (f.failure) lines.push("Failure      Message flagged as failure evidence");
  }

  if (f.headers) {
    const headerText = Object.entries(f.headers)
      .filter(([, value]) => value)
      .map(([key, value]) => `${key}=${value}`)
      .join(" | ");
    if (headerText) lines.push(`Headers      ${headerText}`);
  }

  return lines.join("\n");
}

/* ════════════════════════════════════════════════════════════════
   LOAD DATA
   ════════════════════════════════════════════════════════════════ */
function loadData(data) {
  STATE.token    = data.token    || null;
  STATE.filename = data.filename || "";
  STATE.model    = data.model    || null;
  STATE.summary  = data.summary  || null;
  STATE.sessions = data.sessions || [];
  STATE.sessions.sort((left, right) => {
    const priorityDelta = Number(right.priority_score || 0) - Number(left.priority_score || 0);
    if (priorityDelta !== 0) return priorityDelta;
    return Number(right.confidence || 0) - Number(left.confidence || 0);
  });
  STATE.captureGraph = data.graph || null;
  STATE.graph    = STATE.captureGraph;
  STATE.hydrationPending = true;
  hydrateFromState();
}

window.loadData = loadData;
window.hydrateFromState = hydrateFromState;
window.renderLearningStatus = renderLearningStatus;
window.renderValidationQueue = renderValidationQueue;
window.renderVersionInfo = renderVersionInfo;
window.toggleVersionHistory = toggleVersionHistory;

if (window.__TRACE_PENDING_UPLOAD__) {
  const pendingUpload = window.__TRACE_PENDING_UPLOAD__;
  window.__TRACE_PENDING_UPLOAD__ = null;
  loadData(pendingUpload);
} else if (STATE.hydrationPending || (Array.isArray(STATE.sessions) && STATE.sessions.length)) {
  hydrateFromState();
}

function _renderEvidence(evidence) {
  const list = document.getElementById("whyList");
  if (!list) return;
  list.innerHTML = "";

  if (!evidence.length) {
    const item = document.createElement("li");
    item.innerText = "No evidence available";
    list.appendChild(item);
    return;
  }

  evidence.forEach(text => {
    const item = document.createElement("li");
    item.innerText = text;
    list.appendChild(item);
  });
}

function _renderActions(actions) {
  const list = document.getElementById("rcaActions");
  if (!list) return;
  list.innerHTML = "";

  if (!actions.length) {
    const item = document.createElement("li");
    item.innerText = "No analyst recommendations available";
    list.appendChild(item);
    return;
  }

  actions.forEach(text => {
    const item = document.createElement("li");
    item.innerText = text;
    list.appendChild(item);
  });
}

function _renderAgentVotes(agentic) {
  const el = document.getElementById("agentVotes");
  if (!el) return;
  if (!agentic?.hypotheses?.length) {
    el.innerHTML = `<div class="trace-summary-item">No protocol agent hypotheses available.</div>`;
    return;
  }

  el.innerHTML = agentic.hypotheses.map(item => `
    <div class="autonomous-item">
      <div class="autonomous-head">
        <strong>${item.agent}</strong>
        <span class="chip">${item.label}</span>
        <span class="chip">${Math.round((Number(item.confidence || 0)) * 100)}%</span>
      </div>
      <div class="autonomous-body">${(item.evidence || []).join(" · ") || "No local evidence"}</div>
    </div>
  `).join("");
}

function _renderCausalChain(causal) {
  const el = document.getElementById("causalChain");
  if (!el) return;
  const chain = causal?.causal_chain || [];
  if (!chain.length) {
    el.innerHTML = `<div class="trace-summary-item">No causal chain available for this session.</div>`;
    return;
  }

  el.innerHTML = chain.map((item, index) => `
    <div class="autonomous-item">
      <div class="autonomous-head">
        <strong>${index + 1}. ${item.event}</strong>
        <span class="chip">${Math.round((Number(item.score || 0)) * 100)}%</span>
      </div>
      <div class="autonomous-body">${item.protocol || "UNKNOWN"}${item.failure ? " · failure marker" : ""}</div>
    </div>
  `).join("");
}

function _renderConfidenceModel(model) {
  const el = document.getElementById("confidenceModel");
  if (!el) return;
  if (!model) {
    el.innerHTML = `<div class="trace-summary-item">No confidence calibration data available.</div>`;
    return;
  }

  const scores = model.source_scores || {};
  const rows = [
    ["Final Label", model.final_label || "UNKNOWN"],
    ["Calibrated Confidence", `${Math.round((Number(model.calibrated_confidence_score ?? model.confidence_score ?? 0)) * 100)}%`],
    ["Raw Confidence", `${Math.round((Number(model.raw_confidence_score ?? model.confidence_score ?? 0)) * 100)}%`],
    ["Band", String(model.confidence_band || "uncalibrated").toUpperCase()],
    ["Source", model.calibration_source || "uncalibrated"],
    ["Uncertainty", `${Math.round((Number(model.uncertainty || 0)) * 100)}%`],
    ["Rule", `${Math.round((Number(scores.rule_score || 0)) * 100)}%`],
    ["Pattern", `${Math.round((Number(scores.pattern_score || 0)) * 100)}%`],
    ["Causal", `${Math.round((Number(scores.causal_score || 0)) * 100)}%`],
    ["Agent", `${Math.round((Number(scores.agent_score || 0)) * 100)}%`],
    ["Anomaly", `${Math.round((Number(scores.anomaly_score || 0)) * 100)}%`],
  ];

  el.innerHTML = rows.map(([label, value]) => `
    <div class="autonomous-row"><span>${label}</span><strong>${value}</strong></div>
  `).join("");
}

function _renderKnowledgeSignals(session) {
  const el = document.getElementById("knowledgeSignals");
  if (!el) return;
  const pattern = session.pattern_match || {};
  const graph = session.knowledge_graph_summary || {};
  const timeseries = session.timeseries_summary || {};
  const recurring = timeseries.recurring_failures || [];
  const topRecurring = recurring[0];

  el.innerHTML = `
    <div class="autonomous-row"><span>Pattern Match</span><strong>${pattern.scenario || "None"}</strong></div>
    <div class="autonomous-row"><span>Similarity</span><strong>${pattern.similarity ? `${Math.round(Number(pattern.similarity) * 100)}%` : "—"}</strong></div>
    <div class="autonomous-row"><span>Graph Nodes</span><strong>${graph.nodes ?? 0}</strong></div>
    <div class="autonomous-row"><span>Graph Edges</span><strong>${graph.edges ?? 0}</strong></div>
    <div class="autonomous-row"><span>Recurring Failure</span><strong>${topRecurring ? `${topRecurring.root_cause} x${topRecurring.count}` : "None"}</strong></div>
  `;
}

function _renderDetails(details, isCaptureSummary) {
  const el = document.getElementById("nodeDetails");
  if (!el) return;

  if (!details) {
    el.innerText = isCaptureSummary ? "No trace summary available" : "No session summary available";
    return;
  }

  if (isCaptureSummary) {
    const overviewRows = (details.overview || [])
      .map(([label, value]) => `
        <div class="summary-table-row">
          <span>${label}</span>
          <strong>${value || "Unknown"}</strong>
        </div>
      `)
      .join("");
    const protocolRows = (details.protocol_breakdown || [])
      .map(item => `
        <div class="summary-table-row summary-table-row-protocol">
          <span>${item.label}</span>
          <strong>${item.frames} frames · ${item.percentage}%</strong>
          <div class="summary-subtext">${item.purpose}</div>
        </div>
      `)
      .join("");
    const identityRows = (details.party_identities || [])
      .map(item => `
        <div class="summary-table-row summary-table-row-identity">
          <span>${item.label}</span>
          <strong>${item.msisdn || "Unknown"}</strong>
          <div class="summary-subtext">IMSI: ${item.imsi || "Not observed"}</div>
          <div class="summary-subtext">Network: ${item.network || "Unknown"} (${item.network_source || "Unavailable"})</div>
          <div class="summary-subtext">${item.source || "Unavailable"} · ${String(item.confidence || "low").toUpperCase()} confidence</div>
        </div>
      `)
      .join("");
    const nodeRows = (details.node_inventory || [])
      .map(item => `
        <div class="summary-table-row summary-table-row-node">
          <span>${item.role}</span>
          <strong>${item.ip || "Unknown"}</strong>
          <div class="summary-subtext">${(item.protocols || []).join(", ") || "No protocol evidence"} · ${item.evidence || "No supporting evidence"} · ${String(item.confidence || "low").toUpperCase()} confidence</div>
        </div>
      `)
      .join("");
    const observations = (details.observations || [])
      .map(line => `<li>${line}</li>`)
      .join("");
    const topology = (details.topology?.lines || [])
      .map(line => `<div class="topology-line">${line}</div>`)
      .join("");

    el.innerHTML = `
      <div class="capture-summary-sections">
        <section class="summary-section">
          <h4>PCAP Summary</h4>
          <div class="summary-table">${overviewRows || '<div class="trace-summary-item">No overview available.</div>'}</div>
        </section>
        <section class="summary-section">
          <h4>Subscriber Identity</h4>
          <div class="summary-table">${identityRows || '<div class="trace-summary-item">No subscriber identity available.</div>'}</div>
        </section>
        <section class="summary-section">
          <h4>Protocol Breakdown</h4>
          <div class="summary-table">${protocolRows || '<div class="trace-summary-item">No protocol breakdown available.</div>'}</div>
        </section>
        <section class="summary-section">
          <h4>Detected Network Nodes</h4>
          <div class="summary-table">${nodeRows || '<div class="trace-summary-item">No node inventory available.</div>'}</div>
        </section>
        <section class="summary-section">
          <h4>Key Observations</h4>
          <ul class="bullet-list">${observations || "<li>No analyst observations available.</li>"}</ul>
        </section>
        <section class="summary-section">
          <h4>Network Topology (Inferred)</h4>
          <div class="topology-block">${topology || "No topology inference available."}</div>
        </section>
      </div>
    `;
    return;
  }

  const lines = [];
  if (details.headline) lines.push(details.headline);
  if (details.summary_lines?.length) {
    lines.push("");
    details.summary_lines.forEach(line => lines.push(`- ${line}`));
  }

  el.innerText = lines.join("\n");
}

function _renderTraceOverview(details) {
  _setText("traceHeadline", details?.headline || "Upload a capture to generate a protocol-aware investigation summary.");
  _setText("traceType", details?.trace_type || "Awaiting capture");
  const meta = document.getElementById("traceMeta");
  const list = document.getElementById("traceSummaryList");
  if (!meta || !list) return;

  meta.innerHTML = "";
  list.innerHTML = "";

  [
    details?.trace_type,
    details?.scenario,
    details?.subscriber_imsi ? `IMSI ${details.subscriber_imsi}` : null,
    details?.a_party ? `A ${details.a_party}` : null,
    details?.b_party ? `B ${details.b_party}` : null,
  ].filter(Boolean).forEach(value => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.innerText = value;
    meta.appendChild(chip);
  });

  (details?.summary_lines || []).forEach(line => {
    const item = document.createElement("div");
    item.className = "trace-summary-item";
    item.innerText = line;
    list.appendChild(item);
  });
}

function _renderErrorAnalysis(report) {
  const assessment = document.getElementById("errorAssessment");
  const categoryTable = document.getElementById("errorCategoryTable");
  const sections = document.getElementById("errorSections");
  const timeline = document.getElementById("errorTimeline");
  const recommendations = document.getElementById("errorRecommendations");
  if (!assessment || !categoryTable || !sections || !timeline || !recommendations) return;

  if (!report) {
    assessment.innerText = "Upload a capture to generate protocol error analysis.";
    categoryTable.innerHTML = "No error analysis available.";
    sections.innerHTML = "";
    timeline.innerHTML = "";
    recommendations.innerHTML = "";
    return;
  }

  assessment.innerText = report.assessment || "No analyst assessment available.";

  categoryTable.innerHTML = `
    <div class="error-category-header">
      <span>Category</span>
      <span>Count</span>
      <span>Severity</span>
      <span>Verdict</span>
    </div>
    ${(report.categories || []).map(item => `
      <div class="error-category-row">
        <strong>${item.category}</strong>
        <span>${item.count}</span>
        <span class="error-severity-pill ${String(item.severity || "none").toLowerCase()}">${String(item.severity || "none").toUpperCase()}</span>
        <span>${item.verdict || ""}</span>
      </div>
    `).join("")}
  `;

  sections.innerHTML = (report.sections || []).map(section => `
    <section class="error-section-card">
      <div class="error-section-header">
        <div>
          <h4>${section.title}</h4>
          <div class="panel-subtitle">${section.verdict || ""}</div>
        </div>
        <span class="error-severity-pill ${String(section.severity || "none").toLowerCase()}">${String(section.severity || "none").toUpperCase()}</span>
      </div>
      <p class="error-section-body">${section.analysis || ""}</p>
      ${(section.examples || []).length ? `
        <div class="error-example-list">
          ${(section.examples || []).map(example => `
            <div class="error-example-item">
              ${Object.entries(example).map(([key, value]) => `<div><span>${key.replace(/_/g, " ")}</span><strong>${value ?? "—"}</strong></div>`).join("")}
            </div>
          `).join("")}
        </div>
      ` : ""}
    </section>
  `).join("");

  timeline.innerHTML = (report.timeline || []).map(item => `
    <div class="timeline-item">
      <span class="timeline-time">${item.time || "Unknown"}</span>
      <span class="timeline-event">${item.event || ""}</span>
      <span class="error-severity-pill ${String(item.severity || "none").toLowerCase()}">${String(item.severity || "none").toUpperCase()}</span>
    </div>
  `).join("");

  recommendations.innerHTML = (report.recommendations || []).map(item => `
    <div class="recommendation-card">
      <div class="recommendation-priority">${item.priority || "Info"}</div>
      <h4>${item.title || ""}</h4>
      <p>${item.body || ""}</p>
    </div>
  `).join("");
}

function _renderMetricList(targetId, values) {
  const container = document.getElementById(targetId);
  if (!container) return;
  container.innerHTML = "";

  const entries = Array.isArray(values)
    ? values.map(item => [item.label || item.endpoint || item[0], item.count || item[1]])
    : Object.entries(values);

  if (!entries.length) {
    container.innerHTML = `<div class="trace-summary-item">No data available</div>`;
    return;
  }

  const maxValue = Math.max(...entries.map(([, value]) => Number(value) || 0), 1);
  const list = document.createElement("div");
  list.className = "metric-list";
  const fillClass = targetId === "protocolMix"
    ? "protocol"
    : targetId === "topEndpoints"
      ? "endpoint"
      : targetId === "rcaDistribution"
        ? "rca"
        : "";

  entries.slice(0, 8).forEach(([label, rawValue]) => {
    const value = Number(rawValue) || 0;
    const row = document.createElement("div");
    row.className = "metric-row";
    row.innerHTML = `
      <div class="metric-head">
        <span>${label}</span>
        <strong>${_formatNumber(value)}</strong>
      </div>
    `;
    const bar = document.createElement("div");
    bar.className = "metric-bar";
    bar.innerHTML = `<div class="metric-fill ${fillClass}" style="width:${Math.max(8, Math.round((value / maxValue) * 100))}%"></div>`;
    const wrapper = document.createElement("div");
    wrapper.appendChild(row);
    wrapper.appendChild(bar);
    list.appendChild(wrapper);
  });

  container.appendChild(list);
}

function _renderEndpointList(targetId, values) {
  const normalized = values.map(item => ({
    label: item.endpoint,
    count: item.count,
  }));
  _renderMetricList(targetId, normalized);
}

function _renderExpertFindings(findings, sessions = []) {
  const container = document.getElementById("expertFindings");
  if (!container) return;
  container.innerHTML = "";

  const leadSession = [...(sessions || [])]
    .sort((left, right) => Number(right.priority_score || 0) - Number(left.priority_score || 0))[0];

  if (leadSession && Number(leadSession.priority_score || 0) > 0) {
    const lead = document.createElement("div");
    lead.className = "finding note";
    lead.innerHTML = `
      <div class="finding-head">
        <strong>Top analyst focus: ${leadSession.rca_title || leadSession.rca_label || "Unknown"}</strong>
        <span class="priority-pill ${String(leadSession.priority_band || "low").toLowerCase()}">P${Math.round(Number(leadSession.priority_score || 0))}</span>
      </div>
      <div>${leadSession.priority_reason || "Start with the highest-priority session in the explorer."}</div>
    `;
    container.appendChild(lead);
  }

  if (!findings.length) {
    const item = document.createElement("div");
    item.className = "finding note";
    item.innerHTML = "<strong>No elevated findings</strong><div>The current capture does not expose any high-priority expert heuristics.</div>";
    container.appendChild(item);
    return;
  }

  findings.forEach(finding => {
    const item = document.createElement("div");
    item.className = `finding ${finding.severity || "note"}`;
    item.innerHTML = `
      <div class="finding-head">
        <strong>${finding.title}</strong>
        <span class="finding-severity ${finding.severity || "note"}">${String(finding.severity || "note").toUpperCase()}</span>
      </div>
      <div>${finding.body}</div>
    `;
    container.appendChild(item);
  });
}

function _renderTrafficTrendChart(sessions, protocolCounts) {
  const container = document.getElementById("trafficTrendChart");
  if (!container) return;

  const points = _buildTrafficSeries(sessions, protocolCounts);
  if (!points.length) {
    container.innerHTML = `<div class="chart-empty">Upload a capture to render message activity.</div>`;
    return;
  }

  const width = 360;
  const height = 136;
  const padding = { top: 14, right: 14, bottom: 18, left: 14 };
  const maxValue = Math.max(...points, 1);
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  const step = points.length > 1 ? innerWidth / (points.length - 1) : innerWidth;

  const coords = points.map((value, index) => {
    const x = padding.left + step * index;
    const y = padding.top + innerHeight - ((value / maxValue) * innerHeight);
    return [x, y];
  });

  const linePath = coords.map(([x, y], index) => `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`).join(" ");
  const areaPath = `${linePath} L ${(padding.left + innerWidth).toFixed(2)} ${(padding.top + innerHeight).toFixed(2)} L ${padding.left} ${(padding.top + innerHeight).toFixed(2)} Z`;

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Message activity trend">
      <defs>
        <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="rgba(47,111,189,0.32)"></stop>
          <stop offset="100%" stop-color="rgba(47,111,189,0.02)"></stop>
        </linearGradient>
      </defs>
      <line x1="${padding.left}" y1="${padding.top + innerHeight}" x2="${padding.left + innerWidth}" y2="${padding.top + innerHeight}" stroke="#d9dde5" stroke-width="1"/>
      <path d="${areaPath}" fill="url(#trendFill)"></path>
      <path d="${linePath}" fill="none" stroke="#2f6fbd" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path>
      ${coords.map(([x, y]) => `<circle cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="2.6" fill="#ffffff" stroke="#2f6fbd" stroke-width="2"></circle>`).join("")}
      <text x="${padding.left}" y="12" fill="#6a7481" font-size="11" font-weight="700">Peak ${_formatNumber(maxValue)}</text>
      <text x="${padding.left + innerWidth}" y="12" text-anchor="end" fill="#6a7481" font-size="11">${_formatNumber(points[points.length - 1])}</text>
    </svg>
  `;
}

function _renderProtocolShareChart(values) {
  const container = document.getElementById("protocolShareChart");
  if (!container) return;

  const entries = Object.entries(values || {}).sort((a, b) => (Number(b[1]) || 0) - (Number(a[1]) || 0)).slice(0, 5);
  if (!entries.length) {
    container.innerHTML = `<div class="chart-empty">Protocol share appears here once packets are decoded.</div>`;
    return;
  }

  const total = entries.reduce((sum, [, value]) => sum + (Number(value) || 0), 0) || 1;
  const width = 360;
  const height = 136;
  const barX = 26;
  const barY = 24;
  const barWidth = width - 52;
  const barHeight = 18;
  let offset = 0;
  const segments = entries.map(([label, rawValue]) => {
    const value = Number(rawValue) || 0;
    const segmentWidth = (value / total) * barWidth;
    const color = (PROTOCOL_STYLE[String(label).toUpperCase()] || { color: "#8da6c8" }).color;
    const segment = `<rect x="${(barX + offset).toFixed(2)}" y="${barY}" width="${Math.max(segmentWidth, 4).toFixed(2)}" height="${barHeight}" rx="8" fill="${color}"></rect>`;
    offset += segmentWidth;
    return segment;
  }).join("");

  const legend = entries.map(([label, rawValue], index) => {
    const value = Number(rawValue) || 0;
    const color = (PROTOCOL_STYLE[String(label).toUpperCase()] || { color: "#8da6c8" }).color;
    const x = index % 2 === 0 ? 26 : 190;
    const y = 68 + Math.floor(index / 2) * 26;
    return `
      <rect x="${x}" y="${y - 10}" width="10" height="10" rx="3" fill="${color}"></rect>
      <text x="${x + 16}" y="${y}" fill="#334155" font-size="12" font-weight="700">${label}</text>
      <text x="${x + 128}" y="${y}" text-anchor="end" fill="#64748b" font-size="11">${Math.round((value / total) * 100)}%</text>
    `;
  }).join("");

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Protocol share chart">
      <rect x="${barX}" y="${barY}" width="${barWidth}" height="${barHeight}" rx="9" fill="#edf2f8"></rect>
      ${segments}
      <text x="${barX}" y="14" fill="#6a7481" font-size="11" font-weight="700">Top protocol mix</text>
      ${legend}
    </svg>
  `;
}

function _renderDurationProfileChart(sessions) {
  const container = document.getElementById("durationProfileChart");
  if (!container) return;

  const bins = _buildDurationBins(sessions);
  if (!bins.some(Boolean)) {
    container.innerHTML = `<div class="chart-empty">Session duration profile appears after correlation.</div>`;
    return;
  }

  const width = 360;
  const height = 136;
  const padding = { top: 18, right: 14, bottom: 24, left: 18 };
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  const maxValue = Math.max(...bins, 1);
  const barGap = 8;
  const barWidth = (innerWidth - barGap * (bins.length - 1)) / bins.length;
  const labels = ["0-1s", "1-5s", "5-15s", "15s+"];

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Session duration profile">
      <line x1="${padding.left}" y1="${padding.top + innerHeight}" x2="${padding.left + innerWidth}" y2="${padding.top + innerHeight}" stroke="#d9dde5" stroke-width="1"></line>
      ${bins.map((value, index) => {
        const x = padding.left + index * (barWidth + barGap);
        const h = (value / maxValue) * innerHeight;
        const y = padding.top + innerHeight - h;
        return `
          <rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barWidth.toFixed(2)}" height="${Math.max(h, 4).toFixed(2)}" rx="8" fill="${index === bins.length - 1 ? "#c48a4c" : "#6d95ca"}"></rect>
          <text x="${(x + barWidth / 2).toFixed(2)}" y="${height - 8}" text-anchor="middle" fill="#6a7481" font-size="10">${labels[index]}</text>
          <text x="${(x + barWidth / 2).toFixed(2)}" y="${Math.max(y - 6, 12).toFixed(2)}" text-anchor="middle" fill="#334155" font-size="11" font-weight="700">${value}</text>
        `;
      }).join("")}
    </svg>
  `;
}

function _buildTrafficSeries(sessions, protocolCounts) {
  const values = (sessions || []).map(session => {
    const flowCount = Array.isArray(session.flow) ? session.flow.length : 0;
    return Math.max(flowCount, Number(session.packet_count || 0), 1);
  }).slice(0, 10);

  if (values.length >= 2) return values;

  const fallback = Object.values(protocolCounts || {})
    .map(value => Number(value) || 0)
    .filter(Boolean)
    .slice(0, 10);

  return fallback.length ? fallback : values;
}

function _buildDurationBins(sessions) {
  const bins = [0, 0, 0, 0];
  (sessions || []).forEach(session => {
    const durationMs = Number(session.duration_ms || session.details_summary?.duration_ms || 0);
    if (durationMs <= 1000) bins[0] += 1;
    else if (durationMs <= 5000) bins[1] += 1;
    else if (durationMs <= 15000) bins[2] += 1;
    else bins[3] += 1;
  });
  return bins;
}

function _formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function _truncateMiddle(text, maxLen) {
  const value = String(text || "");
  if (value.length <= maxLen) return value;
  const keep = Math.max(8, Math.floor((maxLen - 3) / 2));
  return `${value.slice(0, keep)}...${value.slice(-keep)}`;
}

function renderLearningStatus(payload) {
  STATE.learning = payload || null;
  const status = payload?.status || {};
  const knowledge = payload?.knowledge || {};
  const retraining = status.last_retraining || null;
  _setText("learnedPatternCount", _formatNumber(knowledge.pattern_count ?? 0));
  _setText("learnedPcapCount", _formatNumber(knowledge.learned_pcap_count ?? 0));
  _setText("learningPendingCount", _formatNumber(status.new_pcaps ?? 0));
  _setText("learningStateLabel", status.running ? "Running" : "Ready");
  _setText("validationPendingCount", _formatNumber(STATE.validation?.pending_count ?? 0));
  _setText("validationTabLearningState", status.running ? "Running" : "Ready");
  _setText("validationTabPath", status.path || knowledge.default_learning_path || payload?.settings?.learn_path || "No path saved");
  _setText("learningStatusMessage", status.message || "System learning status will appear here.");

  const pathInput = document.getElementById("learningPathInput");
  const savedPath = status.path || knowledge.default_learning_path || payload?.settings?.learn_path;
  if (pathInput && savedPath && !pathInput.value) {
    pathInput.value = savedPath;
  }

  const governanceState = _summarizeGovernanceState(retraining, status);
  const driftState = _summarizeDriftState(retraining?.drift || null);
  _setText("governanceStateLabel", governanceState.label);
  _setText("governanceDetail", governanceState.detail);
  _setText("driftStatusLabel", driftState.label);
  _setText("driftDetail", driftState.detail);
}

function renderValidationQueue(payload) {
  STATE.validation = payload || null;
  _setText("validationPendingCount", _formatNumber(payload?.pending_count ?? 0));
  _setText("validationTabPendingCount", _formatNumber(payload?.pending_count ?? 0));
  const container = document.getElementById("validationQueue");
  if (!container) return;
  container.innerHTML = "";

  const items = payload?.items || [];
  const counts = payload?.label_counts || {};
  if (!items.length) {
    container.innerHTML = `<div class="trace-summary-item">No pending validation items.</div>`;
    return;
  }

  const summary = document.createElement("div");
  summary.className = "validation-summary";
  summary.innerHTML = Object.entries(counts)
    .map(([label, count]) => `<span class="chip">${label} x${count}</span>`)
    .join("");
  container.appendChild(summary);

  items.forEach(item => {
    const card = document.createElement("div");
    card.className = "validation-item";
    const status = String(item.validation_status || "pending_review").toLowerCase();
    card.innerHTML = `
      <div class="validation-item-head">
        <strong>${item.hybrid_root_cause || item.rule_root_cause || "UNKNOWN"}</strong>
        <span class="status-pill status-${status}">${item.validation_status || "pending_review"}</span>
      </div>
      <div class="validation-item-body">Session ${_truncateMiddle(item.session_id || "—", 64)} · confidence ${Math.round((Number(item.confidence_score || 0)) * 100)}%</div>
      <div class="validation-item-body">${item.agent_conflict ? "Agent conflict detected" : "Awaiting expert confirmation"}</div>
      <div class="validation-actions">
        <button type="button" onclick="submitValidationAction('${item.validation_id}', 'approve')">Approve</button>
        <button type="button" onclick="submitValidationAction('${item.validation_id}', 'reject')">Reject</button>
        <button type="button" onclick="submitValidationAction('${item.validation_id}', 'defer')">Defer</button>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderVersionInfo(payload) {
  STATE.versionInfo = payload || null;
  _setText("appVersion", payload?.version || "v0.0.0");

  const container = document.getElementById("versionHistoryContent");
  if (!container) return;
  container.innerHTML = "";

  const history = payload?.history || [];
  if (!history.length) {
    container.innerHTML = `<div class="trace-summary-item">No version history available.</div>`;
    return;
  }

  history.forEach(item => {
    const card = document.createElement("div");
    card.className = "history-item";
    const list = (item.changes || []).map(change => `<li>${change}</li>`).join("");
    card.innerHTML = `
      <h4>${item.version} · ${item.title}</h4>
      <div class="history-meta">${item.date}</div>
      <ul>${list}</ul>
    `;
    container.appendChild(card);
  });
}

function _summarizeGovernanceState(retraining, status = {}) {
  if (status?.retraining_running) {
    return {
      label: "Retraining running",
      detail: status.retraining_message || "Candidate models are being rebuilt in the background.",
    };
  }

  if (!retraining) {
    return {
      label: "Awaiting feedback",
      detail: "Retraining and promotion results will appear here.",
    };
  }

  if (retraining.reason === "insufficient_feedback_samples") {
    return {
      label: "Waiting for samples",
      detail: `Need ${retraining.min_samples || 0} reviewed sessions before retraining. Current feedback set: ${retraining.sample_count || 0}.`,
    };
  }

  if (retraining.reason === "feedback_drift_exceeds_limit") {
    return {
      label: "Retraining blocked",
      detail: "Feedback drift exceeded the safety gate, so candidate models were not trained or promoted.",
    };
  }

  if (retraining.promotion?.promoted) {
    return {
      label: "Candidate promoted",
      detail: "Candidate ranking and calibration artifacts cleared benchmark gates and were promoted to live models.",
    };
  }

  if (retraining.promotion?.evaluated) {
    return {
      label: "Candidate held",
      detail: "Candidate models were evaluated, but benchmark promotion gates kept the current live models in place.",
    };
  }

  if (retraining.retrained) {
    return {
      label: "Candidate trained",
      detail: "Retraining produced candidate artifacts. Promotion is disabled or deferred.",
    };
  }

  return {
    label: "No governance event",
    detail: "No retraining decision has been recorded yet.",
  };
}

function _summarizeDriftState(drift) {
  if (!drift) {
    return {
      label: "Not evaluated",
      detail: "Drift checks against the golden benchmark baseline will appear here.",
    };
  }

  const failedChecks = Array.isArray(drift.checks)
    ? drift.checks.filter(check => check && check.passed === false)
    : [];

  if (drift.passed) {
    return {
      label: "Within limits",
      detail: `Label ${_formatMetricValue(drift.label_drift)}, protocol ${_formatMetricValue(drift.protocol_drift)}, technology ${_formatMetricValue(drift.technology_drift)}, duration delta ${_formatMetricValue(drift.avg_duration_ratio_delta)}.`,
    };
  }

  const leadFailure = failedChecks[0];
  return {
    label: "Drift detected",
    detail: leadFailure?.detail || "One or more drift dimensions exceeded the configured safety limits.",
  };
}

function _formatMetricValue(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "n/a";
  return numeric.toFixed(3);
}

function toggleVersionHistory(show) {
  const modal = document.getElementById("versionHistoryModal");
  if (!modal) return;
  modal.style.display = show ? "flex" : "none";
}

/* ════════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════════ */
function _makeSVGEl(tag) {
  return document.createElementNS("http://www.w3.org/2000/svg", tag);
}

function _makeArrowMarker(id, fill, orient) {
  const marker = _makeSVGEl("marker");
  marker.setAttribute("id",           id);
  marker.setAttribute("markerWidth",  "8");
  marker.setAttribute("markerHeight", "8");
  marker.setAttribute("refX",         "7");
  marker.setAttribute("refY",         "3");
  marker.setAttribute("orient",       orient);
  const path = _makeSVGEl("path");
  path.setAttribute("d",    "M0,0 L7,3 L0,6 Z");
  path.setAttribute("fill", fill);
  marker.appendChild(path);
  return marker;
}

function _setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.innerText = text;
}
