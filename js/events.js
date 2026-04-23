/***************************************************************
 * EVENT WIRING
 *
 * Fixes:
 *  [1] window.onload → addEventListener (non-destructive)
 *  [2] Null guards on every getElementById — one missing element
 *      no longer kills all other listeners
 *  [3] protocolFilter uses selectSession re-render path (Array guard)
 *  [4] onclick/onchange → addEventListener (non-destructive)
 *  [5] switchTab guards against missing tab elements
 ***************************************************************/

/* FIX [1]: addEventListener instead of window.onload assignment */
window.addEventListener("load", () => {

  /* FIX [2]: null-guard every element before wiring */
  const uploadBtn  = document.getElementById("uploadBtn");
  const fileInput  = document.getElementById("fileInput");
  const startLearningBtn = document.getElementById("startLearningBtn");
  const saveLearningPathBtn = document.getElementById("saveLearningPathBtn");
  const versionButton = document.getElementById("versionButton");
  const closeVersionModal = document.getElementById("closeVersionModal");
  const versionModal = document.getElementById("versionHistoryModal");
  const demoModeToggle = document.getElementById("demoModeToggle");

  if (uploadBtn && fileInput) {
    /* FIX [4]: addEventListener instead of .onclick assignment */
    uploadBtn.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", async () => {
      const file = fileInput.files[0];
      if (!file) return;
      await uploadPCAP(file);
      /* Reset so the same file can be re-uploaded if needed */
      fileInput.value = "";
    });
  } else {
    console.warn("events.js: uploadBtn or fileInput not found in DOM");
  }

  if (startLearningBtn) {
    startLearningBtn.addEventListener("click", async () => {
      if (typeof startLearning === "function") {
        await startLearning();
      }
    });
  }

  if (saveLearningPathBtn) {
    saveLearningPathBtn.addEventListener("click", async () => {
      if (typeof saveLearningPath === "function") {
        await saveLearningPath();
      }
    });
  }

  if (versionButton) {
    versionButton.addEventListener("click", () => {
      if (typeof toggleVersionHistory === "function") {
        toggleVersionHistory(true);
      }
    });
  }

  if (closeVersionModal) {
    closeVersionModal.addEventListener("click", () => {
      if (typeof toggleVersionHistory === "function") {
        toggleVersionHistory(false);
      }
    });
  }

  if (versionModal) {
    versionModal.addEventListener("click", e => {
      if (e.target === versionModal && typeof toggleVersionHistory === "function") {
        toggleVersionHistory(false);
      }
    });
  }

  initDemoModeToggle(demoModeToggle);

  /* ── Filter: session type ── */
  const sessionFilter = document.getElementById("sessionFilter");
  if (sessionFilter) {
    sessionFilter.addEventListener("change", e => {
      STATE.filters.sessionType = e.target.value;
      renderSessions();
    });
  } else {
    console.warn("events.js: sessionFilter not found in DOM");
  }

  /* ── Filter: free-text search ── */
  const searchBox = document.getElementById("searchBox");
  if (searchBox) {
    searchBox.addEventListener("input", e => {
      STATE.filters.search = e.target.value.toLowerCase();
      renderSessions();
    });
  } else {
    console.warn("events.js: searchBox not found in DOM");
  }

  /* ── Filter: protocol ──
     FIX [3]: re-render via selectSession so the Array.isArray guard
     in render.js applies, instead of calling renderLadder directly */
  const protocolFilter = document.getElementById("protocolFilter");
  if (protocolFilter) {
    protocolFilter.addEventListener("change", e => {
      STATE.filters.protocol = e.target.value;
      if (STATE.selected) {
        selectSession(STATE.selected); /* re-runs the full render path */
      }
    });
  } else {
    console.warn("events.js: protocolFilter not found in DOM");
  }

  if (typeof refreshLearningStatus === "function") {
    refreshLearningStatus();
  }
  if (typeof refreshValidationQueue === "function") {
    refreshValidationQueue();
  }
  if (typeof ensureLearningPolling === "function") {
    ensureLearningPolling();
  }
  if (typeof loadVersionHistory === "function") {
    loadVersionHistory();
  }
  if (typeof loadSystemHealth === "function") {
    loadSystemHealth();
  }
  initContextHelp();

});

function initDemoModeToggle(toggle) {
  const storedMode = window.localStorage?.getItem(DEMO_MODE_STORAGE_KEY);
  setUIMode(storedMode === "demo" ? "demo" : "production");

  if (!toggle) return;
  toggle.addEventListener("click", () => {
    setUIMode(isDemoMode() ? "production" : "demo", { persist: true, announce: true });
  });
}

function isDemoMode() {
  return STATE.uiMode === "demo";
}

function setUIMode(mode, options = {}) {
  const nextMode = mode === "demo" ? "demo" : "production";
  STATE.uiMode = nextMode;
  document.body.classList.toggle("demo-mode", nextMode === "demo");

  const toggle = document.getElementById("demoModeToggle");
  const label = document.getElementById("demoModeLabel");
  if (toggle) {
    toggle.classList.toggle("demo-active", nextMode === "demo");
    toggle.setAttribute("aria-pressed", nextMode === "demo" ? "true" : "false");
    toggle.dataset.helpTitle = "Production / Demo Mode";
    toggle.dataset.help = "Switches between quiet production usage and guided demo explanations.";
    toggle.dataset.helpDetail = "Demo mode enables detailed hover/click coaching across the dashboard. Production mode disables those popovers so analysts can work without interruption.";
  }
  if (label) label.innerText = nextMode === "demo" ? "Demo Mode" : "Production Mode";

  if (options.persist) {
    window.localStorage?.setItem(DEMO_MODE_STORAGE_KEY, nextMode);
  }
  refreshContextHelpAffordances();
  if (nextMode !== "demo" && typeof hideContextHelp === "function") {
    hideContextHelp(true);
  }
  if (options.announce && nextMode === "demo") {
    const target = toggle || document.body;
    window.setTimeout(() => showContextHelpForTarget(target, true), 0);
  }
}

const DEMO_MODE_STORAGE_KEY = "tracemap-ui-mode";

const CONTEXT_HELP_ITEMS = [
  {
    selector: ".brand-mark",
    title: "TraceMAP Workbench",
    body: "This is the main packet-to-session RCA console. It takes raw PCAPs and turns them into correlated telecom sessions, RCA evidence, topology, and analyst-ready views.",
    detail: "How it works: after upload, the backend parses protocol fields, builds session buckets, stitches related identities, applies RCA rules and autonomous reasoning, then pushes the summarized results back into this dashboard."
  },
  {
    selector: "#demoModeToggle",
    title: "Production / Demo Mode",
    body: "Switches between a quiet production workspace and a guided demo workspace.",
    detail: "Production mode disables explanatory popovers so analysts can work without interruption. Demo mode enables detailed coaching on hover, focus, or click, including what each item shows and how the tool produces it."
  },
  {
    selector: ".tab-button[data-tab='analysis']",
    title: "Overview",
    body: "The front-page investigation cockpit. It brings together capture health, selected-session briefing, RCA, topology, correlation evidence, and analyst next checks.",
    detail: "How it works: this tab combines capture-level summary data with the currently selected session. Changing the selected session updates Trace Briefing, Session RCA, Correlation, Failure Topology, and the supporting evidence panels."
  },
  {
    selector: ".tab-button[data-tab='errors']",
    title: "Protocol Audit",
    body: "Telecom-aware protocol audit. It separates expected control-plane behavior from genuine error signatures.",
    detail: "How it works: parsed SIP, Diameter, GTP, NAS, PFCP, RADIUS, TCP, and access protocol markers are grouped into categories with severity, examples, and recommendations."
  },
  {
    selector: ".tab-button[data-tab='visual']",
    title: "Visualization",
    body: "Visual exploration space for call-flow reading, endpoint topology, and causal RCA chains.",
    detail: "How it works: the selected session provides normalized flow events. Ladder View preserves time order, Graph View aggregates endpoint paths, and Causal View shows weighted RCA contributors."
  },
  {
    selector: ".tab-button[data-tab='learning']",
    title: "Learning",
    body: "Controls autonomous learning from PCAP folders and shows learning health.",
    detail: "How it works: the learner scans a configured folder, extracts patterns, updates candidate knowledge, and uses governance checks before promoting new intelligence."
  },
  {
    selector: ".tab-button[data-tab='validation']",
    title: "Validation",
    body: "Analyst review queue for uncertain, conflicting, or high-value learning candidates.",
    detail: "How it works: the system queues items when confidence is insufficient or agents disagree. Analyst approval, rejection, or deferral controls whether those learnings reinforce the knowledge base."
  },
  {
    selector: "#fileName",
    title: "Current Capture",
    body: "Shows the currently loaded PCAP or trace identifier.",
    detail: "How it works: upload and job polling update this value, so the active dashboard always stays tied to the capture being analyzed."
  },
  {
    selector: "#uploadBtn",
    title: "Upload PCAP",
    body: "Loads a packet capture and starts the full analysis pipeline.",
    detail: "How it works: the PCAP is submitted to the backend, parsed through tshark and protocol-specific extractors, converted into sessions, scored by RCA logic, and returned as dashboard-ready JSON."
  },
  {
    selector: "#sessionFilter",
    title: "Session Filter",
    body: "Narrows the Session Explorer by RCA outcome.",
    detail: "How it works: this filter does not re-run parsing. It filters the in-memory session list so you can quickly focus on abnormal sessions or known-good baseline sessions."
  },
  {
    selector: "#searchBox",
    title: "Session Search",
    body: "Searches across session identifiers, parties, protocols, technologies, and RCA text.",
    detail: "How it works: as you type, the UI matches Call-ID, IMSI, MSISDN, A/B party, RCA label, call type, protocol, and technology fields in the already-loaded session set."
  },
  {
    selector: "#protocolFilter",
    title: "Protocol Filter",
    body: "Limits the visible sessions and visual flow to a selected protocol family.",
    detail: "How it works: sessions remain correlated, but the list and visualization are filtered to those containing the chosen protocol so protocol-specific review is less noisy."
  },
  {
    selector: ".trace-overview",
    title: "Trace Overview",
    body: "High-level capture story: trace type, scenario, parties, window, technologies, and correlated session count.",
    detail: "How it works: this panel is built from capture-wide protocol counts, inferred technologies, party identity extraction, capture timing, and session summary statistics."
  },
  {
    selector: ".briefing-panel",
    title: "Trace Briefing",
    body: "Explains the currently selected session and the exact correlation anchor used to select it.",
    detail: "How it works: when you click a session, the UI receives a selected_filter and correlation_anchors list such as Call-ID, TEID, Diameter Session-ID, PFCP SEID, IMSI, MSISDN, or Subscriber IP."
  },
  {
    selector: ".capture-analytics",
    title: "Capture Analytics",
    body: "Capture-level KPIs and charts for activity, protocol share, and session duration distribution.",
    detail: "How it works: the backend summarizes parsed packets and correlated sessions; the frontend renders those counts into KPIs and SVG charts without changing the underlying analysis."
  },
  {
    selector: ".session-rca-panel",
    title: "Session RCA",
    body: "Primary RCA explanation for the selected session, including priority, severity, confidence, evidence, and recommended checks.",
    detail: "How it works: rule output, protocol intelligence, autonomous agent results, causal signals, and learned patterns are merged into a concise analyst narrative."
  },
  {
    selector: ".failure-topology-panel",
    title: "Failure Topology",
    body: "Clickable service path or failure path across inferred network functions.",
    detail: "How it works: the selected session flow is normalized into network-function nodes and protocol edges. When an abnormal RCA and failure marker exist, the likely break path is highlighted; normal sessions stay in neutral colors."
  },
  {
    selector: ".expert-findings",
    title: "Expert Findings",
    body: "Prioritized starting points for investigation.",
    detail: "How it works: capture-level anomalies, abnormal session priority, transport issues, and dominant protocol findings are ranked into short analyst prompts."
  },
  {
    selector: ".intelligence-panel",
    title: "Protocol And Endpoint Intelligence",
    body: "Breakdowns of protocol mix, technology mix, top endpoints, and RCA distribution.",
    detail: "How it works: this panel aggregates parsed packets and session labels to reveal what protocols dominate the trace and which endpoints are most active."
  },
  {
    selector: ".correlation-panel",
    title: "Correlation Inspector",
    body: "Shows how the selected session was bound across protocols and technologies.",
    detail: "How it works: identity methods are hard anchors like Call-ID, Session-ID, TEID, IMSI, and Subscriber IP. Stateful methods explain stitching such as TEID continuation or access-subscriber bridging."
  },
  {
    selector: ".autonomous-panel",
    title: "Autonomous Reasoning",
    body: "Shows agent votes, causal chain, confidence model, and knowledge signals behind the selected RCA.",
    detail: "How it works: protocol-specialist agents and learned knowledge produce supporting hypotheses. The confidence model then calibrates the result instead of blindly trusting a single rule."
  },
  {
    selector: ".view-toggle button:nth-child(1)",
    title: "Ladder View",
    body: "Chronological message ladder across endpoints and protocols.",
    detail: "How it works: the selected session flow is sorted by timestamp, endpoints become vertical lifelines, and each message is drawn as an arrow with protocol color and failure styling."
  },
  {
    selector: ".view-toggle button:nth-child(2)",
    title: "Graph View",
    body: "Endpoint topology view with aggregated protocol paths.",
    detail: "How it works: repeated messages between the same endpoints are collapsed into weighted edges so you can see who talked to whom without reading every packet."
  },
  {
    selector: ".view-toggle button:nth-child(3)",
    title: "Causal View",
    body: "Weighted event chain used by the RCA engine.",
    detail: "How it works: causal inference ranks important events and links them by time, protocol semantics, and learned dependency signals so the RCA has a visible reasoning trail."
  },
  {
    selector: "#graphFitBtn",
    title: "Fit Graph",
    body: "Recenters and scales the graph to fit the canvas.",
    detail: "How it works: this calls the graph library fit operation, which recalculates the viewport without changing the underlying graph or session correlation."
  },
  {
    selector: "#graphPhysicsBtn",
    title: "Graph Physics",
    body: "Pauses or resumes automatic graph layout.",
    detail: "How it works: when physics is active, the graph uses a force layout to reduce overlap. Pause it when the topology is readable and you want stable positions during inspection."
  },
  {
    selector: "#saveLearningPathBtn",
    title: "Save Learning Path",
    body: "Stores the folder used by autonomous learning.",
    detail: "How it works: the configured path is persisted in learning settings and used by the watcher to discover PCAPs that have not already been processed."
  },
  {
    selector: "#startLearningBtn",
    title: "Start Learning",
    body: "Runs a supervised learning pass over newly discovered PCAPs.",
    detail: "How it works: the learner extracts session patterns, updates candidate knowledge, writes run reports, and routes uncertain/conflicting findings to the Validation Queue."
  },
  {
    selector: "#versionButton",
    title: "Release History",
    body: "Opens the release health summary and tool improvement history.",
    detail: "How it works: the frontend calls the version-history and system-health APIs, displays the current app version, git commit, environment checks, and release notes from docs/version_history.json."
  },
  {
    selector: ".release-health-panel",
    title: "Release Health",
    body: "Production-readiness checkpoint for the running tool instance.",
    detail: "How it works: the backend checks Python, writable runtime folders, git release state, auth posture, tshark availability, and protocol/field compatibility. This catches stale branch, Windows setup, and tshark-version issues before upload."
  },
  {
    selector: ".failure-topology-legend",
    title: "Failure Topology Legend",
    body: "Explains node colors and highlighted edges in the service/failure topology.",
    detail: "How it works: neutral nodes are inferred functions, blue nodes are implicated only when a failure exists, and red failure markers are hidden for normal sessions."
  },
  {
    selector: ".graph-legend",
    title: "Topology Legend",
    body: "Maps node roles and protocol colors used by the graph.",
    detail: "How it works: role entries come from inferred node types, while protocol entries come from the protocols represented by visible graph edges."
  },
  {
    selector: "#graphSelection",
    title: "Graph Selection",
    body: "Shows details for the selected graph node, path, event, or edge.",
    detail: "How it works: clicking graph objects reads the associated metadata and renders endpoint, protocol, message, weight, or causal timing details here."
  },
  {
    selector: "#failureTopologySelection",
    title: "Topology Selection",
    body: "Shows details for the selected topology node or edge.",
    detail: "How it works: topology nodes carry inferred role, address, confidence, evidence, and protocol list; edges carry protocol, hit count, normal/failure status, and break-path meaning."
  },
  {
    selector: ".error-hero-panel",
    title: "Error Summary",
    body: "Protocol-aware assessment of whether the trace looks healthy, noisy, or failure-bearing.",
    detail: "How it works: error categories are scored by protocol semantics so expected messages such as normal authentication challenges are not treated the same as service-impacting failures."
  },
  {
    selector: ".validation-workbench",
    title: "Review Workbench",
    body: "Workspace for approving, rejecting, or deferring learning candidates.",
    detail: "How it works: analyst actions update validation status and determine whether proposed knowledge should reinforce future RCA behavior."
  }
];

let contextHelpTooltip = null;
let contextHelpActiveTarget = null;
let contextHelpPinned = false;

function initContextHelp() {
  applyContextHelpAttributes();

  contextHelpTooltip = document.getElementById("contextHelpPopover");
  if (!contextHelpTooltip) {
    contextHelpTooltip = document.createElement("div");
    contextHelpTooltip.id = "contextHelpPopover";
    contextHelpTooltip.className = "context-help-popover";
    contextHelpTooltip.setAttribute("role", "status");
    contextHelpTooltip.innerHTML = `
      <div class="context-help-kicker">Demo coach</div>
      <div class="context-help-title"></div>
      <div class="context-help-body"></div>
      <div class="context-help-detail"></div>
      <div class="context-help-foot">Production mode hides this. Click pins it. Esc closes.</div>
    `;
    document.body.appendChild(contextHelpTooltip);
  }
  refreshContextHelpAffordances();

  document.addEventListener("pointerover", event => {
    if (!isDemoMode() || contextHelpPinned) return;
    const target = targetFromHelpEvent(event);
    if (target) showContextHelpForTarget(target);
  }, true);

  document.addEventListener("pointerout", event => {
    if (!isDemoMode() || contextHelpPinned) return;
    const target = targetFromHelpEvent(event);
    if (target && !target.contains(event.relatedTarget)) hideContextHelp();
  }, true);

  document.addEventListener("focusin", event => {
    if (!isDemoMode()) return;
    const target = targetFromHelpEvent(event);
    if (target) showContextHelpForTarget(target);
  }, true);

  document.addEventListener("focusout", event => {
    if (!isDemoMode() || contextHelpPinned) return;
    if (targetFromHelpEvent(event)) hideContextHelp();
  }, true);

  document.addEventListener("click", event => {
    if (!isDemoMode()) return;
    const target = targetFromHelpEvent(event);
    if (target) {
      showContextHelpForTarget(target, true);
      return;
    }
    if (!contextHelpTooltip?.contains(event.target)) hideContextHelp(true);
  }, true);

  document.addEventListener("keydown", event => {
    if (event.key === "Escape") hideContextHelp(true);
  });

  window.addEventListener("resize", () => positionContextHelp(contextHelpActiveTarget));
  window.addEventListener("scroll", () => positionContextHelp(contextHelpActiveTarget), true);
}

function targetFromHelpEvent(event) {
  if (!isDemoMode()) return null;
  return event.target?.closest?.("[data-help], [data-tip]");
}

function hasContextHelp(target) {
  return Boolean((target?.dataset?.help || target?.dataset?.tip || "").trim());
}

function positionContextHelp(target) {
  if (!target || !contextHelpTooltip?.classList.contains("visible")) return;
  const rect = target.getBoundingClientRect();
  const margin = 12;
  const tooltipRect = contextHelpTooltip.getBoundingClientRect();
  const width = tooltipRect.width || 440;
  const height = tooltipRect.height || 180;
  let left = rect.left + rect.width / 2 - width / 2;
  let top = rect.bottom + margin;

  if (top + height > window.innerHeight - margin) {
    top = Math.max(margin, rect.top - height - margin);
  }
  left = Math.max(margin, Math.min(window.innerWidth - width - margin, left));

  contextHelpTooltip.style.left = `${Math.round(left)}px`;
  contextHelpTooltip.style.top = `${Math.round(top)}px`;
}

function showContextHelpForTarget(target, pin = false) {
  if (!isDemoMode() || !hasContextHelp(target) || !contextHelpTooltip) return;
  contextHelpActiveTarget = target;
  contextHelpPinned = Boolean(pin);
  const titleEl = contextHelpTooltip.querySelector(".context-help-title");
  const bodyEl = contextHelpTooltip.querySelector(".context-help-body");
  const detailEl = contextHelpTooltip.querySelector(".context-help-detail");
  const titleFallback = target.querySelector?.(".mini-title, span")?.innerText?.trim();
  const title = target.dataset.helpTitle || target.dataset.tipTitle || target.getAttribute("aria-label") || titleFallback || target.innerText?.trim() || "Quick help";
  const body = target.dataset.help || target.dataset.tip;
  const detail = target.dataset.helpDetail || defaultDemoDetailFor(target);

  if (titleEl) titleEl.innerText = title;
  if (bodyEl) bodyEl.innerText = body;
  if (detailEl) detailEl.innerText = detail;
  contextHelpTooltip.classList.toggle("pinned", contextHelpPinned);
  contextHelpTooltip.classList.add("visible");
  positionContextHelp(target);
}

function hideContextHelp(force = false) {
  if (contextHelpPinned && !force) return;
  contextHelpPinned = false;
  contextHelpActiveTarget = null;
  contextHelpTooltip?.classList.remove("visible", "pinned");
}

function defaultDemoDetailFor(target) {
  if (target?.classList?.contains("kpi")) {
    return "How it works: this KPI is calculated from the parsed capture summary and correlated sessions. It updates after upload and reflects the active capture, not a static demo number.";
  }
  if (target?.classList?.contains("session")) {
    return "How it works: clicking this session refreshes Trace Briefing, RCA evidence, topology, correlation inspector, and visualization panels using the session's normalized flow and identifiers.";
  }
  return "";
}

function applyContextHelpAttributes(root = document) {
  CONTEXT_HELP_ITEMS.forEach(item => {
    root.querySelectorAll(item.selector).forEach(element => {
      if (!element.dataset.helpTitle) element.dataset.helpTitle = item.title;
      if (!element.dataset.help) element.dataset.help = item.body;
      if (item.detail && !element.dataset.helpDetail) element.dataset.helpDetail = item.detail;
      if (!element.getAttribute("aria-label")) element.setAttribute("aria-label", item.title);
    });
  });
  refreshContextHelpAffordances(root);
}

function refreshContextHelpAffordances(root = document) {
  root.querySelectorAll("[data-help], [data-tip]").forEach(element => {
    element.classList.toggle("mode-aware", isDemoMode());
    if (["BUTTON", "SELECT", "INPUT", "TEXTAREA", "A"].includes(element.tagName)) return;
    if (isDemoMode()) {
      if (!element.hasAttribute("tabindex")) {
        element.setAttribute("tabindex", "0");
        element.dataset.helpTabindexAdded = "true";
      }
    } else if (element.dataset.helpTabindexAdded === "true") {
      element.removeAttribute("tabindex");
      delete element.dataset.helpTabindexAdded;
    }
  });
}

/* ════════════════════════════════════════════════════════════════
   TAB SWITCH
   FIX [5]: guard against missing tab elements
   ════════════════════════════════════════════════════════════════ */
function switchTab(tab) {
  const analysisTab = document.getElementById("analysisTab");
  const errorTab = document.getElementById("errorTab");
  const visualTab   = document.getElementById("visualTab");
  const learningTab = document.getElementById("learningTab");
  const validationTab = document.getElementById("validationTab");
  const tabButtons = document.querySelectorAll(".tab-button");

  if (analysisTab) analysisTab.style.display = tab === "analysis" ? "block" : "none";
  if (errorTab) errorTab.style.display = tab === "errors" ? "block" : "none";
  if (visualTab)   visualTab.style.display   = tab === "visual"   ? "block" : "none";
  if (learningTab) learningTab.style.display = tab === "learning" ? "block" : "none";
  if (validationTab) validationTab.style.display = tab === "validation" ? "block" : "none";
  tabButtons.forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });

  if (tab === "visual" && typeof _refreshVisualView === "function") {
    _refreshVisualView();
  }
}
