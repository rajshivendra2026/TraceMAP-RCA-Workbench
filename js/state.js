/***************************************************************
 * GLOBAL STATE (SINGLE SOURCE OF TRUTH)
 *
 * Must load before all other scripts.
 * Filters declared here — not in render.js — so no script
 * depends on render.js having run first.
 ***************************************************************/

const STATE = {
  token:     null,     // upload token used for follow-up API calls
  filename:  "",       // most recently uploaded PCAP
  model:     null,     // model status payload from backend
  summary:   null,     // capture-level technology/protocol summary
  learning:  null,     // learning status payload
  validation: null,    // validation queue payload
  versionInfo: null,   // version history payload
  captureGraph: null,  // capture-wide topology graph
  sessions:  [],       // Session[] from server
  selected:  null,     // currently selected session
  graph:     null,     // current graph (session or capture)
  graphNetwork: null,  // vis.js network instance for graph view
  graphPhysicsEnabled: true,
  uiMode: "production", // "production" | "demo"
  viewMode:  "ladder", // "ladder" | "graph" | "causal"
  hydrationPending: false,

  filters: {
    sessionType: "ALL", // "ALL" | "FAILED" | "SUCCESS"
    search:      "",    // free-text search across call_id / imsi / msisdn
    protocol:    "ALL", // "ALL" | "SIP" | "DIAMETER" | "INAP" | "S1AP"
  },
};

/*
 * Upload/render handshake
 *
 * API callbacks may complete before render.js finishes evaluating,
 * especially after hard UI refactors or when the browser serves a stale
 * script from cache. Keep a safe placeholder so uploads never fail just
 * because loadData was not exported yet.
 */
window.__TRACE_PENDING_UPLOAD__ = window.__TRACE_PENDING_UPLOAD__ || null;

window.traceDebug = function traceDebug(stage, meta = {}) {
  try {
    console.debug(`[TraceMAP] ${stage}`, meta);
    fetch("/api/debug/frontend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        stage,
        meta,
        ts: new Date().toISOString(),
      }),
    }).catch(() => {});
  } catch (_) {}
};

window.addEventListener("error", event => {
  window.traceDebug("window.error", {
    message: event.message,
    source: event.filename,
    line: event.lineno,
    column: event.colno,
  });
});

window.addEventListener("unhandledrejection", event => {
  window.traceDebug("window.unhandledrejection", {
    reason: String(event.reason || "unknown"),
  });
});

if (typeof window.loadData !== "function") {
  window.loadData = function queuePendingUpload(data) {
    const payload = data || {};
    STATE.token = payload.token || null;
    STATE.filename = payload.filename || "";
    STATE.model = payload.model || null;
    STATE.summary = payload.summary || null;
    STATE.sessions = payload.sessions || [];
    STATE.captureGraph = payload.graph || null;
    STATE.graph = STATE.captureGraph;
    STATE.hydrationPending = true;
    window.__TRACE_PENDING_UPLOAD__ = payload;
    window.traceDebug("queuePendingUpload", {
      filename: STATE.filename,
      sessions: STATE.sessions.length,
    });
  };
}
