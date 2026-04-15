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
  viewMode:  "ladder", // "ladder" | "graph" | "causal"

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

if (typeof window.loadData !== "function") {
  window.loadData = function queuePendingUpload(data) {
    window.__TRACE_PENDING_UPLOAD__ = data || null;
  };
}
