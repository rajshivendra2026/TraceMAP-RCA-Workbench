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
  const versionButton = document.getElementById("versionButton");
  const closeVersionModal = document.getElementById("closeVersionModal");
  const versionModal = document.getElementById("versionHistoryModal");

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

});

/* ════════════════════════════════════════════════════════════════
   TAB SWITCH
   FIX [5]: guard against missing tab elements
   ════════════════════════════════════════════════════════════════ */
function switchTab(tab) {
  const analysisTab = document.getElementById("analysisTab");
  const visualTab   = document.getElementById("visualTab");

  if (analysisTab) analysisTab.style.display = tab === "analysis" ? "block" : "none";
  if (visualTab)   visualTab.style.display   = tab === "visual"   ? "block" : "none";
}
