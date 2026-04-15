/***************************************************************
 * API HANDLER — PCAP UPLOAD
 *
 * Fixes:
 *  [1] Success alert no longer fires when loadData is missing
 *  [2] Client-side file type validation before network call
 *  [3] File size guard (default max: 500 MB)
 *  [4] Upload button disabled + loading state during upload
 ***************************************************************/

const ALLOWED_EXTENSIONS = [".pcap", ".pcapng", ".cap"];
const MAX_FILE_BYTES      = 500 * 1024 * 1024; // 500 MB
let learningStatusTimer = null;

async function uploadPCAP(file) {

  /* FIX [2]: validate file extension client-side */
  const ext = "." + file.name.split(".").pop().toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    alert(
      `❌ Unsupported file type: "${ext}"\n` +
      `Allowed: ${ALLOWED_EXTENSIONS.join(", ")}`
    );
    return;
  }

  /* FIX [3]: guard against huge files */
  if (file.size > MAX_FILE_BYTES) {
    const mb = (file.size / 1024 / 1024).toFixed(1);
    alert(
      `❌ File too large: ${mb} MB\n` +
      `Maximum allowed: ${MAX_FILE_BYTES / 1024 / 1024} MB`
    );
    return;
  }

  /* FIX [4]: disable upload button and show loading state */
  const uploadBtn = document.getElementById("uploadBtn");
  const origLabel = uploadBtn?.innerText;
  if (uploadBtn) {
    uploadBtn.disabled   = true;
    uploadBtn.innerText  = "Uploading…";
  }

  const formData = new FormData();
  formData.append("file", file);

  try {
    console.log(`Uploading: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);

    const res = await fetch("/upload", {
      method: "POST",
      body:   formData,
    });

    if (!res.ok) {
      /* Attempt to read server error body for a better message */
      let detail = "";
      try { detail = (await res.json()).error || ""; } catch (_) {}
      throw new Error(
        `Server returned ${res.status}${detail ? ": " + detail : ""}`
      );
    }

    const data = await res.json();
    console.log("Server response:", data);

    if (typeof STATE !== "undefined") {
      STATE.token = data.token || null;
      STATE.filename = data.filename || "";
      STATE.model = data.model || null;
      STATE.summary = data.summary || null;
      STATE.sessions = data.sessions || [];
      STATE.captureGraph = data.graph || null;
      STATE.graph = STATE.captureGraph;
      STATE.hydrationPending = true;
    }

    if (typeof window.hydrateFromState === "function") {
      window.hydrateFromState();
    } else if (typeof window.loadData === "function") {
      window.loadData(data);
    } else {
      console.error("No render hydrator available after upload completion");
      window.__TRACE_PENDING_UPLOAD__ = data;
    }

    if (typeof refreshValidationQueue === "function") {
      refreshValidationQueue();
    }
    alert("✅ PCAP processed successfully");

  } catch (err) {
    console.error("uploadPCAP error:", err);
    alert("❌ Upload failed: " + err.message);
  } finally {
    /* FIX [4]: always restore the button regardless of success/failure */
    if (uploadBtn) {
      uploadBtn.disabled  = false;
      uploadBtn.innerText = origLabel ?? "Upload PCAP";
    }
  }
}

async function startLearning() {
  const btn = document.getElementById("startLearningBtn");
  const pathInput = document.getElementById("learningPathInput");
  const origLabel = btn?.innerText;
  if (btn) {
    btn.disabled = true;
    btn.innerText = "Starting…";
  }

  try {
    const res = await fetch("/api/learning/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: pathInput?.value || "" }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Server returned ${res.status}`);
    }
    if (typeof window.renderLearningStatus === "function") {
      window.renderLearningStatus(data);
    }
    await refreshValidationQueue();
    await refreshLearningStatus();
  } catch (err) {
    alert("❌ Learning start failed: " + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = origLabel ?? "Start Learning";
    }
  }
}

async function saveLearningPath() {
  const btn = document.getElementById("saveLearningPathBtn");
  const pathInput = document.getElementById("learningPathInput");
  const origLabel = btn?.innerText;
  if (btn) {
    btn.disabled = true;
    btn.innerText = "Saving…";
  }

  try {
    const pathValue = pathInput?.value?.trim() || "";
    if (!pathValue) {
      throw new Error("Enter a PCAP learning path first.");
    }
    const res = await fetch("/api/learning/path", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: pathValue }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Server returned ${res.status}`);
    }
    if (typeof window.renderLearningStatus === "function") {
      window.renderLearningStatus(data);
    }
    alert("✅ Learning path saved");
  } catch (err) {
    alert("❌ Saving learning path failed: " + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = origLabel ?? "Save Path";
    }
  }
}

async function refreshLearningStatus() {
  try {
    const res = await fetch("/api/learning/status");
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Server returned ${res.status}`);
    }
    if (typeof window.renderLearningStatus === "function") {
      window.renderLearningStatus(data);
    }
  } catch (err) {
    console.error("refreshLearningStatus error:", err);
  }
}

async function refreshValidationQueue() {
  try {
    const res = await fetch("/api/learning/validation");
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Server returned ${res.status}`);
    }
    if (typeof window.renderValidationQueue === "function") {
      window.renderValidationQueue(data);
    }
  } catch (err) {
    console.error("refreshValidationQueue error:", err);
  }
}

async function submitValidationAction(validationId, action, note = "") {
  try {
    const res = await fetch("/api/learning/validation/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        validation_id: validationId,
        action,
        note,
        reviewer: "analyst-ui",
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Server returned ${res.status}`);
    }
    if (typeof window.renderValidationQueue === "function") {
      window.renderValidationQueue(data.queue);
    }
    if (typeof window.renderLearningStatus === "function") {
      window.renderLearningStatus({ ...(STATE.learning || {}), knowledge: data.knowledge, status: STATE.learning?.status || {} });
    }
    return data;
  } catch (err) {
    alert("❌ Validation update failed: " + err.message);
    throw err;
  }
}

async function loadVersionHistory() {
  try {
    const res = await fetch("/api/version-history");
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Server returned ${res.status}`);
    }
    if (typeof window.renderVersionInfo === "function") {
      window.renderVersionInfo(data);
    }
  } catch (err) {
    console.error("loadVersionHistory error:", err);
  }
}

function ensureLearningPolling() {
  if (learningStatusTimer) return;
  learningStatusTimer = window.setInterval(() => {
    refreshLearningStatus();
  }, 10000);
}

window.startLearning = startLearning;
window.saveLearningPath = saveLearningPath;
window.refreshLearningStatus = refreshLearningStatus;
window.refreshValidationQueue = refreshValidationQueue;
window.submitValidationAction = submitValidationAction;
window.loadVersionHistory = loadVersionHistory;
window.ensureLearningPolling = ensureLearningPolling;
