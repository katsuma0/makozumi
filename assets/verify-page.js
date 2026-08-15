// ============================================================
// Makozumi verifier page controller.
//
// Its whole job: take a code from the URL (an NFC tap), a paste, or a
// Web NFC scan, run it through the verification core, and show the result.
// It renders nothing from a code until that code's signature has been
// checked, and it writes every value with textContent, never innerHTML.
// ============================================================

import {
  verifyToken,
  loadRevocations,
  isOfficialOrigin,
  isFramed,
  enforceSecureContext,
  extractToken,
  DISPLAY_FIELDS,
  OFFICIAL_ORIGINS,
  PUBLIC_KEYS,
} from "./makozumi.js";

const $ = (id) => document.getElementById(id);

// --- refuse to run inside someone else's frame ---------------
if (isFramed()) {
  $("app").classList.add("hidden");
  $("framed").classList.remove("hidden");
  throw new Error("framed");
}

// --- refuse to run on plain http (WebCrypto needs a secure context) ---
if (!enforceSecureContext()) {
  throw new Error("redirecting to https");
}

// --- tell the visitor exactly which site they are on ---------
(function showOrigin() {
  const el = $("origin");
  const text = $("origin-text");
  const host = location.host || "this device";
  if (isOfficialOrigin()) {
    el.classList.add("good");
    text.textContent = "";
    const label = document.createElement("span");
    label.textContent = "Official site · ";
    const b = document.createElement("b");
    b.textContent = host;
    text.append(label, b);
  } else if (["localhost", "127.0.0.1", "[::1]", ""].includes(location.hostname)) {
    text.textContent = "Local preview · " + host;
  } else {
    el.classList.add("bad");
    text.textContent = "";
    const b = document.createElement("b");
    b.textContent = host;
    const rest = document.createElement("span");
    rest.textContent =
      " is not the official Makozumi site. Check results only at " +
      OFFICIAL_ORIGINS[0].replace(/^https:\/\//, "") + "/makozumi/";
    text.append(b, rest);
  }
})();

// --- revocation list (fetched once, non-blocking) ------------
let revoked = new Set();
let revocationAvailable = false;
const revocationReady = loadRevocations().then((r) => {
  revoked = r.revoked;
  revocationAvailable = r.available;
  if (!r.available) {
    const n = $("revocation-notice");
    n.textContent =
      "The revocation list could not be loaded, so this check could not confirm the item has not been reported lost or stolen. The signature check below is unaffected.";
    n.classList.remove("hidden");
  }
  return r;
});

// --- rendering ----------------------------------------------

const STATE_UI = {
  authentic: { cls: "ok", label: "✓ AUTHENTIC" },
  expired: { cls: "warn", label: "⚠ EXPIRED" },
  revoked: { cls: "bad", label: "⚠ REVOKED" },
  forged: { cls: "bad", label: "✕ NOT AUTHENTIC" },
  malformed: { cls: "bad", label: "✕ NOT A MAKOZUMI CODE" },
  unsupported: { cls: "warn", label: "⚠ CANNOT CHECK" },
};

function setStatus(cls, big, sub) {
  const el = $("status");
  el.className = "status " + cls;
  el.textContent = "";
  const b = document.createElement("div");
  b.className = "big";
  b.textContent = big;
  const s = document.createElement("div");
  s.className = "sub";
  s.textContent = sub;
  el.append(b, s);
}

function hideInfo() {
  $("info").classList.add("hidden");
  $("info-list").textContent = "";
  $("keynote").textContent = "";
}

function showInfo(item, state) {
  const list = $("info-list");
  list.textContent = "";
  let rows = 0;
  for (const [field, label] of DISPLAY_FIELDS) {
    const value = item[field];
    if (!value) continue;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value; // never innerHTML
    list.append(dt, dd);
    rows++;
  }
  if (!rows) {
    $("info").classList.add("hidden");
    return;
  }
  const key = PUBLIC_KEYS[item.kid];
  const parts = ["Signed with " + (key ? key.label : item.kid) + " (ECDSA P-256)"];
  if (item.retiredKey) {
    parts.push("⚠ That key has been retired — treat this item with extra care.");
  }
  if (state === "authentic") {
    parts.push(
      revocationAvailable
        ? "Checked against the revocation list."
        : "Revocation list unavailable."
    );
  }
  $("keynote").textContent = parts.join(" · ");
  $("info").classList.remove("hidden");
}

let runToken = 0;

async function verifyAndRender(raw) {
  const myRun = ++runToken;
  hideInfo();
  setStatus("busy", "CHECKING…", "Verifying the signature on this code.");

  await revocationReady.catch(() => {});
  if (myRun !== runToken) return; // a newer check started; drop this one

  let result;
  try {
    result = await verifyToken(raw, { revoked });
  } catch (err) {
    // Nothing should reach here, but a stuck "CHECKING…" would be worse than
    // an honest failure, so never leave the visitor without an answer.
    if (myRun !== runToken) return;
    setStatus(
      "warn",
      "⚠ CANNOT CHECK",
      "The check could not be completed on this device. Open the official site over https in an up-to-date browser."
    );
    hideInfo();
    return { state: "unsupported", detail: String(err) };
  }
  if (myRun !== runToken) return;

  const ui = STATE_UI[result.state] || STATE_UI.forged;
  setStatus(ui.cls, ui.label, result.detail);
  if (result.item) showInfo(result.item, result.state);
  else hideInfo();
  return result;
}

// --- input sources ------------------------------------------

// 1. The NFC tap: the code rides in the URL and is checked on load,
//    with no button press. Also supports ?c= for tools that drop fragments.
function codeFromLocation() {
  const fromHash = location.hash ? location.hash.slice(1) : "";
  if (fromHash) return fromHash;
  const params = new URLSearchParams(location.search);
  return params.get("c") || "";
}

function checkLocation() {
  const code = codeFromLocation();
  if (code) verifyAndRender(code);
}

// 2. Pasted by hand.
$("verify-btn").addEventListener("click", () => {
  const raw = $("code-input").value;
  if (!raw.trim()) {
    setStatus("wait", "TAP A TAG", "Paste a Makozumi code above, then press Verify.");
    hideInfo();
    return;
  }
  verifyAndRender(raw);
});

// 3. Web NFC scan (Android Chrome).
$("scan-btn").addEventListener("click", async () => {
  const btn = $("scan-btn");
  if (!("NDEFReader" in window)) {
    $("scan-hint").textContent =
      "This browser cannot scan NFC directly. Tap the tag with your phone instead — it opens this page and checks automatically.";
    return;
  }
  try {
    const reader = new NDEFReader();
    await reader.scan();
    btn.disabled = true;
    btn.textContent = "Hold the tag to your phone…";
    reader.onreading = (event) => {
      for (const record of event.message.records) {
        if (record.recordType !== "url" && record.recordType !== "text") continue;
        let text;
        try {
          text = new TextDecoder().decode(record.data);
        } catch {
          continue;
        }
        if (extractToken(text)) {
          verifyAndRender(text);
          btn.disabled = false;
          btn.textContent = "Scan a tag with this phone";
          return;
        }
      }
      setStatus("bad", "✕ NOT A MAKOZUMI CODE", "That tag does not carry a Makozumi code.");
      hideInfo();
      btn.disabled = false;
      btn.textContent = "Scan a tag with this phone";
    };
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "Scan a tag with this phone";
    $("scan-hint").textContent = "NFC scan could not start: " + err.message;
  }
});

// Tapping a second tag while the page is open re-checks it.
window.addEventListener("hashchange", checkLocation);

checkLocation();

// Expose for the automated test suite only (harmless: everything here is public).
window.__makozumi = { verifyAndRender };
