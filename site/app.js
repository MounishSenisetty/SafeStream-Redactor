// SafeStream Redactor demo page. All detection runs in engine.js (a Web Worker
// running the real Python package); this file only collects input and draws results.
// Text from the user is always inserted with textContent / DOM nodes, never as HTML,
// and never leaves the page: not in a request, not in the address bar.

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children.filter((c) => c !== null && c !== undefined && c !== false));
  return node;
};
const MAX_BYTES = 1024 * 1024; // the demo's cap; the CLI streams files of any size
const MARK_LIMIT = 3000; // findings highlighted in the views; all are redacted
const ROW_LIMIT = 500; // findings rows drawn before "Show all"
const BACKDROP_LIMIT = 200_000; // characters highlighted behind the input box
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

// The README's "What it detects" table, as groups for the type picker
const PICKER = [
  { kind: "PII", groups: [
    ["Personal data", ["email", "phone", "credit_card", "ssn", "ipv4", "ipv6", "mac_address", "address", "dob", "username"]],
    ["Labelled identifiers", ["id_number"]],
  ] },
  { kind: "Secrets", groups: [
    ["Cloud and service credentials", ["aws_key", "aws_secret", "aws_account_id", "github_token", "slack_token", "slack_webhook",
      "stripe_key", "google_api_key", "sendgrid_key", "twilio_key", "npm_token", "openai_key", "anthropic_key", "vendor_token"]],
    ["Other secrets", ["api_key", "jwt", "private_key", "url_credentials", "password_hash", "secret"]],
  ] },
  { kind: "Opt-in", note: "Run only when their tier is on: Regional IDs, Dates, or the prose profile (URLs and prose fields).", groups: [
    ["Regional IDs", ["iban", "crypto_address", "uk_nino", "nhs_number", "in_aadhaar", "in_pan"]],
    ["Dates, URLs and prose fields", ["date", "url", "sex", "title", "nrp", "money"]],
  ] },
];
// highlight colours: one per family, each paired with a short tag and an underline style
const FAMILIES = {
  personal: { label: "Personal data", tag: "PII" },
  ids: { label: "Identifiers", tag: "ID" },
  cloud: { label: "Credentials", tag: "KEY" },
  secrets: { label: "Other secrets", tag: "SEC" },
  names: { label: "Names", tag: "NAME" },
  optin: { label: "Dates, URLs, prose", tag: "OPT" },
  custom: { label: "Your rules", tag: "YOU" },
};
const FAMILY_OF = {};
PICKER[0].groups[0][1].forEach((t) => { FAMILY_OF[t] = "personal"; });
["id_number", ...PICKER[2].groups[0][1]].forEach((t) => { FAMILY_OF[t] = "ids"; });
PICKER[1].groups[0][1].forEach((t) => { FAMILY_OF[t] = "cloud"; });
PICKER[1].groups[1][1].forEach((t) => { FAMILY_OF[t] = "secrets"; });
PICKER[2].groups[1][1].forEach((t) => { FAMILY_OF[t] = "optin"; });
["person", "org", "loc"].forEach((t) => { FAMILY_OF[t] = "names"; });
FAMILY_OF.custom = "custom";
const familyOf = (type) => FAMILY_OF[type] || "secrets";

// from policy.py, operators.py and docs/CLI.md
const MODES = {
  replace: { label: "Replace", what: "Swap each finding for fixed text such as [REDACTED].",
    when: "Sharing logs or documents where nobody needs the values." },
  mask: { label: "Mask", what: "Hide all but the last few characters, e.g. ***************1111. Never more than half of a value stays visible.",
    when: "Support and billing screens where the last digits help find a record." },
  pseudonymize: { label: "Pseudonymize", what: "A keyed token such as <EMAIL_75e802c7c314f5a2>. Equal values get equal tokens.",
    when: "Analytics and debugging across files: count and join on a value without seeing it. Anyone with the key can test guesses, so keep it secret." },
  hash: { label: "Hash", what: "A salted digest such as <EMAIL:H:1918f15f636eab43>.",
    when: "Stable tokens when you cannot manage a key. Add a secret salt: an unsalted hash of an SSN can be guessed." },
  fictionalize: { label: "Fictionalize", what: "Swap in a realistic but fake value from reserved ranges: example.com, 555-01xx phone numbers, TEST-NET IP addresses.",
    when: "Test fixtures and demos that must still look like real data." },
  encrypt: { label: "Encrypt", what: "Reversible AES-256-GCM tokens; safestream deanonymize restores the originals with the key.",
    when: "When authorised people must be able to recover the original later." },
};

// short explanations for technical terms (data-term="key" in the page)
const TERMS = {
  pii: "Personally identifiable information: data that identifies a person, such as an email address, phone number or SSN.",
  secret: "Credentials that grant access: API keys, tokens, private keys, passwords in URLs.",
  wasm: "WebAssembly runs compiled code in the browser. Here it runs CPython (via Pyodide) and the unmodified Python package.",
  csp: "Content-Security-Policy: a rule the browser enforces. This page's policy forbids connections to any other site.",
  stream: "The engine reads text through a fixed-size window, so a 100 GB file uses the same memory as a 1 KB one.",
  determinism: "Equal input and settings always give byte-identical output, however the text is chunked or split across cores.",
  severity: "A fixed level per entity type: critical (live credentials), high, medium, low. It never depends on the matched text.",
  confidence: "How sure the detector is, from 0 to 1. Findings below the minimum confidence are dropped.",
  entropy: "Randomness. Long, random-looking strings are flagged as secrets even without a known format.",
  hmac: "A keyed hash. The same value and key always give the same token; without the key the token cannot be checked.",
  chunk: "How many characters the engine reads per step.",
  overlap: "Text carried from one pass to the next, so an entity cut by a chunk boundary is still seen whole. 8 KiB by default.",
  policy: "A TOML file with every setting. Use it with safestream redact … --config policy.toml, serve and mcp-serve.",
  mcp: "Model Context Protocol: how AI agents call tools. The server speaks it over stdio.",
  jsonrpc: "The message format MCP uses: {jsonrpc, id, method, params} in, {result} or {error} out.",
  sarif: "Static Analysis Results Interchange Format: a JSON report GitHub code scanning can show as alerts.",
  exit: "The number a command returns to the shell. CI systems fail a step when it is not 0.",
  tracemalloc: "Python's own memory tracer. It reports the peak memory Python code allocated during the run.",
};

// ---------------------------------------------------------------- small helpers
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};
const fmtBytes = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(n >= 10485760 ? 0 : 1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(0)} KiB` : `${n} B`);
const shq = (s) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
// letter shortcuts stay off while a field takes text (checkboxes and radios do not)
const isTyping = (t) => t && (t.isContentEditable || /^(TEXTAREA|SELECT)$/.test(t.tagName)
  || (t.tagName === "INPUT" && !/^(checkbox|radio|range|button|submit|file)$/.test(t.type)));
const lines = (block) => [...new Set(block.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")))];
const randomKey = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
}
async function copyText(text, what = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    toast(what);
  } catch {
    toast("Copy is blocked in this browser. Select the text and copy it instead.");
  }
}
function download(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = el("a", { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------------------------------------------------------------- theme
const savedTheme = store.get("theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  store.set("theme", next);
}
$("theme").addEventListener("click", toggleTheme);

// ---------------------------------------------------------------- tooltips
let tipFor = null;
function showTip(target) {
  const tip = $("tooltip");
  tip.textContent = TERMS[target.dataset.term];
  tip.hidden = false;
  const r = target.getBoundingClientRect();
  const w = Math.min(300, innerWidth - 24);
  tip.style.maxWidth = `${w}px`;
  const left = Math.max(12, Math.min(r.left + scrollX, scrollX + innerWidth - w - 12));
  tip.style.left = `${left}px`;
  tip.style.top = `${r.bottom + scrollY + 6}px`;
  tipFor = target;
}
function hideTip() { $("tooltip").hidden = true; tipFor = null; }
function initTerms(root = document) {
  root.querySelectorAll("[data-term]").forEach((t) => {
    if (t.dataset.termReady || !TERMS[t.dataset.term]) return;
    t.dataset.termReady = "1";
    t.classList.add("term");
    if (!t.closest("button, label, a")) t.tabIndex = 0;
    t.setAttribute("aria-describedby", "tooltip");
    t.addEventListener("mouseenter", () => showTip(t));
    t.addEventListener("mouseleave", hideTip);
    t.addEventListener("focus", () => showTip(t));
    t.addEventListener("blur", hideTip);
  });
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && tipFor) hideTip(); });

// ---------------------------------------------------------------- engine
// The worker is started from a blob: URL so it inherits this page's CSP.
let nextId = 1;
const pending = new Map();
let worker;
let info = null;
const net = { page: 0, worker: 0, offsite: 0, pageBaseline: 0 };

async function startEngine() {
  const base = new URL(".", location.href).href;
  const source = await (await fetch("engine.js")).text();
  worker = new Worker(URL.createObjectURL(new Blob([source], { type: "text/javascript" })), { type: "module" });
  worker.onmessage = ({ data }) => {
    if (data.progress) return bootProgress(data.progress);
    const p = pending.get(data.id);
    if (data.step) return p && p.onStep && p.onStep(data.step);
    pending.delete(data.id);
    if (typeof data.net === "number") { net.worker = data.net; net.offsite = Math.max(net.offsite, data.offsite || 0); renderNet(); }
    if (p) data.ok ? p.resolve(data.result) : p.reject(new Error(data.error));
  };
  worker.onerror = (e) => bootFailed(e.message || "the engine could not start");
  return call("init", { base });
}
function call(op, args, onStep) {
  return new Promise((resolve, reject) => {
    if (!worker) return reject(new Error("The engine is still starting."));
    const id = nextId++;
    pending.set(id, { resolve, reject, onStep });
    worker.postMessage({ id, op, args });
  });
}

const STAGES = ["Loading the Python runtime", "Loading SafeStream", "Starting the engine"];
function bootProgress(stage) {
  $("boot-text").textContent = stage + "…";
  const pct = ((STAGES.indexOf(stage) + 1) / (STAGES.length + 1)) * 100;
  $("boot-fill").style.width = `${pct}%`;
  $("boot-progress").setAttribute("aria-valuenow", String(Math.round(pct)));
}
function bootFailed(msg) {
  $("boot").classList.add("failed");
  $("boot").hidden = false;
  $("boot-text").textContent = `The engine could not start: ${msg}. Reload the page to try again. A browser with WebAssembly (any current Chrome, Edge, Firefox or Safari) is needed.`;
  $("boot-note").textContent = "";
}

// network-request counter: the browser's resource timing for the page, plus the worker's own
function renderNet() {
  const total = net.page + net.worker;
  $("net-count").textContent = total;
  $("net-count-2").textContent = total;
  $("offsite-count").textContent = net.offsite;
}
function watchPageRequests() {
  const pageOrigin = location.origin;
  performance.setResourceTimingBufferSize(10000);
  const offsite = () => performance.getEntriesByType("resource").filter((e) => new URL(e.name).origin !== pageOrigin).length;
  net.pageBaseline = performance.getEntriesByType("resource").length;
  const update = () => {
    net.page = performance.getEntriesByType("resource").length - net.pageBaseline;
    net.offsite = Math.max(net.offsite, offsite());
    renderNet();
  };
  try { new PerformanceObserver(update).observe({ type: "resource" }); } catch { /* old browser */ }
  update();
}

// ---------------------------------------------------------------- settings: a policy file
// `policy` is the policy.toml dictionary, defaults omitted. The controls and the TOML
// editor are two views of it; keys with no control (from a pasted file) are kept.
const form = $("settings");
let policy = {};
let replacements = {}; // per-type replacement text
let typeBoxes = [];

const DEFAULTS = { min_confidence: 0.5, use_entropy: true, profile: "default", mode: "replace", replacement: "[REDACTED]",
  mask_keep_last: 4, mask_char: "*", pseudonym_length: 16, hash_algorithm: "sha256" };

function buildModes() {
  const box = $("modes");
  const current = form.elements.mode ? form.elements.mode.value : "replace";
  box.replaceChildren(...Object.entries(MODES).map(([value, m]) => {
    const disabled = value === "encrypt" && !(info && info.crypto);
    const input = el("input", { type: "radio", name: "mode", value, checked: value === (current || "replace"), disabled });
    return el("label", { className: "mode" + (disabled ? " off" : "") }, input,
      el("span", { className: "mode-name" }, m.label, disabled ? el("small", {}, " local only") : null));
  }));
}

function buildTypeList(types) {
  const known = new Set(types);
  const placed = new Set();
  const sections = PICKER.map(({ kind, groups, note }) => {
    const groupEls = groups.map(([label, list]) => {
      const present = list.filter((t) => known.has(t));
      present.forEach((t) => placed.add(t));
      return typeGroup(label, present);
    });
    const allBtn = el("button", { type: "button", className: "link", textContent: "all" });
    const noneBtn = el("button", { type: "button", className: "link", textContent: "none" });
    allBtn.dataset.kind = noneBtn.dataset.kind = kind;
    allBtn.dataset.set = "all";
    noneBtn.dataset.set = "none";
    allBtn.setAttribute("aria-label", `Select all ${kind}`);
    noneBtn.setAttribute("aria-label", `Select no ${kind}`);
    const sec = el("details", { className: "types-sec", open: kind !== "Opt-in" },
      el("summary", {}, el("span", { className: "kind" }, kind), el("span", { className: "sec-actions" }, allBtn, " · ", noneBtn)),
      note ? el("p", { className: "muted small" }, note) : null, ...groupEls);
    sec.dataset.kind = kind;
    return sec;
  });
  const rest = types.filter((t) => !placed.has(t));
  if (rest.length) sections.push(el("details", { className: "types-sec" }, el("summary", {}, "Other"), typeGroup("Other", rest)));
  $("types-list").replaceChildren(...sections);
  typeBoxes = [...$("types-list").querySelectorAll("input")];
  // per-type replacement picker: every type the engine knows
  $("repl-type").replaceChildren(...info.all_types.map((t) => new Option(t, t)));
}
function typeGroup(label, list) {
  return el("div", { className: "types-group" }, el("p", { className: "group-label" }, label),
    ...list.map((t) => {
      const box = el("input", { type: "checkbox", value: t, checked: true });
      return el("label", {}, box, el("span", { className: "sw", ariaHidden: "true" }), t,
        sevDot(info.severity[t]));
    }));
}
function sevDot(sev) {
  const d = el("span", { className: "sev-dot", title: `severity: ${sev}` }, el("span", { className: "sr-only" }, ` (${sev})`));
  d.dataset.sev = sev;
  return d;
}
function swatch(type) {
  const s = el("span", { className: "sw" });
  s.dataset.fam = familyOf(type);
  return s;
}

function setOrDelete(obj, key, value, dflt) {
  if (value === dflt || value === "" || value === undefined || (Array.isArray(value) && !value.length)) delete obj[key];
  else obj[key] = value;
}

// controls -> policy (keys without a control are left as they are)
function controlsToPolicy() {
  const f = form.elements;
  const p = structuredClone(policy);
  const det = (p.detection ||= {});
  const red = (p.redaction ||= {});
  const cus = (p.custom ||= {});
  const profile = f.profile.value;
  setOrDelete(det, "min_confidence", Number(f.min_confidence.value), DEFAULTS.min_confidence);
  setOrDelete(det, "use_entropy", f.use_entropy.checked, true);
  setOrDelete(det, "use_gazetteer", f.use_names.checked, false);
  setOrDelete(det, "use_ensemble", f.use_names.checked, false);
  setOrDelete(det, "use_regional", f.use_regional.checked, false);
  setOrDelete(det, "use_dates", f.use_dates.checked, profile === "prose");
  setOrDelete(det, "use_log_usernames", f.use_log_usernames.checked, false);
  setOrDelete(det, "profile", profile, "default");
  const chosen = typeBoxes.filter((b) => b.checked).map((b) => b.value);
  if (chosen.length === typeBoxes.length) delete det.types;
  else det.types = chosen;

  const mode = f.mode.value;
  for (const k of ["mode", "replacement", "mask_keep_last", "mask_char", "hmac_key", "pseudonym_length", "hash_algorithm", "hash_salt", "encrypt_key"]) delete red[k];
  setOrDelete(red, "mode", mode, "replace");
  if (mode === "replace") setOrDelete(red, "replacement", f.replacement.value, DEFAULTS.replacement);
  if (mode === "mask") {
    setOrDelete(red, "mask_keep_last", Math.max(0, Math.trunc(Number(f.mask_keep_last.value) || 0)), DEFAULTS.mask_keep_last);
    setOrDelete(red, "mask_char", f.mask_char.value || "*", DEFAULTS.mask_char);
  }
  if (mode === "pseudonymize" || mode === "fictionalize") red.hmac_key = f.hmac_key.value;
  if (mode === "pseudonymize") setOrDelete(red, "pseudonym_length", Math.trunc(Number(f.pseudonym_length.value) || 16), DEFAULTS.pseudonym_length);
  if (mode === "hash") {
    setOrDelete(red, "hash_algorithm", f.hash_algorithm.value, DEFAULTS.hash_algorithm);
    setOrDelete(red, "hash_salt", f.hash_salt.value, "");
  }
  if (mode === "encrypt") red.encrypt_key = encryptKey;
  if (Object.keys(replacements).length) red.replacements = { ...replacements };
  else delete red.replacements;
  setOrDelete(cus, "words", lines(f.custom_words.value), undefined);
  setOrDelete(cus, "patterns", lines(f.custom_patterns.value), undefined);
  for (const k of Object.keys(p)) if (p[k] && typeof p[k] === "object" && !Object.keys(p[k]).length) delete p[k];
  policy = p;
}
const encryptKey = randomKey() + randomKey();

// policy -> controls
function policyToControls() {
  const f = form.elements;
  const det = policy.detection || {};
  const red = policy.redaction || {};
  const cus = policy.custom || {};
  f.min_confidence.value = det.min_confidence ?? DEFAULTS.min_confidence;
  f.use_entropy.checked = det.use_entropy ?? true;
  f.use_names.checked = !!(det.use_gazetteer || det.use_ensemble);
  f.use_regional.checked = !!det.use_regional;
  f.profile.value = det.profile === "prose" ? "prose" : "default";
  f.use_dates.checked = det.use_dates ?? det.profile === "prose";
  f.use_log_usernames.checked = !!det.use_log_usernames;
  const types = det.types ? new Set(det.types) : null;
  typeBoxes.forEach((b) => { b.checked = !types || types.has(b.value); });
  const mode = MODES[red.mode] ? red.mode : "replace";
  const radio = form.querySelector(`input[name="mode"][value="${mode}"]`);
  if (radio && !radio.disabled) radio.checked = true;
  f.replacement.value = red.replacement ?? DEFAULTS.replacement;
  f.mask_keep_last.value = red.mask_keep_last ?? DEFAULTS.mask_keep_last;
  f.mask_char.value = red.mask_char ?? DEFAULTS.mask_char;
  if (red.hmac_key) f.hmac_key.value = red.hmac_key;
  f.pseudonym_length.value = red.pseudonym_length ?? DEFAULTS.pseudonym_length;
  f.hash_algorithm.value = red.hash_algorithm ?? DEFAULTS.hash_algorithm;
  f.hash_salt.value = red.hash_salt ?? "";
  replacements = { ...(red.replacements || {}) };
  f.custom_words.value = (cus.words || []).join("\n");
  f.custom_patterns.value = (cus.patterns || []).join("\n");
  renderReplacements();
  showModeFields();
}

function showModeFields() {
  const mode = form.elements.mode.value;
  form.querySelectorAll("[data-for]").forEach((n) => { n.hidden = !n.dataset.for.split(" ").includes(mode); });
  const m = MODES[mode];
  $("mode-help").replaceChildren(el("span", {}, m.what), el("span", { className: "when" }, el("strong", {}, "When: "), m.when));
  $("conf-out").textContent = Number(form.elements.min_confidence.value).toFixed(2);
  const n = typeBoxes.filter((b) => b.checked).length;
  $("types-count").textContent = typeBoxes.length ? (n === typeBoxes.length ? "(all)" : `(${n} of ${typeBoxes.length})`) : "";
  $("rail-summary").textContent = `${m.label}${n === typeBoxes.length ? "" : `, ${n} types`}`;
}

function renderReplacements() {
  $("repl-list").replaceChildren(...Object.entries(replacements).map(([type, text]) => {
    const rm = el("button", { type: "button", className: "link", textContent: "remove" });
    rm.setAttribute("aria-label", `Remove the replacement for ${type}`);
    rm.addEventListener("click", () => { delete replacements[type]; renderReplacements(); settingsChanged(); });
    return el("li", {}, el("code", {}, type), " → ", el("code", {}, text), " ", rm);
  }));
}
$("repl-add").addEventListener("click", () => {
  const type = $("repl-type").value;
  const text = $("repl-text").value;
  if (!type) return;
  replacements[type] = text;
  $("repl-text").value = "";
  renderReplacements();
  settingsChanged();
});
$("repl-text").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("repl-add").click(); } });
$("new-key").addEventListener("click", () => { form.elements.hmac_key.value = randomKey(); settingsChanged(); });

form.addEventListener("click", (e) => {
  const t = e.target.closest("[data-types], [data-set]");
  if (!t) return;
  e.preventDefault();
  if (t.dataset.types) typeBoxes.forEach((b) => { b.checked = t.dataset.types === "all"; });
  else {
    const sec = $("types-list").querySelector(`.types-sec[data-kind="${t.dataset.kind}"]`);
    sec.querySelectorAll("input").forEach((b) => { b.checked = t.dataset.set === "all"; });
  }
  settingsChanged();
});
form.addEventListener("input", (e) => { if (!e.target.closest(".repl-add")) settingsChanged(); });
form.addEventListener("submit", (e) => e.preventDefault());

// the engine caches one redactor per distinct settings string
const settingsKey = () => JSON.stringify(policy);

let settingsTimer;
let controlsVersion = 0;
function settingsChanged({ fromToml = false } = {}) {
  if (!fromToml) { controlsToPolicy(); controlsVersion++; }
  showModeFields();
  if (!fromToml && document.activeElement !== $("policy-text")) renderToml();
  renderSnippets();
  writeHash();
  clearTimeout(settingsTimer);
  settingsTimer = setTimeout(() => {
    runAnalyze();
    if (!$("panel-inspector").hidden) loadTrace();
  }, 250);
}

function settingsError(err) {
  const box = $("settings-error");
  box.hidden = !err;
  box.textContent = err ? `The engine rejected these settings: ${err.message}` : "";
}

// ---------------------------------------------------------------- policy.toml (both ways)
const SCHEMA_ORDER = {
  detection: ["types", "min_confidence", "use_entropy", "use_gazetteer", "use_ensemble", "use_regional", "use_dates", "use_log_usernames", "profile"],
  redaction: ["mode", "replacement", "mask_keep_last", "mask_char", "hmac_key", "pseudonym_length", "hash_algorithm", "hash_salt", "encrypt_key"],
  custom: ["words", "patterns"],
  streaming: ["chunk_size", "overlap"],
};
function tomlString(s) {
  // a literal string keeps regex backslashes readable; a basic string escapes the rest
  if (!/['\n\r\u0000-\u001f\u007f]/.test(s)) return `'${s}'`;
  return JSON.stringify(s).replace(/\u007f/g, "\\u007F");
}
function tomlValue(v) {
  if (typeof v === "boolean") return String(v);
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(v);
  if (typeof v === "string") return /\\/.test(v) ? tomlString(v) : JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(tomlValue).join(", ")}]`;
  return JSON.stringify(String(v));
}
function toToml(p) {
  const out = ["# policy.toml, written by the SafeStream demo", "# safestream redact app.log -o clean.log --config policy.toml"];
  const sections = [...new Set([...Object.keys(SCHEMA_ORDER), ...Object.keys(p)])];
  let wrote = false;
  for (const sec of sections) {
    const table = p[sec];
    if (!table || typeof table !== "object") continue;
    const order = SCHEMA_ORDER[sec] || [];
    const keys = Object.keys(table).filter((k) => k !== "replacements").sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
    if (keys.length) {
      out.push("", `[${sec}]`);
      for (const k of keys) {
        const comment = k === "hmac_key" || k === "encrypt_key" || k === "hash_salt" ? "   # a random key for this tab: use your own secret" : "";
        out.push(`${k} = ${tomlValue(table[k])}${comment}`);
      }
      wrote = true;
    }
    if (sec === "redaction" && table.replacements && Object.keys(table.replacements).length) {
      out.push("", "[redaction.replacements]");
      for (const [t, r] of Object.entries(table.replacements)) out.push(`${t} = ${tomlValue(r)}`);
      wrote = true;
    }
  }
  if (!wrote) out.push("", "# every setting is at its default: change one on the left, or add keys here");
  return out.join("\n") + "\n";
}
let tomlText = "";
function renderToml() {
  tomlText = toToml(policy);
  $("policy-text").value = tomlText;
  policyStatus("ok", "Matches the settings on the left.");
}
function policyStatus(kind, msg) {
  const s = $("policy-status");
  s.className = `status-line ${kind}`;
  s.textContent = msg;
}
let tomlTimer;
$("policy-text").addEventListener("input", () => {
  clearTimeout(tomlTimer);
  policyStatus("", "Checking…");
  tomlTimer = setTimeout(applyToml, 450);
});
async function applyToml() {
  if (!info) return;
  const text = $("policy-text").value;
  const version = controlsVersion;
  try {
    const parsed = await call("checkPolicy", { toml: text });
    // the file or a control changed while it was checked: the newer edit wins
    if (text !== $("policy-text").value || version !== controlsVersion) return;
    policy = parsed;
    tomlText = text;
    policyToControls();
    settingsChanged({ fromToml: true });
    policyStatus("ok", "Valid. Applied to the page.");
  } catch (err) {
    policyStatus("err", err.message);
  }
}
$("policy-text").addEventListener("blur", () => { if ($("policy-status").classList.contains("ok")) renderToml(); });
$("policy-download").addEventListener("click", () => download($("policy-text").value, "policy.toml"));
$("policy-starter").addEventListener("click", () => {
  $("policy-text").value = info.starter_config;
  $("policy-text").focus();
  applyToml();
});

// ---------------------------------------------------------------- samples
const SAMPLES = {
  log: {
    label: "Service log",
    hint: "A service log with personal data and leaked credentials.",
    text: `2026-11-02T09:14:07Z INFO  auth     login ok user=maria.garcia@corpmail.com ip=10.20.30.40
2026-11-02T09:14:09Z WARN  billing  payment declined card=4111 1111 1111 1111 ssn=123-45-6789
2026-11-02T09:14:11Z INFO  api      GET /v1/orders client_ip=2001:db8::8a2e:370:7334
2026-11-02T09:15:31Z DEBUG deploy   aws_key=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghijklmnopqrstuvwxyz
2026-11-02T09:15:32Z DEBUG notify   callback phone=+1 415 555 0132
2026-11-02T09:16:02Z ERROR payments stripe key sk_live_1234567890abcdefghijklmnop rejected
2026-11-02T09:16:40Z INFO  session  jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
2026-11-02T09:17:05Z INFO  health   ok in 12 ms
`,
  },
  csv: {
    label: "Customers CSV",
    hint: "A customer export. Turn on Name heuristics to catch the names column too.",
    file: "customers.csv",
    text: `customer_id,name,email,phone,card_number,ssn,signup_ip,plan
1001,Maria Garcia,maria.garcia@corpmail.com,+1 415 555 0132,4111 1111 1111 1111,123-45-6789,10.20.30.40,pro
1002,Daniel Okafor,daniel.okafor@corpmail.com,(415) 555-0172,5555 5555 5555 4444,512-44-8372,10.20.30.41,free
1003,Li Wei,li.wei@corpmail.com,+1 212 555 0198,4242 4242 4242 4242,078-05-1120,2001:db8::1,team
1004,Ana Novak,ana.novak@corpmail.com,+1 646 555 0143,3782 822463 10005,219-09-9999,192.168.40.12,pro
`,
  },
  json: {
    label: "JSON API payload",
    hint: "A logged API request: a bearer token, a webhook URL, and the customer's details.",
    file: "request.json",
    text: `{
  "request_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
  "endpoint": "POST /v2/payments",
  "headers": {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "X-Forwarded-For": "203.0.113.42"
  },
  "body": {
    "customer": {
      "email": "maria.garcia@corpmail.com",
      "phone": "+1 415 555 0132",
      "date_of_birth": "1987-03-14"
    },
    "card": { "number": "4111 1111 1111 1111", "exp": "12/29" },
    "webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
  },
  "status": 402
}
`,
  },
  env: {
    label: ".env secrets",
    hint: "Credentials, including a secret with no known format (found by entropy).",
    file: ".env",
    text: `# .env (production)
DATABASE_URL=postgres://orders_admin:Tr0ub4dor-and-3@db.internal.corp:5432/orders
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_1234567890abcdefghijklmnop
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
SESSION_SECRET=9f2c4e7a1b8d3f6e0a5c2b9d7e4f1a3c
LOG_LEVEL=info
FEATURE_FLAGS=checkout_v2,search_v3
`,
  },
  chat: {
    label: "Support chat",
    hint: "Prose: a customer pastes personal data into a support chat.",
    file: "chat.txt",
    text: `[09:41] Agent (Priya): Hi, thanks for contacting support! How can I help?
[09:42] Customer: Hi, I was charged twice for order 48213. My email is daniel.okafor@corpmail.com
[09:42] Agent (Priya): Sorry about that. Can you confirm the phone number on the account?
[09:43] Customer: (415) 555-0172. The card was 4242 4242 4242 4242 if that helps
[09:43] Customer: and my SSN is 512-44-8372 in case you need to verify me
[09:44] Agent (Priya): Please never send your SSN or full card number in chat. I have flagged this message.
[09:45] Customer: ok sorry! Shipping address is 742 Evergreen Terrace, Springfield, OR 97403
[09:46] Agent (Priya): Thanks. The duplicate charge is refunded; you'll see it in 3-5 business days.
`,
  },
  code: {
    label: "Source code",
    hint: "Keys and a database password committed in source code: what the CI gate is for.",
    file: "client.py",
    text: `# billing/client.py
import os

import boto3
import requests

# TODO: move these to the secret manager before release!
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
DATABASE_URL = "postgres://billing:Tr0ub4dor-and-3@db.internal.corp:5432/billing"

API_VERSION = "2026-11-01"
TIMEOUT_SECONDS = 30


def s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


def notify(message: str) -> None:
    requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=TIMEOUT_SECONDS)
`,
  },
  clean: {
    label: "Look-alikes (clean)",
    hint: "Commit hashes, UUIDs, digests and version numbers look like secrets or IP addresses, but are not. Nothing here should be flagged.",
    file: "RELEASE_NOTES.md",
    text: `Release notes, build 4.2.11 (commit 9fceb02d0ae598e95dc970b74767f19372d61af8)

- request_id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 is now logged on every retry
- installer sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- version 10.20.30 replaces 10.20.29 (ticket PLAT-4412, order 48213)
- the API listens on port 8080; retries back off 250 ms, 500 ms, then 1 s
- container image digest sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
- the cache key is user_profile_v2_settings_cache; it expires after 86400 seconds
- theme colour #3b4fd8, font-size 14px, line-height 1.5; build took 3m 12s
- published 2026-11-02 to /opt/app/releases/4.2.11/
`,
  },
};
let currentSample = "log";
let fileName = "app.log";
function buildSamples() {
  const box = $("samples");
  for (const [key, s] of Object.entries(SAMPLES)) {
    const b = el("button", { type: "button", className: "chip-btn", textContent: s.label });
    b.dataset.sample = key;
    b.setAttribute("aria-pressed", "false");
    box.append(b);
  }
  box.addEventListener("click", (e) => {
    const b = e.target.closest("[data-sample]");
    if (b) loadSample(b.dataset.sample);
  });
}
function markSample(key) {
  currentSample = key;
  $("samples").querySelectorAll("[data-sample]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.sample === key)));
}
function loadSample(key) {
  const s = SAMPLES[key];
  setInput(s.text);
  $("sample-hint").textContent = s.hint;
  fileName = s.file || "app.log";
  markSample(key);
  writeHash();
  runAnalyze();
}

// ---------------------------------------------------------------- input: type, paste, drop, open
const input = $("input");
function setInput(text) {
  input.value = text;
  input.scrollTop = 0;
  paintBackdrop(null);
  updateSize();
}
function updateSize() {
  const bytes = new TextEncoder().encode(input.value).length;
  $("input-size").textContent = `${bytes.toLocaleString()} bytes${bytes > MAX_BYTES ? " (over the 1 MiB limit of this demo)" : ""}`;
  return bytes;
}
async function readFile(file) {
  if (!file) return;
  if (file.size > MAX_BYTES) {
    toast(`${file.name} is ${fmtBytes(file.size)}. The demo takes up to 1 MiB; the CLI streams files of any size.`);
    return;
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.subarray(0, 8192).includes(0)) {
    toast(`${file.name} looks like a binary file. Open a text file instead.`);
    return;
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    text = new TextDecoder("utf-8").decode(bytes);
    toast(`${file.name} has bytes that are not valid UTF-8; they were replaced with � and not scanned.`);
  }
  setInput(text);
  $("sample-hint").textContent = `Scanning ${file.name}, in this tab only.`;
  fileName = file.name;
  markSample(null);
  writeHash();
  runAnalyze();
}
$("upload").addEventListener("change", (e) => { readFile(e.target.files[0]); e.target.value = ""; });
$("clear-input").addEventListener("click", () => {
  setInput("");
  markSample(null);
  $("sample-hint").textContent = "";
  writeHash();
  runAnalyze();
  input.focus();
});
const editor = $("editor");
let dragDepth = 0;
editor.addEventListener("dragenter", (e) => { if ([...e.dataTransfer.types].includes("Files")) { dragDepth++; $("drop").hidden = false; } });
editor.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; $("drop").hidden = true; } });
editor.addEventListener("dragover", (e) => { if ([...e.dataTransfer.types].includes("Files")) e.preventDefault(); });
editor.addEventListener("drop", (e) => {
  if (!e.dataTransfer.files.length) return;
  e.preventDefault();
  dragDepth = 0;
  $("drop").hidden = true;
  readFile(e.dataTransfer.files[0]);
});
input.addEventListener("input", () => {
  if (currentSample) { markSample(null); writeHash(); }
  paintBackdrop(null);
  const bytes = updateSize();
  scheduleAnalyze(bytes > 200_000 ? 900 : bytes > 50_000 ? 500 : 250);
});
input.addEventListener("scroll", () => {
  $("backdrop").scrollTop = input.scrollTop;
  $("backdrop").scrollLeft = input.scrollLeft;
});

// ---------------------------------------------------------------- playground run
let last = null; // {text, result}
let analyzeTimer;
let running = false;
let dirty = false;
function scheduleAnalyze(delay) {
  clearTimeout(analyzeTimer);
  analyzeTimer = setTimeout(runAnalyze, delay);
}
async function runAnalyze() {
  clearTimeout(analyzeTimer);
  if (!info) return;
  if (running) { dirty = true; return; }
  const text = input.value;
  if (updateSize() > MAX_BYTES) {
    toast("The demo takes up to 1 MiB of text. Use the CLI for larger files.");
    return;
  }
  running = true;
  dirty = false;
  setBusy(true);
  try {
    const result = await call("analyze", { text, settings: settingsKey() });
    settingsError(null);
    if (text === input.value) {
      last = { text, result };
      renderPlayground();
    } else dirty = true;
  } catch (err) {
    settingsError(err);
  } finally {
    running = false;
    setBusy(false);
    if (dirty) runAnalyze();
  }
}
function setBusy(on) {
  $("output").setAttribute("aria-busy", String(on));
  document.body.classList.toggle("busy", on);
  if (on) $("m-time").textContent = "running…";
  else if (last) $("m-time").textContent = `${last.result.ms} ms`;
}

function severityBadge(sev) {
  const s = el("span", { className: "sev", textContent: sev });
  s.dataset.sev = sev;
  return s;
}
function makeMark(f, i, body, tagged) {
  const m = el("mark", { textContent: body });
  m.dataset.fam = familyOf(f.type);
  m.dataset.i = i;
  if (tagged) {
    m.dataset.tag = FAMILIES[familyOf(f.type)].tag;
    m.tabIndex = -1;
    m.title = `${f.type} · ${f.severity}${f.confidence !== undefined ? ` · confidence ${f.confidence.toFixed(2)}` : ""}${f.line ? ` · line ${f.line}:${f.column}` : ""}`;
  }
  return m;
}
// text[start:end] as DOM nodes, findings wrapped (highlighted) or replaced (redacted)
function annotate(text, findings, { redacted, start = 0, end = text.length, tagged = true, limit = Infinity }) {
  const frag = document.createDocumentFragment();
  let cursor = start;
  let marks = 0;
  findings.forEach((f, i) => {
    if (f.end <= start || f.start >= end) return;
    if (redacted && (f.start < start || f.start >= end)) return;
    const s = Math.max(f.start, start);
    const e = Math.min(f.end, end);
    if (s > cursor) frag.append(text.slice(cursor, s));
    const body = redacted ? f.replacement : text.slice(s, e);
    frag.append(marks++ < limit ? makeMark(f, f.i ?? i, body, tagged) : body);
    cursor = redacted ? f.end : e;
  });
  if (cursor < end) frag.append(text.slice(cursor, end));
  return frag;
}

function paintBackdrop(findings) {
  const bd = $("backdrop");
  const text = input.value;
  if (text.length > BACKDROP_LIMIT) { bd.hidden = true; return; }
  bd.hidden = false;
  bd.replaceChildren(findings ? annotate(text, findings, { redacted: false, tagged: false }) : text, "\n ");
  bd.scrollTop = input.scrollTop;
  bd.scrollLeft = input.scrollLeft;
}

function renderPlayground() {
  if (!last) return;
  const { text, result } = last;
  const f = result.findings;
  f.forEach((x, i) => { x.i = i; });
  const types = new Set(f.map((x) => x.type));
  const worst = f.reduce((w, x) => (SEV_ORDER[x.severity] > SEV_ORDER[w] ? x.severity : w), "low");
  $("m-findings").textContent = f.length;
  $("m-types").textContent = types.size;
  $("m-severity").replaceChildren(f.length ? severityBadge(worst) : "none");
  $("m-chars").textContent = text.length.toLocaleString();
  $("m-time").textContent = `${result.ms} ms`;

  const view = document.querySelector('input[name="view"]:checked').value;
  const out = $("output");
  if (!text) {
    out.replaceChildren(el("span", { className: "empty-state" }, "Paste text, drop a file, or pick a sample above. The redacted version appears here as you type."));
  } else {
    out.replaceChildren(annotate(text, f, { redacted: view === "redacted", limit: MARK_LIMIT }));
  }
  const notes = [];
  if (f.length > MARK_LIMIT) notes.push(`Highlighting the first ${MARK_LIMIT.toLocaleString()} of ${f.length.toLocaleString()} findings; all of them are redacted, and Copy and Download include everything.`);
  if (text.length > BACKDROP_LIMIT) notes.push("Input highlighting is off above 200,000 characters to keep typing smooth.");
  if (text && !f.length) notes.push(currentSample === "clean" ? "Nothing flagged, as expected: these values only look sensitive." : "Nothing detected with the current settings.");
  $("output-note").textContent = notes.join(" ");
  paintBackdrop(f);
  renderLegend(f);
  renderFindings();
  $("det-card").hidden = true;
}
document.querySelectorAll('input[name="view"]').forEach((r) => r.addEventListener("change", () => { renderPlayground(); writeHash(); }));

function renderLegend(findings) {
  const present = new Set(findings.map((f) => familyOf(f.type)));
  $("legend").replaceChildren(el("span", { className: "muted small" }, "Colour key:"), ...Object.entries(FAMILIES).map(([fam, d]) => {
    const item = el("span", { className: "legend-item" + (present.has(fam) ? "" : " absent") });
    const sw = el("span", { className: "sw" });
    sw.dataset.fam = fam;
    item.append(sw, el("span", { className: "tag-pill", textContent: d.tag }), d.label);
    item.dataset.fam = fam;
    return item;
  }));
}

// --- findings table: counts, filters, sorting, linking
const table = { sort: "start", dir: 1, type: "", sev: "", q: "", all: false };
function filteredFindings() {
  const f = last ? last.result.findings : [];
  const q = table.q.toLowerCase();
  const rows = f.filter((x) => (!table.type || x.type === table.type) && (!table.sev || x.severity === table.sev)
    && (!q || x.type.includes(q) || x.detector.includes(q)));
  const key = { severity: (x) => SEV_ORDER[x.severity], type: (x) => x.type, start: (x) => x.start, confidence: (x) => x.confidence, detector: (x) => x.detector }[table.sort];
  return rows.sort((a, b) => {
    const ka = key(a); const kb = key(b);
    return (ka < kb ? -1 : ka > kb ? 1 : a.start - b.start) * table.dir;
  });
}
function renderFindings() {
  if (!last) return;
  const { text, result } = last;
  const all = result.findings;
  // counts by type
  const counts = {};
  all.forEach((x) => { counts[x.type] = (counts[x.type] || 0) + 1; });
  $("type-counts").replaceChildren(...Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([type, n]) => {
    const b = el("button", { type: "button", className: "count-chip" }, swatch(type), `${type} `, el("strong", {}, String(n)));
    b.dataset.type = type;
    b.setAttribute("aria-pressed", String(table.type === type));
    b.setAttribute("aria-label", `${type}: ${n}. Show only ${type}`);
    return b;
  }));
  const rows = filteredFindings();
  const shown = table.all ? rows : rows.slice(0, ROW_LIMIT);
  $("findings-shown").textContent = rows.length === all.length ? `(${all.length})` : `(${rows.length} of ${all.length})`;
  $("show-all").hidden = shown.length === rows.length;
  $("show-all").textContent = `Show all ${rows.length.toLocaleString()}`;
  $("f-clear").hidden = !(table.type || table.sev || table.q);
  document.querySelectorAll("#findings th[aria-sort]").forEach((th) => {
    const k = th.querySelector("button").dataset.sort;
    th.setAttribute("aria-sort", k === table.sort ? (table.dir > 0 ? "ascending" : "descending") : "none");
  });
  const body = $("findings").tBodies[0];
  if (!shown.length) {
    const msg = all.length ? "No findings match these filters."
      : !text ? "No input yet." : currentSample === "clean" ? "Nothing detected, as expected for look-alikes." : "Nothing detected with the current settings.";
    body.replaceChildren(el("tr", {}, el("td", { colSpan: 7, className: "empty", textContent: msg })));
    return;
  }
  const reveal = $("reveal").checked;
  body.replaceChildren(...shown.map((f) => {
    const jump = el("button", { type: "button", className: "jump" }, swatch(f.type), f.type);
    jump.setAttribute("aria-label", `${f.type} at line ${f.line}, column ${f.column}: show in output`);
    const tr = el("tr", {},
      el("td", {}, severityBadge(f.severity)),
      el("td", {}, jump),
      el("td", { className: "num", textContent: `${f.line}:${f.column}` }),
      el("td", { className: "num", textContent: f.confidence.toFixed(2) }),
      el("td", { textContent: f.detector }),
      el("td", {}, el("code", { textContent: reveal ? text.slice(f.start, f.end) : "•".repeat(Math.min(12, f.end - f.start)) })),
      el("td", {}, el("code", { textContent: f.replacement })));
    tr.dataset.i = f.i;
    return tr;
  }));
}
$("type-counts").addEventListener("click", (e) => {
  const b = e.target.closest("[data-type]");
  if (!b) return;
  table.type = table.type === b.dataset.type ? "" : b.dataset.type;
  renderFindings();
});
$("f-search").addEventListener("input", (e) => { table.q = e.target.value.trim(); renderFindings(); });
$("f-sev").addEventListener("change", (e) => { table.sev = e.target.value; renderFindings(); });
$("f-clear").addEventListener("click", () => {
  Object.assign(table, { type: "", sev: "", q: "" });
  $("f-search").value = "";
  $("f-sev").value = "";
  renderFindings();
});
$("show-all").addEventListener("click", () => { table.all = true; renderFindings(); });
$("findings").tHead.addEventListener("click", (e) => {
  const b = e.target.closest("[data-sort]");
  if (!b) return;
  if (table.sort === b.dataset.sort) table.dir = -table.dir;
  else { table.sort = b.dataset.sort; table.dir = b.dataset.sort === "severity" || b.dataset.sort === "confidence" ? -1 : 1; }
  renderFindings();
});
function toggleReveal() { $("reveal").checked = !$("reveal").checked; renderFindings(); }
$("reveal").addEventListener("change", renderFindings);

// linking a highlight and its row, both ways
let linked = null;
function link(i, { scrollRow = false, scrollMark = false } = {}) {
  if (linked !== null) document.querySelectorAll(`[data-i="${linked}"]`).forEach((n) => n.classList.remove("linked"));
  linked = i;
  if (i === null) return;
  const nodes = document.querySelectorAll(`[data-i="${i}"]`);
  nodes.forEach((n) => n.classList.add("linked"));
  if (scrollRow) {
    const row = $("findings").querySelector(`tr[data-i="${i}"]`);
    if (row) scrollWithin($("findings-wrap"), row);
  }
  if (scrollMark) {
    const m = $("output").querySelector(`mark[data-i="${i}"]`);
    if (m) scrollWithin($("output"), m);
    const b = $("backdrop").querySelector(`mark[data-i="${i}"]`);
    if (b && !$("backdrop").hidden) {
      input.scrollTop = Math.max(0, b.offsetTop - input.clientHeight / 3);
      input.scrollLeft = Math.max(0, b.offsetLeft - 40);
    }
  }
}
function scrollWithin(box, node) {
  const b = box.getBoundingClientRect();
  const n = node.getBoundingClientRect();
  if (n.top < b.top || n.bottom > b.bottom) box.scrollTop += n.top - b.top - b.height / 3;
}
$("output").addEventListener("mouseover", (e) => { const m = e.target.closest("mark"); if (m) link(m.dataset.i); });
$("output").addEventListener("mouseleave", () => link(null));
$("output").addEventListener("focusin", (e) => { const m = e.target.closest("mark"); if (m) link(m.dataset.i, { scrollRow: true }); });
$("output").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const marks = [...$("output").querySelectorAll("mark")];
  if (!marks.length) return;
  e.preventDefault();
  const at = marks.indexOf(document.activeElement);
  const next = at < 0 ? (e.key === "ArrowRight" ? 0 : marks.length - 1) : Math.min(Math.max(at + (e.key === "ArrowRight" ? 1 : -1), 0), marks.length - 1);
  marks[next].focus();
});
$("findings").tBodies[0].addEventListener("mouseover", (e) => { const tr = e.target.closest("tr[data-i]"); if (tr) link(tr.dataset.i); });
$("findings").tBodies[0].addEventListener("mouseleave", () => link(null));
$("findings").tBodies[0].addEventListener("focusin", (e) => { const tr = e.target.closest("tr[data-i]"); if (tr) link(tr.dataset.i, { scrollMark: true }); });
$("findings").tBodies[0].addEventListener("click", (e) => {
  const b = e.target.closest(".jump");
  if (!b) return;
  const i = b.closest("tr").dataset.i;
  const m = $("output").querySelector(`mark[data-i="${i}"]`);
  if (m) { m.focus({ preventScroll: true }); link(i, { scrollMark: true }); }
});

// --- copy, download, determinism
function outName() {
  const dot = fileName.lastIndexOf(".");
  return dot > 0 ? `${fileName.slice(0, dot)}.redacted${fileName.slice(dot)}` : `${fileName}.redacted`;
}
function copyOutput() { if (last) copyText(last.result.redacted, "Copied the redacted output"); }
function downloadOutput() { if (last) download(last.result.redacted, outName()); }
$("copy-out").addEventListener("click", copyOutput);
$("download-out").addEventListener("click", downloadOutput);
$("det-btn").addEventListener("click", async () => {
  if (!last) return;
  const card = $("det-card");
  card.hidden = false;
  card.replaceChildren(el("p", { className: "muted" }, "Re-running four independent ways…"));
  try {
    const r = await call("determinism", { text: input.value, settings: settingsKey() });
    const sameAsShown = last.text === input.value;
    const rows = r.runs.map((run) => el("tr", {},
      el("td", { textContent: run.label }),
      el("td", {}, el("code", { textContent: run.sha256.slice(0, 16) + "…", title: run.sha256 })),
      el("td", { className: "num", textContent: run.bytes.toLocaleString() }),
      el("td", { className: "num", textContent: `${run.ms} ms` })));
    card.replaceChildren(
      el("div", { className: "card-head" }, el("h2", {}, "Determinism check"),
        el("span", { className: `tag ${r.identical ? "ok" : "err"}`, textContent: r.identical ? "byte-identical" : "outputs differ" })),
      el("p", {}, r.identical
        ? `All four runs produced the same ${r.runs[0].bytes.toLocaleString()} bytes (same SHA-256), however the text was chunked.`
        : "The runs disagree. Please report this: the engine promises byte-identical output."),
      el("div", { className: "table-wrap" }, el("table", {}, el("thead", {}, el("tr", {},
        ...["Run", "SHA-256 of the output", "Bytes", "Time"].map((h) => el("th", { scope: "col", textContent: h })))), el("tbody", {}, ...rows))),
      sameAsShown && r.runs[0].bytes === new TextEncoder().encode(last.result.redacted).length
        ? el("p", { className: "muted small" }, "The first run is the output shown above.") : null);
  } catch (err) {
    card.replaceChildren(el("p", { className: "error", textContent: err.message }));
  }
});

// ---------------------------------------------------------------- run this yourself
const SECRET_ENV = { hmac_key: "SAFESTREAM_KEY", hash_salt: "SAFESTREAM_SALT", encrypt_key: "SAFESTREAM_ENCRYPT_KEY" };
// the policy as command-line flags; `config` lists the settings that have no flag
function cliPlan(p) {
  const det = { ...(p.detection || {}) };
  const red = { ...(p.redaction || {}) };
  const cus = p.custom || {};
  const st = { ...(p.streaming || {}) };
  const detect = []; const redact = []; const env = []; const config = [];
  if (det.types) { if (det.types.length) detect.push(["--types", det.types.join(",")]); else config.push("an empty type list"); delete det.types; }
  if ("min_confidence" in det) { detect.push(["--min-confidence", String(det.min_confidence)]); delete det.min_confidence; }
  if (det.use_entropy === false) { detect.push(["--no-entropy"]); delete det.use_entropy; }
  if (det.use_regional) { detect.push(["--regional"]); delete det.use_regional; }
  if (det.profile === "prose") { detect.push(["--profile", "prose"]); delete det.profile; }
  if (det.use_dates === true) { detect.push(["--dates"]); delete det.use_dates; }
  if (det.use_log_usernames) { detect.push(["--log-usernames"]); delete det.use_log_usernames; }
  for (const w of cus.words || []) detect.push(["--custom-word", w]);
  for (const r of cus.patterns || []) detect.push(["--custom-regex", r]);
  if ("chunk_size" in st) { detect.push(["--chunk-size", String(st.chunk_size)]); delete st.chunk_size; }
  if ("overlap" in st) { detect.push(["--overlap", String(st.overlap)]); delete st.overlap; }
  if (det.use_gazetteer || det.use_ensemble) { config.push("name heuristics"); delete det.use_gazetteer; delete det.use_ensemble; }
  config.push(...Object.keys(det), ...Object.keys(st));
  if (red.mode) { redact.push(["--mode", red.mode]); delete red.mode; }
  if ("replacement" in red) { redact.push(["--replace", red.replacement]); delete red.replacement; }
  for (const [t, r] of Object.entries(red.replacements || {})) redact.push(["--replace-type", `${t}=${r}`]);
  delete red.replacements;
  if ("mask_keep_last" in red) { redact.push(["--keep-last", String(red.mask_keep_last)]); delete red.mask_keep_last; }
  if ("mask_char" in red) { redact.push(["--mask-char", red.mask_char]); delete red.mask_char; }
  for (const k of ["hmac_key", "hash_salt"]) {
    if (k in red) { redact.push([k === "hmac_key" ? "--hmac-key" : "--hash-salt", { env: SECRET_ENV[k], value: red[k] }]); env.push(SECRET_ENV[k]); delete red[k]; }
  }
  if ("encrypt_key" in red) { env.push(SECRET_ENV.encrypt_key); delete red.encrypt_key; }
  config.push(...Object.keys(red));
  for (const sec of Object.keys(p)) if (!["detection", "redaction", "custom", "streaming"].includes(sec)) config.push(`[${sec}]`);
  return { detect, redact, env, config };
}
const shellArg = (a) => (typeof a === "object" ? `"$${a.env}"` : shq(a));
const realArg = (a) => (typeof a === "object" ? a.value : a);
function cliCommand(sub, inputName, plan, display) {
  const useConfig = plan.config.length > 0;
  const parts = sub === "redact" ? ["redact", inputName, "-o", "clean.log"] : ["detect", inputName];
  const flags = useConfig ? [["--config", "policy.toml"]] : [...plan.detect, ...(sub === "redact" ? plan.redact : [])];
  if (display) return ["safestream", ...parts, ...flags.map((f) => f.map(shellArg).join(" "))];
  return [...parts, ...flags.flat().map(realArg)];
}
function renderSnippets() {
  const plan = cliPlan(policy);
  const useConfig = plan.config.length > 0;
  const head = [];
  if (useConfig) head.push(`# ${plan.config.join(", ")} ${plan.config.length > 1 ? "have" : "has"} no flag: save the policy.toml card as policy.toml`);
  else for (const v of plan.env) head.push(`export ${v}='your secret'   # the page uses a random key for this tab`);
  const fmt = (argv) => {
    // wrap a long command at about 72 columns, one shell continuation per line
    const out = [argv[0]];
    for (const part of argv.slice(1)) {
      if (out.at(-1).length + part.length + 1 > 72) out.push(`    ${part}`);
      else out[out.length - 1] += ` ${part}`;
    }
    return out.join(" \\\n");
  };
  $("cli-snippet").textContent = [...head, fmt(cliCommand("redact", "app.log", plan, true)),
    `${fmt(cliCommand("detect", "app.log", plan, true))}   # list findings; values stay hidden`].join("\n");

  // Python: the policy's keys are Redactor / RedactionPolicy keyword arguments
  const py = pythonSnippet();
  $("py-snippet").textContent = py;

  const isDefault = !Object.keys(policy).length;
  const serve = isDefault ? "safestream serve" : "safestream serve --config policy.toml";
  $("rest-snippet").textContent = `${serve}            # http://127.0.0.1:8000, loopback only

curl -s -X POST http://127.0.0.1:8000/redact \\
  -H 'Content-Type: application/json' \\
  -d '{"text": "email bob@corp.io key AKIAIOSFODNN7EXAMPLE"}'`;
  const args = isDefault ? ["mcp-serve"] : ["mcp-serve", "--config", "/path/to/policy.toml"];
  const mcpConfig = JSON.stringify({ mcpServers: { safestream: { command: "safestream", args } } }, null, 2);
  $("mcp-config").textContent = mcpConfig;
  $("mcp-snippet").textContent = `${mcpConfig}

# then an agent calls, for example:
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "scan", "arguments": {"text": "deploy key AKIAIOSFODNN7EXAMPLE"}}}`;
  renderCiSnippets();
}
function pyValue(v) {
  if (typeof v === "boolean") return v ? "True" : "False";
  if (Array.isArray(v)) return `[${v.map(pyValue).join(", ")}]`;
  if (typeof v === "string") return JSON.stringify(v);
  return String(v);
}
function pythonSnippet() {
  const det = policy.detection || {};
  const red = policy.redaction || {};
  const cus = policy.custom || {};
  const kw = [];
  for (const [k, v] of Object.entries(det)) kw.push(`${k}=${pyValue(v)}`);
  if (cus.words) kw.push(`custom_words=${pyValue(cus.words)}`);
  if (cus.patterns) kw.push(`custom_patterns=${pyValue(cus.patterns)}`);
  for (const [k, v] of Object.entries(policy.streaming || {})) kw.push(`${k}=${pyValue(v)}`);
  const pol = [];
  let needOs = false;
  let needType = false;
  for (const [k, v] of Object.entries(red)) {
    if (SECRET_ENV[k]) { pol.push(`${k}=os.environ[${JSON.stringify(SECRET_ENV[k])}]`); needOs = true; }
    else if (k === "replacements") {
      needType = true;
      pol.push(`replacements={${Object.entries(v).map(([t, r]) => `EntityType.${t.toUpperCase()}: ${JSON.stringify(r)}`).join(", ")}}`);
    } else pol.push(`${k}=${pyValue(v)}`);
  }
  if (pol.length) kw.push(`policy=RedactionPolicy(\n        ${pol.join(",\n        ")},\n    )`);
  const names = ["Redactor", pol.length ? "RedactionPolicy" : null, needType ? "EntityType" : null].filter(Boolean).sort();
  const other = Object.keys(policy).filter((s) => !["detection", "redaction", "custom", "streaming"].includes(s));
  return [needOs ? "import os\n" : null,
    `from safestream_redactor import ${names.join(", ")}`,
    "",
    kw.length ? `redactor = Redactor(\n    ${kw.join(",\n    ")},\n)` : "redactor = Redactor()",
    other.length ? `# also in policy.toml: ${other.join(", ")}` : null,
    `stats = redactor.redact_file("app.log", "clean.log")  # constant memory, atomic`,
    "print(stats.summary())",
    "",
    "# or straight from the policy file:",
    "# from safestream_redactor.config import redactor_from_config",
    '# redactor = redactor_from_config("policy.toml")'].filter((x) => x !== null).join("\n");
}

// run the CLI command above, for real, on the playground input
$("cli-run").addEventListener("click", async () => {
  const box = $("cli-result");
  if (!info || !last) return;
  const plan = cliPlan(policy);
  const argv = cliCommand("redact", "app.log", plan, false);
  const files = { "app.log": input.value };
  if (plan.config.length) files["policy.toml"] = toToml(policy);
  box.replaceChildren(el("p", { className: "muted small" }, "Running safestream in this tab…"));
  try {
    const r = await call("cli", { argv, files });
    const out = r.files["clean.log"];
    const same = out !== undefined && last.text === input.value && out === last.result.redacted;
    box.replaceChildren(
      el("p", {}, el("span", { className: `tag ${r.exit === 0 ? "ok" : "err"}`, textContent: `exit ${r.exit}` }), " ",
        out === undefined ? "No clean.log was written." : same
          ? "clean.log is byte-identical to the playground output." : "clean.log differs from the playground output."),
      r.stderr ? el("pre", { className: "code small-view", textContent: r.stderr }) : null);
  } catch (err) {
    box.replaceChildren(el("p", { className: "error", textContent: err.message }));
  }
});

// sub-tabs (Run this yourself)
function wireTabs(list, onSelect) {
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  const select = (tab, focus) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute("aria-controls")).hidden = !on;
    }
    if (focus) tab.focus();
    if (onSelect) onSelect(tab);
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (e.key === "Home" || e.key === "End" || step) {
        e.preventDefault();
        const next = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + step + tabs.length) % tabs.length;
        select(tabs[next], true);
      }
    });
  });
  return { tabs, select };
}
wireTabs(document.querySelector("#run-card .subtabs"));

// ---------------------------------------------------------------- main tabs
const NO_RAIL = new Set(["tab-install", "tab-trust"]);
const main = wireTabs(document.querySelector(".tabs"), (tab) => {
  $("layout").classList.toggle("wide", NO_RAIL.has(tab.id));
  if (tab.id === "tab-inspector") loadTrace();
  else pause();
  if (tab.id === "tab-ci" && !$("ci-input").value) { ciPreset("leak"); runGate(); }
  // show a real answer straight away, not an empty pane
  if (tab.id === "tab-rest" && !$("rest-response").textContent) sendRest();
  if (tab.id === "tab-mcp" && !$("mcp-response").textContent) sendMcp();
  writeHash();
});
const tabName = (tab) => tab.id.slice(4);
const activeTab = () => main.tabs.find((t) => t.getAttribute("aria-selected") === "true");
function goTo(name, focus = false) {
  const tab = $(`tab-${name}`);
  if (!tab) return;
  main.select(tab, focus);
  if (!focus) $("main").scrollIntoView({ block: "start", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}
document.addEventListener("click", (e) => {
  const g = e.target.closest("[data-goto]");
  if (g) { e.preventDefault(); goTo(g.dataset.goto); }
  const c = e.target.closest("[data-copy]");
  if (c) { const n = $(c.dataset.copy); copyText(n instanceof HTMLTextAreaElement ? n.value : n.textContent); }
});

// settings rail: always open on wide screens, a collapsible section on narrow ones
const narrow = matchMedia("(max-width: 900px)");
const syncRail = () => { $("rail").open = !narrow.matches; };
narrow.addEventListener("change", syncRail);
syncRail();

// ---------------------------------------------------------------- shareable state (never the text)
// Only settings and the active tab go in the address. Text, custom words and
// patterns, per-type replacements and keys never do: they may be sensitive.
function writeHash() {
  if (!readyForHash) return;
  const f = form.elements;
  const q = new URLSearchParams();
  const tab = activeTab();
  if (tab && tab.id !== "tab-playground") q.set("tab", tabName(tab));
  if (f.mode.value !== "replace") q.set("mode", f.mode.value);
  if (f.mode.value === "replace" && f.replacement.value !== DEFAULTS.replacement) q.set("replacement", f.replacement.value);
  if (f.mode.value === "mask") { q.set("keep", f.mask_keep_last.value); if (f.mask_char.value !== "*") q.set("mchar", f.mask_char.value); }
  if (f.mode.value === "hash" && f.hash_algorithm.value !== "sha256") q.set("alg", f.hash_algorithm.value);
  if (Number(f.min_confidence.value) !== 0.5) q.set("conf", f.min_confidence.value);
  if (!f.use_entropy.checked) q.set("entropy", "0");
  for (const k of ["use_names", "use_regional", "use_log_usernames"]) if (f[k].checked) q.set(k.slice(4), "1");
  if (f.profile.value === "prose") q.set("profile", "prose");
  if (f.use_dates.checked !== (f.profile.value === "prose")) q.set("dates", f.use_dates.checked ? "1" : "0");
  const chosen = typeBoxes.filter((b) => b.checked).map((b) => b.value);
  if (typeBoxes.length && chosen.length !== typeBoxes.length) q.set("types", chosen.join(",") || "none");
  if (document.querySelector('input[name="view"]:checked').value !== "redacted") q.set("view", "highlighted");
  if (currentSample && currentSample !== "log") q.set("sample", currentSample);
  const hash = q.toString();
  history.replaceState(null, "", hash ? `#${hash}` : location.pathname + location.search);
}
let readyForHash = false;
function readHash() {
  const q = new URLSearchParams(location.hash.slice(1));
  const f = form.elements;
  const mode = q.get("mode");
  if (mode && MODES[mode]) {
    const r = form.querySelector(`input[name="mode"][value="${mode}"]`);
    if (r && !r.disabled) r.checked = true;
  }
  if (q.has("replacement")) f.replacement.value = q.get("replacement").slice(0, 60);
  if (q.has("keep")) f.mask_keep_last.value = Math.max(0, Math.min(32, Number(q.get("keep")) || 0));
  if (q.has("mchar")) f.mask_char.value = q.get("mchar").slice(0, 1) || "*";
  if (q.get("alg") === "sha512") f.hash_algorithm.value = "sha512";
  if (q.has("conf")) f.min_confidence.value = Math.max(0, Math.min(1, Number(q.get("conf")) || 0));
  if (q.get("entropy") === "0") f.use_entropy.checked = false;
  for (const k of ["names", "regional", "log_usernames"]) if (q.get(k) === "1") f[`use_${k}`].checked = true;
  if (q.get("profile") === "prose") f.profile.value = "prose";
  f.use_dates.checked = q.has("dates") ? q.get("dates") === "1" : f.profile.value === "prose";
  if (q.has("types")) {
    const set = new Set(q.get("types") === "none" ? [] : q.get("types").split(","));
    typeBoxes.forEach((b) => { b.checked = set.has(b.value); });
  }
  if (q.get("view") === "highlighted") document.querySelector('input[name="view"][value="highlighted"]').checked = true;
  return { tab: q.get("tab"), sample: SAMPLES[q.get("sample")] ? q.get("sample") : null };
}
addEventListener("hashchange", () => {
  const { tab } = readHash();
  settingsChanged();
  if (tab && $(`tab-${tab}`)) main.select($(`tab-${tab}`));
});

// ---------------------------------------------------------------- inspector
let longLog = null;
function makeLongLog() {
  // ~60 KB of log with secrets throughout, including long tokens that chunk
  // boundaries will cut, so the engine has to retreat and keep them whole
  let seed = 7;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  const users = ["maria.garcia", "d.okafor", "li.wei", "a.novak", "s.iyer"];
  const out = [];
  let size = 0;
  for (let i = 0; size < 60000; i++) {
    const ts = `2026-11-02T${String(9 + Math.floor(i / 3600) % 12).padStart(2, "0")}:${String(Math.floor(i / 60) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`;
    const kind = rnd(9);
    const u = users[rnd(users.length)];
    let line;
    if (kind === 0) line = `${ts} INFO  auth    login ok user=${u}@corpmail.com ip=10.${rnd(250)}.${rnd(250)}.${rnd(250)}`;
    else if (kind === 1) line = `${ts} WARN  billing card=4111 1111 1111 1111 ssn=123-45-6789 retry=${rnd(5)}`;
    else if (kind === 2) line = `${ts} DEBUG session jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNzMwNTQwMDAwfQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`;
    else if (kind === 3) line = `${ts} DEBUG deploy  aws_key=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghijklmnopqrstuvwxyz`;
    else line = `${ts} INFO  api     GET /v1/orders/${10000 + rnd(90000)} 200 in ${rnd(90) + 3} ms`;
    out.push(line);
    size += line.length + 1;
  }
  return out.join("\n") + "\n";
}
// a JWT placed across the first planned chunk boundary (8,192 characters)
function makeSplitLog() {
  const line = "2026-11-02T09:14:07Z INFO  api     GET /v1/orders/10442 200 in 12 ms\n";
  let t = "";
  while (t.length + line.length < 8192 - 40) t += line;
  t += "2026-11-02T09:16:40Z DEBUG session jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNzMwNTQwMDAwfQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n";
  while (t.length < 20000) t += line;
  return t;
}

let trace = null;
let pos = 0;
let timer = null;
let traceSeq = 0;

async function loadTrace() {
  if (!info) return;
  const src = document.querySelector('input[name="isrc"]:checked').value;
  const text = src === "input" ? input.value : src === "split" ? makeSplitLog() : (longLog ??= makeLongLog());
  const chunkSel = $("ichunk");
  if (src === "split" && chunkSel.options.length) chunkSel.selectedIndex = 0;
  const chunk = Number(chunkSel.value) || 0;
  const seq = ++traceSeq;
  pause();
  if (!text) {
    $("inotes").replaceChildren(el("div", { className: "note" }, "The playground input is empty. Pick a sample there, or choose the long log."));
    return;
  }
  try {
    const result = await call("trace", { text, settings: settingsKey(), chunk: chunk || info.overlap });
    if (seq !== traceSeq) return;
    if (!chunkSel.options.length || chunkSel.dataset.sizes !== result.sizes.join()) {
      chunkSel.dataset.sizes = result.sizes.join();
      chunkSel.replaceChildren(...result.sizes.map((n, i) => new Option(`${n.toLocaleString()} chars (${i + 1}× overlap)`, n)));
      chunkSel.value = String(result.chunk);
    }
    trace = { text, ...result };
    pos = src === "split" ? Math.max(0, trace.passes.findIndex((p) => p.retreated_by)) : 0;
    settingsError(null);
    renderTraceSummary();
    renderPass();
  } catch (err) {
    if (seq === traceSeq) settingsError(err);
  }
}
document.querySelectorAll('input[name="isrc"]').forEach((r) => r.addEventListener("change", loadTrace));
$("ichunk").addEventListener("change", loadTrace);

function renderTraceSummary() {
  const { passes, text } = trace;
  const widest = Math.max(...passes.map((p) => p.window[1] - p.window[0]));
  $("i-passes").textContent = passes.length;
  $("i-findings").textContent = passes.reduce((n, p) => n + p.findings.length, 0);
  $("i-retreats").textContent = passes.filter((p) => p.retreated_by).length;
  $("i-window").textContent = `${widest.toLocaleString()} chars`;
  $("i-input").textContent = `${text.length.toLocaleString()} chars`;
  $("tape-end").textContent = `${text.length.toLocaleString()} chars`;
  $("iseek").max = passes.length - 1;
  $("bars").replaceChildren(...passes.map((p) => {
    const bar = el("span");
    bar.style.height = `${((p.window[1] - p.window[0]) / widest) * 100}%`;
    return bar;
  }));
  $("bars-caption").textContent = `Window size of each pass. It never exceeds ${widest.toLocaleString()} characters, whatever the input size: that is the constant-memory guarantee.`;
}

function renderPass() {
  const { passes, text } = trace;
  const p = passes[pos];
  const pct = (n) => `${(n / text.length) * 100}%`;
  $("ipos").textContent = `${pos + 1} of ${passes.length}`;
  $("iseek").value = pos;
  $("iseek").setAttribute("aria-valuetext", `Pass ${pos + 1} of ${passes.length}`);
  $("t-done").style.width = pct(p.emit[0]);
  const win = $("t-win");
  win.style.left = pct(p.window[0]);
  win.style.width = pct(p.window[1] - p.window[0]);
  const span = p.window[1] - p.window[0] || 1;
  $("t-ctx").style.width = `${((p.emit[0] - p.window[0]) / span) * 100}%`;
  $("t-emit").style.width = `${((p.emit[1] - p.emit[0]) / span) * 100}%`;
  $("t-carry").style.width = `${((p.window[1] - p.emit[1]) / span) * 100}%`;
  [...$("bars").children].forEach((b, i) => b.classList.toggle("on", i === pos));

  const notes = [["", `Pass ${pos + 1} scanned characters ${p.window[0].toLocaleString()}–${p.window[1].toLocaleString()} and wrote ${p.emit[0].toLocaleString()}–${p.emit[1].toLocaleString()} (lines ${p.lines[0]}–${p.lines[1]}) in ${p.ms} ms.`]];
  if (p.retreated_by) notes.push(["warn", `The planned boundary at ${p.planned_end.toLocaleString()} would have cut an entity in two, so it moved back ${p.retreated_by} characters (red dashed line). The next pass writes the entity whole.`]);
  if (p.straddlers.length) notes.push(["ok", `Held back by the previous pass and written whole here: ${p.straddlers.join(", ")}. A secret split across a chunk boundary is still caught.`]);
  if (p.deferred) notes.push(["", `${p.deferred} earlier pass(es) wrote nothing: a detection covered the whole planned segment, so the engine read more text first.`]);
  $("inotes").replaceChildren(...notes.map(([cls, msg]) => el("div", { className: `note ${cls}`, textContent: msg })));

  // the scanned window: context | emitted | (actual cut, planned cut) carried
  const all = passes.flatMap((x) => x.findings);
  const frag = document.createDocumentFragment();
  const band = (cls, s, e) => el("span", { className: cls }, annotate(text, all, { redacted: false, start: s, end: e, tagged: false }));
  if (p.emit[0] > p.window[0]) frag.append(band("b-ctx", p.window[0], p.emit[0]));
  frag.append(band("b-emit", p.emit[0], p.emit[1]));
  frag.append(el("span", { className: "cut", title: "where this pass stopped writing" }));
  if (p.window[1] > p.emit[1]) {
    const carry = band("b-carry", p.emit[1], p.window[1]);
    if (p.retreated_by) {
      // the planned cut sits inside the carried text
      const at = p.planned_end;
      carry.replaceChildren(annotate(text, all, { redacted: false, start: p.emit[1], end: at, tagged: false }),
        el("span", { className: "planned", title: "planned boundary: it would have cut an entity" }),
        annotate(text, all, { redacted: false, start: at, end: p.window[1], tagged: false }));
    }
    frag.append(carry);
  }
  $("iwindow").replaceChildren(frag);
  // open the pane where this pass starts writing, not at the dim context above it
  const emitted = $("iwindow").querySelector(".b-emit");
  const cut = $("iwindow").querySelector(p.retreated_by ? ".planned" : ".b-emit");
  $("iwindow").scrollTop = Math.max(0, (p.retreated_by ? cut : emitted).offsetTop - 48);
  $("isegment").replaceChildren(annotate(text, p.findings, { redacted: true, start: p.emit[0], end: p.emit[1], tagged: true }));
}

function pause() {
  clearInterval(timer);
  timer = null;
  $("iplay").textContent = "Play";
}
function step(d) {
  if (!trace) return;
  pos = Math.min(Math.max(pos + d, 0), trace.passes.length - 1);
  renderPass();
}
$("iplay").addEventListener("click", () => {
  if (!trace) return;
  if (timer) return pause();
  if (pos >= trace.passes.length - 1) pos = -1;
  $("iplay").textContent = "Pause";
  const tick = () => {
    if (pos >= trace.passes.length - 1) return pause();
    step(1);
  };
  tick();
  timer = setInterval(tick, Number($("ispeed").value));
});
$("istep").addEventListener("click", () => { pause(); step(1); });
$("iback").addEventListener("click", () => { pause(); step(-1); });
$("iseek").addEventListener("input", (e) => { pause(); pos = Number(e.target.value); renderPass(); });
$("ispeed").addEventListener("change", () => { if (timer) { pause(); $("iplay").click(); } });

// --- generated large input: throughput and peak memory, measured here
$("bench-run").addEventListener("click", async () => {
  if (!info) return;
  const sizes = $("bench-sizes").value.split(",").map(Number);
  const btn = $("bench-run");
  btn.disabled = true;
  $("bench-progress").hidden = false;
  $("bench-fill").style.width = "2%";
  $("bench-status").textContent = "Starting…";
  const started = performance.now();
  try {
    const r = await call("bench", { settings: settingsKey(), sizes: JSON.stringify(sizes) }, ({ i, n, stage }) => {
      const done = (i * 2 + (stage === "timing" ? 0 : 1)) / (n * 2);
      $("bench-fill").style.width = `${Math.max(2, done * 100)}%`;
      $("bench-status").textContent = `${fmtBytes(sizes[i])}: ${stage}…`;
    });
    $("bench-fill").style.width = "100%";
    $("bench-status").textContent = `Done in ${((performance.now() - started) / 1000).toFixed(1)} s.`;
    renderBench(r);
  } catch (err) {
    $("bench-status").textContent = err.message;
  } finally {
    btn.disabled = false;
    setTimeout(() => { $("bench-progress").hidden = true; }, 600);
  }
});
function renderBench(r) {
  const maxPeak = Math.max(...r.rows.map((x) => x.peak_bytes));
  const maxIn = Math.max(...r.rows.map((x) => x.bytes));
  const rows = r.rows.map((x) => el("tr", {},
    el("td", { className: "num", textContent: fmtBytes(x.bytes) }),
    el("td", { className: "num", textContent: `${x.seconds} s` }),
    el("td", { className: "num", textContent: `${x.mb_per_s} MB/s` }),
    el("td", { className: "num", textContent: fmtBytes(x.peak_bytes) }),
    el("td", {}, el("code", { textContent: x.sha256.slice(0, 12) + "…", title: x.sha256 }))));
  const chart = el("div", { className: "bench-chart", role: "img" });
  chart.setAttribute("aria-label", `Input size versus peak memory: ${r.rows.map((x) => `${fmtBytes(x.bytes)} in, ${fmtBytes(x.peak_bytes)} peak`).join("; ")}.`);
  for (const x of r.rows) {
    const inBar = el("span", { className: "bar in" });
    inBar.style.width = `${(x.bytes / maxIn) * 100}%`;
    const peakBar = el("span", { className: "bar peak" });
    peakBar.style.width = `${Math.max(0.5, (x.peak_bytes / maxIn) * 100)}%`;
    chart.append(el("div", { className: "bench-row" },
      el("span", { className: "bench-label", textContent: fmtBytes(x.bytes) }),
      el("span", { className: "bench-bars" }, inBar, peakBar)));
  }
  const ratio = maxPeak / Math.min(...r.rows.map((x) => x.peak_bytes));
  $("bench-out").replaceChildren(
    el("div", { className: "table-wrap" }, el("table", {}, el("thead", {}, el("tr", {},
      ...["Input", "Time", "Throughput", "Peak memory", "Output SHA-256"].map((h) => el("th", { scope: "col", textContent: h })))), el("tbody", {}, ...rows))),
    el("p", { className: "muted small legend-row" }, el("span", { className: "key in" }, "input size"), " ", el("span", { className: "key peak" }, "peak memory"), " (same scale)"),
    chart,
    el("p", {}, `Input grew ${(maxIn / Math.min(...r.rows.map((x) => x.bytes))).toFixed(0)}×; peak memory changed ${ratio.toFixed(2)}×. `,
      `The window is one ${r.chunk.toLocaleString()}-character chunk plus a ${r.overlap.toLocaleString()}-character overlap, whatever the input size.`),
    el("p", { className: "muted small" }, "Measured in this tab: the pure-Python engine on one thread inside WebAssembly, with allocation tracing off for the timing run. A local install is several times faster (see below)."));
}

// ---------------------------------------------------------------- REST console
const REST_TEXT = "email bob@corp.io key AKIAIOSFODNN7EXAMPLE";
function restRoute() {
  const [route, variant] = $("rest-route").value.split("|");
  const [method, path] = route.split(" ");
  return { method, path, variant };
}
function restDefaults() {
  const { method, variant } = restRoute();
  $("rest-body").value = method !== "POST" ? ""
    : variant === "nofield" ? JSON.stringify({ txt: REST_TEXT }, null, 2)
    : variant === "badjson" ? "{text: not json}"
    : JSON.stringify({ text: REST_TEXT }, null, 2);
  $("rest-body").disabled = method !== "POST";
  renderCurl();
}
function renderCurl() {
  const { method, path } = restRoute();
  let cmd = `curl -s ${method === "POST" ? "-X POST " : ""}http://127.0.0.1:8000${path}`;
  if (method === "POST") {
    let body = $("rest-body").value;
    try { body = JSON.stringify(JSON.parse(body)); } catch { /* send as typed */ }
    if (body.length > 400) body = body.slice(0, 400) + "…";
    cmd += ` \\\n  -H 'Content-Type: application/json' \\\n  -d ${shq(body)}`;
  }
  $("rest-curl").textContent = `# with \`${Object.keys(policy).length ? "safestream serve --config policy.toml" : "safestream serve"}\` running locally\n${cmd}`;
}
$("rest-route").addEventListener("change", restDefaults);
$("rest-body").addEventListener("input", renderCurl);
$("rest-use-input").addEventListener("click", () => {
  $("rest-route").value = "POST /redact";
  $("rest-body").disabled = false;
  $("rest-body").value = JSON.stringify({ text: input.value }, null, 2);
  renderCurl();
});
let restSeq = 0;
async function sendRest() {
  if (!info) return;
  const { method, path } = restRoute();
  const status = $("rest-status");
  const seq = ++restSeq;
  try {
    const r = await call("rest", { method, path, body: method === "POST" ? $("rest-body").value : "", settings: settingsKey() });
    if (seq !== restSeq) return; // a newer request was sent: show its reply only
    status.textContent = `${r.status}`;
    status.className = `status ${r.status < 400 ? "ok" : "err"}`;
    $("rest-response").textContent = JSON.stringify(r.body, null, 2);
  } catch (err) {
    if (seq !== restSeq) return;
    status.textContent = "error";
    status.className = "status err";
    $("rest-response").textContent = err.message;
  }
}
$("rest-send").addEventListener("click", sendRest);

// ---------------------------------------------------------------- MCP console
const MCP_TEXT = "deploy key AKIAIOSFODNN7EXAMPLE, notify maria.garcia@corpmail.com";
let mcpId = 1;
const tool = (name, args = {}) => ({ method: "tools/call", params: { name, arguments: args } });
const MCP_PRESETS = {
  initialize: () => ({ method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "demo", version: "1" } } }),
  initialized: () => ({ method: "notifications/initialized" }),
  ping: () => ({ method: "ping" }),
  list: () => ({ method: "tools/list" }),
  scan: () => tool("scan", { text: MCP_TEXT }),
  redact: () => tool("redact", { text: MCP_TEXT }),
  explain: () => tool("explain_detection", { text: MCP_TEXT }),
  detectors: () => tool("detectors"),
  health: () => tool("health"),
  unknown: () => tool("exfiltrate", { text: MCP_TEXT }),
};
function mcpPreset(name) {
  const msg = MCP_PRESETS[name]();
  // a notification has no id and gets no reply
  $("mcp-body").value = JSON.stringify(name === "initialized" ? { jsonrpc: "2.0", ...msg } : { jsonrpc: "2.0", id: mcpId++, ...msg }, null, 2);
}
$("mcp-presets").addEventListener("click", (e) => {
  const b = e.target.closest("[data-preset]");
  if (b) { mcpPreset(b.dataset.preset); sendMcp(); }
});
$("mcp-use-input").addEventListener("click", () => {
  let msg;
  try { msg = JSON.parse($("mcp-body").value); } catch { msg = null; }
  if (!msg || msg.method !== "tools/call" || !msg.params || !msg.params.arguments || !("text" in msg.params.arguments)) {
    msg = { jsonrpc: "2.0", id: mcpId++, ...tool("scan", {}) };
  }
  msg.params.arguments.text = input.value;
  $("mcp-body").value = JSON.stringify(msg, null, 2);
});
let mcpSeq = 0;
async function sendMcp() {
  if (!info) return;
  const seq = ++mcpSeq;
  try {
    const reply = await call("mcp", { message: $("mcp-body").value, settings: settingsKey() });
    if (seq !== mcpSeq) return; // a newer message was sent: show its reply only
    $("mcp-response").textContent = reply === null ? "(no reply: that was a notification)" : JSON.stringify(reply, null, 2);
  } catch (err) {
    if (seq !== mcpSeq) return;
    $("mcp-response").textContent = err.message;
  }
}
$("mcp-send").addEventListener("click", sendMcp);

// ---------------------------------------------------------------- CI gate
const CI_PRESETS = {
  leak: { name: "change.diff", text: `diff --git a/config/settings.py b/config/settings.py
index 3b18e51..a9c4f2d 100644
--- a/config/settings.py
+++ b/config/settings.py
@@ -12,6 +12,8 @@ DEBUG = False
 ALLOWED_HOSTS = ["api.internal.corp"]
 TIMEOUT_SECONDS = 30
+# temporary, for the billing migration
+STRIPE_SECRET_KEY = "sk_live_1234567890abcdefghijklmnop"
+GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
 LOG_LEVEL = "info"
` },
  clean: { name: "change.diff", text: `diff --git a/config/settings.py b/config/settings.py
index 3b18e51..7c0d2e9 100644
--- a/config/settings.py
+++ b/config/settings.py
@@ -12,6 +12,8 @@ DEBUG = False
 ALLOWED_HOSTS = ["api.internal.corp"]
 TIMEOUT_SECONDS = 30
+# secrets come from the environment, never from the repository
+STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
+GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
 LOG_LEVEL = "info"
` },
};
function ciPreset(name) {
  if (name === "input") {
    $("ci-input").value = input.value;
    $("ci-name").value = fileName;
  } else {
    $("ci-input").value = CI_PRESETS[name].text;
    $("ci-name").value = CI_PRESETS[name].name;
  }
  renderCiCommand();
  $("ci-verdict").replaceChildren(el("span", { className: "muted", textContent: "Run the gate to see the verdict." }));
  $("ci-output").textContent = "";
}
document.querySelectorAll("[data-ci]").forEach((b) => b.addEventListener("click", () => ciPreset(b.dataset.ci)));
const ciName = () => ($("ci-name").value.trim() || "change.diff").replace(/[\\/]/g, "_");
function ciArgv() {
  const fmt = document.querySelector('input[name="ci-format"]:checked').value;
  const argv = ["detect", ciName(), "--fail-on-detect"];
  if (fmt) argv.push(fmt);
  if (Object.keys(policy).length) argv.push("--config", "policy.toml");
  return argv;
}
function renderCiCommand() { $("ci-cmd").textContent = `safestream ${ciArgv().map(shq).join(" ")}`; }
$("ci-name").addEventListener("input", renderCiCommand);
document.querySelectorAll('input[name="ci-format"]').forEach((r) => r.addEventListener("change", renderCiCommand));
async function runGate() {
  if (!info) return;
  renderCiCommand();
  const files = { [ciName()]: $("ci-input").value };
  if (Object.keys(policy).length) files["policy.toml"] = toToml(policy);
  $("ci-verdict").replaceChildren(el("span", { className: "muted", textContent: "Running…" }));
  try {
    const r = await call("cli", { argv: ciArgv(), files });
    const m = r.stderr.match(/-- (\d+) detection/);
    let n = m ? Number(m[1]) : null;
    if (n === null && r.stdout.trim().startsWith("{\n")) { try { n = JSON.parse(r.stdout).runs[0].results.length; } catch { /* not SARIF */ } }
    if (n === null) n = r.stdout.split("\n").filter((l) => l.startsWith("{")).length;
    const verdict = r.exit === 0 ? ["pass", "PASS", "No findings. Exit code 0: the commit or CI job goes ahead."]
      : r.exit === 1 ? ["fail", "FAIL", `${n} finding${n === 1 ? "" : "s"}. Exit code 1: the commit or CI job is blocked.`]
      : ["fail", "ERROR", `Exit code ${r.exit}: the command was not run as intended.`];
    const v = el("div", { className: `verdict ${verdict[0]}` }, el("strong", { textContent: verdict[1] }), el("span", { textContent: verdict[2] }));
    $("ci-verdict").replaceChildren(v);
    $("ci-output").textContent = [r.stdout && `$ stdout\n${r.stdout}`, r.stderr && `$ stderr\n${r.stderr}`].filter(Boolean).join("\n") || "(no output)";
  } catch (err) {
    $("ci-verdict").replaceChildren(el("p", { className: "error", textContent: err.message }));
  }
}
$("ci-run").addEventListener("click", runGate);
function renderCiSnippets() {
  const v = info ? `v${info.version}` : "v0.5.0";
  const cfg = Object.keys(policy).length;
  $("ci-precommit").textContent = `# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MounishSenisetty/SafeStream-Redactor
    rev: ${v}
    hooks:
      - id: safestream-detect${cfg ? '\n        args: ["--config", "policy.toml"]' : ""}`;
  $("ci-action").textContent = `- uses: MounishSenisetty/SafeStream-Redactor@${v}
  with:
    paths: "."${cfg ? '\n    config: policy.toml' : ""}
    sarif-file: results.sarif        # optional
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif`;
  if ($("ci-cmd")) renderCiCommand();
}

// ---------------------------------------------------------------- install: chooser and local-only panels
const PATHS = [
  ["Sanitize files, directories or pipes", "CLI", "safestream redact app.log -o clean.log\nsafestream redact logs/ -o logs_clean/ --workers 8\ntail -f app.log | safestream redact - -o -", "playground", "Try the settings in the Playground; Run this yourself gives the command."],
  ["Redact inside my own application", "Python library", 'from safestream_redactor import Redactor\n\nredactor = Redactor()\nredactor.redact("email bob@corp.io, ssn: 123-45-6789")\nredactor.redact_file("app.log", "app.clean.log")', "playground", "Run this yourself → Python follows your settings."],
  ["Call it from another language or a container", "REST API", "safestream serve            # http://127.0.0.1:8000\ncurl -s -X POST http://127.0.0.1:8000/redact \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"text\": \"email bob@corp.io\"}'", "rest", "Try every endpoint in the REST API tab."],
  ["Give an AI agent a safe redaction tool", "MCP server", '{\n  "mcpServers": {\n    "safestream": { "command": "safestream", "args": ["mcp-serve"] }\n  }\n}', "mcp", "Send real JSON-RPC messages in the MCP server tab."],
  ["Try it without installing anything", "Live demo", "You are here.", "playground", "Back to the Playground."],
  ["Try it on my own large files, without code", "Local web playground", "pip install 'safestream-redactor[ui]'\nsafestream ui               # opens http://127.0.0.1:8501", null, "Uploads up to 2 GB, on loopback only."],
  ["Block secrets before they are committed or merged", "Pre-commit hook, GitHub Action", "safestream detect . --fail-on-detect", "ci", "Run the gate and copy the configuration in the CI gate tab."],
  ["Run it fully isolated", "Docker", 'docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD":/data \\\n    ghcr.io/mounishsenisetty/safestream-redactor redact /data/app.log -o /data/clean.log', null, "No network at all; docker-compose.yml adds a read-only filesystem and a 64 MiB memory cap."],
];
function buildChooser() {
  const box = $("chooser");
  PATHS.forEach(([want, use], i) => {
    const r = el("input", { type: "radio", name: "path", value: String(i), checked: i === 0 });
    box.append(el("label", { className: "choice" }, r, el("span", {}, el("strong", { textContent: want }), el("small", { textContent: use }))));
  });
  box.addEventListener("change", renderChoice);
  renderChoice();
}
function renderChoice() {
  const i = Number(document.querySelector('input[name="path"]:checked').value);
  const [, use, snippet, tab, note] = PATHS[i];
  const pre = el("pre", { className: "code", id: "chooser-snippet", textContent: snippet });
  const go = tab ? el("button", { type: "button", className: "btn small", textContent: `Open the ${$(`tab-${tab}`).textContent} tab` }) : null;
  if (go) go.dataset.goto = tab;
  const copy = el("button", { type: "button", className: "btn copy", textContent: "Copy" });
  copy.dataset.copy = "chooser-snippet";
  $("chooser-out").replaceChildren(el("p", {}, el("strong", { textContent: `Use: ${use}. ` }), note),
    el("div", { className: "snippet" }, pre, copy), go);
}
const LOCAL_ONLY = [
  ["Native Rust core", "3–12× faster, byte-identical output.", "pip install 'safestream-redactor[native]'\nsafestream redact huge.log -o clean.log --backend native"],
  ["Multi-core workers", "Directories fan out over files; one big file is split across cores. Output is byte-identical to one core.", "safestream redact logs/ -o logs_clean/ --workers 8\nsafestream redact huge.log -o clean.log --workers 8"],
  ["Kernel-enforced offline mode", "Linux only: a seccomp filter or an empty network namespace, on top of the in-process guard.", "safestream redact input.txt -o out.txt --offline-hard seccomp\nsafestream redact input.txt -o out.txt --offline-hard netns"],
  ["Names with spaCy", "Free-form person, organisation and location names.", "pip install 'safestream-redactor[ner]'\npython -m spacy download en_core_web_sm\nsafestream redact in.txt -o out.txt --ner"],
  ["On-device ONNX names", "A local token-classification model you supply; no data leaves the machine.", "pip install 'safestream-redactor[onnx]'\npython scripts/export_onnx.py --out models/ner\nsafestream redact in.txt -o out.txt --onnx models/ner/model.int8.onnx \\\n    --onnx-vocab models/ner/tokenizer.json --onnx-labels models/ner/labels.json"],
  ["Encrypt and restore", "Reversible AES-256-GCM tokens.", "pip install 'safestream-redactor[crypto]'\nexport SAFESTREAM_ENCRYPT_KEY='a secret of at least 16 bytes'\nsafestream redact app.log -o clean.log --mode encrypt\nsafestream deanonymize clean.log -o restored.log"],
  ["Memory budget", "Refuses a configuration that cannot fit (exit code 3).", "safestream redact huge.log -o clean.log --memory-limit 256MiB"],
  ["Local web playground", "This playground for files up to 2 GB, served on loopback with telemetry off.", "pip install 'safestream-redactor[ui]'\nsafestream ui"],
  ["File-system DLP (Linux)", "A daemon that logs, redacts or blocks files with secrets as they are written.", "sudo safestream fanotify --watch /srv/exports --mode audit"],
];
function buildLocalOnly() {
  $("local-only").replaceChildren(...LOCAL_ONLY.map(([title, what, cmd], i) => {
    const id = `lo-${i}`;
    const copy = el("button", { type: "button", className: "btn copy", textContent: "Copy" });
    copy.dataset.copy = id;
    return el("div", { className: "card local-only" },
      el("div", { className: "card-head" }, el("h3", { textContent: title }), el("span", { className: "tag", textContent: "local only" })),
      el("p", { className: "muted small", textContent: what }),
      el("div", { className: "snippet" }, el("pre", { className: "code", id, textContent: cmd }), copy));
  }));
}

// ---------------------------------------------------------------- guided tour
const TOUR = [
  { at: "local-badge", title: "Everything runs here", body: "The real package runs in this tab. This counter shows network requests since the engine started. It stays at 0." },
  { at: "samples", title: "Pick some text", body: "Choose a sample, type or paste your own, or drop a file onto the input box." },
  { at: "output", title: "See what was found", body: "Each finding is coloured by type. Hover or focus one to find its row in the Findings table, and the other way round." },
  { at: "mode-group", title: "Choose how values are rewritten", body: "Replace, mask, pseudonymize, hash or fictionalize. The output updates as you change it.", rail: true },
  { at: "copy-out", title: "Copy or download", body: "Take the redacted text with you. Check determinism re-runs it four ways and compares the bytes." },
  { at: "run-card", title: "Run it yourself", body: "The same settings as a command, Python, REST and MCP. Run this command here proves the command gives the same bytes." },
];
let tourAt = -1;
let tourPrevFocus = null;
function startTour() {
  tourPrevFocus = document.activeElement;
  goTo("playground");
  tourAt = 0;
  showTourStep();
}
function endTour(done = true) {
  if (tourAt < 0) return;
  document.querySelectorAll(".tour-target").forEach((n) => n.classList.remove("tour-target"));
  $("tour").hidden = true;
  tourAt = -1;
  if (done) store.set("tour", "done");
  $("tour-btn").textContent = "Take the tour again";
  if (tourPrevFocus && tourPrevFocus.focus) tourPrevFocus.focus();
}
function showTourStep() {
  const s = TOUR[tourAt];
  document.querySelectorAll(".tour-target").forEach((n) => n.classList.remove("tour-target"));
  if (s.rail && narrow.matches) $("rail").open = true;
  const target = $(s.at);
  target.classList.add("tour-target");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  // the header is sticky: for a target there, show the top of the page instead
  if (target.closest(".topbar")) scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
  else target.scrollIntoView({ block: "center", behavior: reduce ? "auto" : "smooth" });
  $("tour-step").textContent = `Step ${tourAt + 1} of ${TOUR.length}`;
  $("tour-title").textContent = s.title;
  $("tour-body").textContent = s.body;
  $("tour-back").disabled = tourAt === 0;
  $("tour-next").textContent = tourAt === TOUR.length - 1 ? "Finish" : "Next";
  const box = $("tour");
  box.hidden = false;
  const place = () => {
    const r = target.getBoundingClientRect();
    const w = Math.min(340, innerWidth - 24);
    box.style.width = `${w}px`;
    const h = box.offsetHeight;
    let top = r.bottom + 10;
    if (top + h > innerHeight - 8) top = Math.max(8, r.top - h - 10);
    if (top < 8 || top + h > innerHeight) top = innerHeight - h - 12;
    box.style.top = `${top + scrollY}px`;
    box.style.left = `${Math.max(12, Math.min(r.left, innerWidth - w - 12)) + scrollX}px`;
  };
  place();
  setTimeout(place, reduce ? 0 : 400);
  $("tour-next").focus({ preventScroll: true });
}
$("tour-btn").addEventListener("click", startTour);
$("tour-next").addEventListener("click", () => { if (tourAt === TOUR.length - 1) endTour(); else { tourAt++; showTourStep(); } });
$("tour-back").addEventListener("click", () => { if (tourAt > 0) { tourAt--; showTourStep(); } });
$("tour-skip").addEventListener("click", () => endTour());
addEventListener("resize", () => { if (tourAt >= 0) showTourStep(); });

// ---------------------------------------------------------------- help and shortcuts
const help = $("help");
const openHelp = () => { if (!help.open) help.showModal(); };
$("help-btn").addEventListener("click", openHelp);
$("help-close").addEventListener("click", () => help.close());
$("help-tour").addEventListener("click", () => { help.close(); startTour(); });
help.addEventListener("click", (e) => { if (e.target === help) help.close(); });

function runActive() {
  const id = activeTab().id;
  if (id === "tab-playground") runAnalyze();
  else if (id === "tab-inspector") loadTrace();
  else if (id === "tab-rest") sendRest();
  else if (id === "tab-mcp") sendMcp();
  else if (id === "tab-ci") runGate();
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && tourAt >= 0) { endTour(); return; }
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); runActive(); return; }
  if (e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target) || help.open) return;
  if (/^[1-7]$/.test(e.key)) { main.select(main.tabs[Number(e.key) - 1], true); return; }
  const action = { c: copyOutput, d: downloadOutput, v: toggleReveal, t: toggleTheme, "?": openHelp }[e.key];
  if (action) { e.preventDefault(); action(); }
});

// ---------------------------------------------------------------- start
$("csp-text").textContent = document.querySelector('meta[http-equiv="Content-Security-Policy"]').content.split("; ").join(";\n");
$("boot-note").textContent = "About 14 MB, downloaded once from this site. You can read and explore while it loads.";
initTerms();
buildSamples();
buildChooser();
buildLocalOnly();
buildModes();
form.elements.hmac_key.value = randomKey();
restDefaults();
mcpPreset("scan");
renderCiSnippets();
const initial = readHash();
loadSample(initial.sample || "log");
if (initial.tab && $(`tab-${initial.tab}`)) main.select($(`tab-${initial.tab}`));
controlsToPolicy();
showModeFields();
renderToml();
renderSnippets();
readyForHash = true;
if (!store.get("tour")) $("tour-btn").classList.add("pulse");
else $("tour-btn").textContent = "Take the tour again";

startEngine()
  .then((result) => {
    info = result;
    $("version").textContent = `v${info.version}`;
    $("py-version").textContent = `Python ${info.python}`;
    buildModes();
    buildTypeList(info.pattern_types);
    readHash(); // the hash may name types, which exist only now
    controlsToPolicy();
    settingsChanged();
    $("boot-fill").style.width = "100%";
    $("boot").hidden = true;
    watchPageRequests();
    document.body.dataset.ready = "true"; // for the smoke test
    runAnalyze();
    if (activeTab().id === "tab-inspector") loadTrace();
    if (activeTab().id === "tab-ci") runGate();
    if (activeTab().id === "tab-rest") sendRest();
    if (activeTab().id === "tab-mcp") sendMcp();
    if (!store.get("tour") && matchMedia("(min-width: 600px)").matches) startTour();
  })
  .catch((err) => bootFailed(err.message));
