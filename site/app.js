// SafeStream Redactor demo page. All detection runs in engine.js (a Web Worker
// running the real Python package); this file only collects input and draws results.
// Text from the user is always inserted with textContent / DOM nodes, never as HTML.

const $ = (id) => document.getElementById(id);
const MAX_BYTES = 1024 * 1024; // the demo's cap; the CLI streams files of any size
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

// ---------------------------------------------------------------- theme
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};
const savedTheme = store.get("theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
$("theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  store.set("theme", next);
});

// ---------------------------------------------------------------- engine
// The worker is started from a blob: URL so it inherits this page's CSP.
let nextId = 1;
const pending = new Map();
let worker;
let info = null;

async function startEngine() {
  const base = new URL(".", location.href).href;
  const source = await (await fetch("engine.js")).text();
  worker = new Worker(URL.createObjectURL(new Blob([source], { type: "text/javascript" })), {
    type: "module",
  });
  worker.onmessage = ({ data }) => {
    if (data.progress) return bootProgress(data.progress);
    const p = pending.get(data.id);
    pending.delete(data.id);
    if (p) data.ok ? p.resolve(data.result) : p.reject(new Error(data.error));
  };
  worker.onerror = (e) => bootFailed(e.message || "the engine could not start");
  return call("init", { base });
}

function call(op, args) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });
}

const STAGES = ["Loading the Python runtime", "Loading SafeStream", "Starting the engine"];
function bootProgress(stage) {
  $("boot-text").textContent = stage + "…";
  $("boot-fill").style.width = `${((STAGES.indexOf(stage) + 1) / (STAGES.length + 1)) * 100}%`;
}
function bootFailed(msg) {
  $("boot").classList.add("failed");
  $("boot-text").textContent = `The engine could not start: ${msg}. Reload the page to try again.`;
}

// ---------------------------------------------------------------- settings
const form = $("settings");
let typeBoxes = [];

function buildTypeList(types) {
  const list = $("types-list");
  list.replaceChildren(...types.map((t) => {
    const label = document.createElement("label");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.value = t;
    box.checked = true;
    label.append(box, t);
    return label;
  }));
  typeBoxes = [...list.querySelectorAll("input")];
  updateTypeCount();
}
function updateTypeCount() {
  const n = typeBoxes.filter((b) => b.checked).length;
  $("types-count").textContent = n === typeBoxes.length ? "(all)" : `(${n} of ${typeBoxes.length})`;
}
form.addEventListener("click", (e) => {
  const which = e.target.dataset && e.target.dataset.types;
  if (!which) return;
  typeBoxes.forEach((b) => { b.checked = which === "all"; });
  updateTypeCount();
  settingsChanged();
});

function randomKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
form.elements.hash_key.value = randomKey();

function readSettings() {
  const f = form.elements;
  const chosen = typeBoxes.filter((b) => b.checked).map((b) => b.value);
  return {
    style: f.style.value,
    replacement: f.replacement.value,
    keep_last: Number(f.keep_last.value) || 0,
    hash_key: f.hash_key.value,
    min_confidence: Number(f.min_confidence.value),
    use_entropy: f.use_entropy.checked,
    use_names: f.use_names.checked,
    types: chosen.length === typeBoxes.length ? null : chosen,
    custom_words: f.custom_words.value,
    custom_patterns: f.custom_patterns.value,
  };
}
// the engine caches one redactor per distinct settings string
const settingsKey = () => JSON.stringify(readSettings());

function showStyleFields() {
  const style = form.elements.style.value;
  form.querySelectorAll("[data-for]").forEach((el) => { el.hidden = el.dataset.for !== style; });
}

let settingsTimer;
function settingsChanged() {
  showStyleFields();
  $("conf-out").textContent = Number(form.elements.min_confidence.value).toFixed(2);
  updateTypeCount();
  clearTimeout(settingsTimer);
  settingsTimer = setTimeout(() => {
    analyze();
    if (!$("panel-inspector").hidden) loadTrace();
  }, 250);
}
form.addEventListener("input", settingsChanged);
form.addEventListener("submit", (e) => e.preventDefault());

function settingsError(err) {
  const el = $("settings-error");
  el.hidden = !err;
  el.textContent = err ? err.message : "";
}

// ---------------------------------------------------------------- samples
const SAMPLES = {
  log: {
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
  env: {
    hint: "Credentials, including a secret with no known format (found by entropy).",
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
  ticket: {
    hint: "Prose. Turn on Name heuristics in Settings to catch the customer's name too.",
    text: `Ticket #48213: refund request
From: Daniel Okafor <daniel.okafor@corpmail.com>
Phone: (415) 555-0172
Date of birth: 14/03/1987
Account number: 004417829
Shipping address: 742 Evergreen Terrace, Springfield, OR 97403

Hi team, I was charged twice on my card. The full number is 4242 4242 4242 4242
and my SSN is 512-44-8372 if you need to verify me. Please refund to the same card.
Thanks, Daniel
`,
  },
};

function loadSample(name) {
  $("input").value = SAMPLES[name].text;
  $("sample-hint").textContent = SAMPLES[name].hint;
  fileName = "sample.txt";
  analyze();
}
$("sample").addEventListener("change", (e) => loadSample(e.target.value));

// ---------------------------------------------------------------- upload
let fileName = "sample.txt";
$("upload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  if (file.size > MAX_BYTES) {
    toast(`${file.name} is ${(file.size / 1048576).toFixed(1)} MiB. The demo takes up to 1 MiB; the CLI streams files of any size.`);
    return;
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.subarray(0, 8192).includes(0)) {
    toast(`${file.name} looks like a binary file. Open a text file instead.`);
    return;
  }
  $("input").value = new TextDecoder().decode(bytes);
  $("sample-hint").textContent = `Scanning ${file.name}, locally.`;
  fileName = file.name;
  analyze();
});

// ---------------------------------------------------------------- playground
let last = null; // {text, result}
let analyzeTimer;
$("input").addEventListener("input", () => {
  clearTimeout(analyzeTimer);
  analyzeTimer = setTimeout(analyze, 300);
});

let analyzeSeq = 0;
async function analyze() {
  if (!info) return;
  const text = $("input").value;
  const bytes = new TextEncoder().encode(text).length;
  $("input-size").textContent = `${bytes.toLocaleString()} bytes`;
  if (bytes > MAX_BYTES) {
    toast("The demo takes up to 1 MiB of text. Use the CLI for larger files.");
    return;
  }
  const seq = ++analyzeSeq;
  try {
    const result = await call("analyze", { text, settings: settingsKey() });
    if (seq !== analyzeSeq) return; // a newer edit superseded this one
    settingsError(null);
    last = { text, result };
    renderPlayground();
  } catch (err) {
    if (seq === analyzeSeq) settingsError(err);
  }
  renderSnippets();
}

function highlighted(text, findings, start = 0, end = text.length) {
  // DOM nodes for text[start:end] with each finding wrapped in a <mark>
  const frag = document.createDocumentFragment();
  let cursor = start;
  for (const f of findings) {
    if (f.end <= start || f.start >= end) continue;
    const s = Math.max(f.start, start);
    const e = Math.min(f.end, end);
    if (s > cursor) frag.append(text.slice(cursor, s));
    const mark = document.createElement("mark");
    mark.dataset.sev = f.severity;
    mark.title = `${f.type} · ${f.severity}${f.confidence !== undefined ? ` · ${f.confidence.toFixed(2)}` : ""}`;
    mark.textContent = text.slice(s, e);
    frag.append(mark);
    cursor = e;
  }
  if (cursor < end) frag.append(text.slice(cursor, end));
  return frag;
}

function redactedNodes(text, findings, start = 0, end = text.length) {
  // DOM nodes for text[start:end] with each finding replaced, the replacement marked
  const frag = document.createDocumentFragment();
  let cursor = start;
  for (const f of findings) {
    if (f.start < start || f.start >= end) continue;
    if (f.start > cursor) frag.append(text.slice(cursor, f.start));
    const mark = document.createElement("mark");
    mark.dataset.sev = f.severity;
    mark.title = `${f.type} · ${f.severity}`;
    mark.textContent = f.replacement;
    frag.append(mark);
    cursor = f.end;
  }
  if (cursor < end) frag.append(text.slice(cursor, end));
  return frag;
}

function renderPlayground() {
  if (!last) return;
  const { text, result } = last;
  const f = result.findings;
  const types = new Set(f.map((x) => x.type));
  const worst = f.reduce((w, x) => (SEV_ORDER[x.severity] > SEV_ORDER[w] ? x.severity : w), "low");
  $("m-findings").textContent = f.length;
  $("m-types").textContent = types.size;
  $("m-severity").replaceChildren(f.length ? severityBadge(worst) : "none");
  $("m-chars").textContent = text.length.toLocaleString();
  $("m-time").textContent = `${result.ms} ms`;

  const view = document.querySelector('input[name="view"]:checked').value;
  $("output").replaceChildren(view === "redacted" ? redactedNodes(text, f) : highlighted(text, f));
  renderFindings();
}
document.querySelectorAll('input[name="view"]').forEach((r) => r.addEventListener("change", renderPlayground));

function severityBadge(sev) {
  const s = document.createElement("span");
  s.className = "sev";
  s.dataset.sev = sev;
  s.textContent = sev;
  return s;
}

function renderFindings() {
  const body = $("findings").tBodies[0];
  const reveal = $("reveal").checked;
  const { text, result } = last;
  if (!result.findings.length) {
    const td = document.createElement("td");
    td.colSpan = 6;
    td.className = "empty";
    td.textContent = "Nothing detected with the current settings.";
    body.replaceChildren(document.createElement("tr"));
    body.rows[0].append(td);
    return;
  }
  body.replaceChildren(...result.findings.map((f) => {
    const tr = document.createElement("tr");
    const cells = [
      severityBadge(f.severity),
      f.type,
      `${f.line}:${f.column}`,
      f.confidence.toFixed(2),
      f.detector,
    ];
    for (const c of cells) {
      const td = document.createElement("td");
      td.append(c);
      tr.append(td);
    }
    tr.children[2].className = tr.children[3].className = "num";
    const value = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = reveal ? text.slice(f.start, f.end) : "•".repeat(Math.min(12, f.end - f.start));
    value.append(code);
    tr.append(value);
    return tr;
  }));
}
$("reveal").addEventListener("change", () => last && renderFindings());

// ---------------------------------------------------------------- copy, download, toast
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    toast("Copy is blocked in this browser. Select the text and copy it instead.");
  }
}
document.addEventListener("click", (e) => {
  const id = e.target.dataset && e.target.dataset.copy;
  if (id) copyText($(id).textContent);
});
$("copy-out").addEventListener("click", () => last && copyText(last.result.redacted));
$("download-out").addEventListener("click", () => {
  if (!last) return;
  const url = URL.createObjectURL(new Blob([last.result.redacted], { type: "text/plain" }));
  const a = document.createElement("a");
  const dot = fileName.lastIndexOf(".");
  a.href = url;
  a.download = dot > 0 ? `${fileName.slice(0, dot)}.redacted${fileName.slice(dot)}` : `${fileName}.redacted`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// ---------------------------------------------------------------- snippets
const shq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
const pyq = (s) => JSON.stringify(s);
const rules = (block) => [...new Set(block.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")))];

function renderSnippets() {
  const s = readSettings();
  const cli = ["safestream redact app.log -o clean.log"];
  const py = [];
  const policy = [];
  if (s.types) { cli.push(`--types ${s.types.join(",") || "''"}`); py.push(`types=${pyq(s.types)}`); }
  if (s.min_confidence !== 0.5) { cli.push(`--min-confidence ${s.min_confidence}`); py.push(`min_confidence=${s.min_confidence}`); }
  if (!s.use_entropy) { cli.push("--no-entropy"); py.push("use_entropy=False"); }
  for (const w of rules(s.custom_words)) cli.push(`--custom-word ${shq(w)}`);
  for (const r of rules(s.custom_patterns)) cli.push(`--custom-regex ${shq(r)}`);
  if (rules(s.custom_words).length) py.push(`custom_words=${pyq(rules(s.custom_words))}`);
  if (rules(s.custom_patterns).length) py.push(`custom_patterns=[${rules(s.custom_patterns).map((r) => `r${pyq(r)}`).join(", ")}]`);
  if (s.use_names) { py.push("use_gazetteer=True", "use_ensemble=True"); policy.push("use_gazetteer = true", "use_ensemble = true"); }
  if (s.style === "mask") {
    cli.push(`--mode mask --keep-last ${s.keep_last}`);
    py.push(`policy=RedactionPolicy(mode="mask", mask_keep_last=${s.keep_last})`);
  } else if (s.style === "hash") {
    cli.push('--mode pseudonymize --hmac-key "$SAFESTREAM_KEY"');
    py.push('policy=RedactionPolicy(mode="pseudonymize", hmac_key=os.environ["SAFESTREAM_KEY"])');
  } else if (s.replacement !== "[REDACTED]") {
    cli.push(`--replace ${shq(s.replacement)}`);
    py.push(`policy=RedactionPolicy(replacement=${pyq(s.replacement)})`);
  }
  let cliText = cli.join(" \\\n    ");
  if (policy.length) {
    cliText = `# name heuristics have no flag: put these under [detection] in policy.toml\n# ${policy.join("\n# ")}\n${cliText} \\\n    --config policy.toml`;
  }
  $("cli-snippet").textContent = cliText;
  const imports = py.some((p) => p.startsWith("policy=")) ? "Redactor, RedactionPolicy" : "Redactor";
  const head = s.style === "hash" ? "import os\n\n" : "";
  const args = py.length ? `\n    ${py.join(",\n    ")},\n` : "";
  $("py-snippet").textContent = `${head}from safestream_redactor import ${imports}\n\nredactor = Redactor(${args})\nredactor.redact_file("app.log", "clean.log")`;
}

// ---------------------------------------------------------------- tabs
const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectTab(tab) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute("aria-selected", on);
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute("aria-controls")).hidden = !on;
  }
  if (tab.id === "tab-inspector") loadTrace();
  if (tab.id !== "tab-inspector") pause();
}
tabs.forEach((t, i) => {
  t.addEventListener("click", () => selectTab(t));
  t.addEventListener("keydown", (e) => {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (e.key === "Home" || e.key === "End" || step) {
      e.preventDefault();
      const next = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + step + tabs.length) % tabs.length;
      tabs[next].focus();
      selectTab(tabs[next]);
    }
  });
});

// settings rail: always open on wide screens, a collapsible section on narrow ones
const narrow = matchMedia("(max-width: 900px)");
const syncRail = () => { $("rail").open = !narrow.matches; };
narrow.addEventListener("change", syncRail);
syncRail();

// ---------------------------------------------------------------- inspector
let longLog = null;
function makeLongLog() {
  // ~60 KB of log with secrets throughout, including long tokens that chunk
  // boundaries will cut, so the engine has to retreat and keep them whole
  let seed = 7;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  const users = ["maria.garcia", "d.okafor", "li.wei", "a.novak", "s.iyer"];
  const lines = [];
  for (let i = 0; lines.join("\n").length < 60000; i++) {
    const ts = `2026-11-02T${String(9 + Math.floor(i / 3600) % 12).padStart(2, "0")}:${String(Math.floor(i / 60) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`;
    const kind = rnd(9);
    const u = users[rnd(users.length)];
    if (kind === 0) lines.push(`${ts} INFO  auth    login ok user=${u}@corpmail.com ip=10.${rnd(250)}.${rnd(250)}.${rnd(250)}`);
    else if (kind === 1) lines.push(`${ts} WARN  billing card=4111 1111 1111 1111 ssn=123-45-6789 retry=${rnd(5)}`);
    else if (kind === 2) lines.push(`${ts} DEBUG session jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNzMwNTQwMDAwfQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`);
    else if (kind === 3) lines.push(`${ts} DEBUG deploy  aws_key=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghijklmnopqrstuvwxyz`);
    else lines.push(`${ts} INFO  api     GET /v1/orders/${10000 + rnd(90000)} 200 in ${rnd(90) + 3} ms`);
  }
  return lines.join("\n") + "\n";
}

let trace = null;
let pos = 0;
let timer = null;
let traceSeq = 0;

async function loadTrace() {
  if (!info) return;
  const useInput = document.querySelector('input[name="isrc"]:checked').value === "input";
  const text = useInput ? $("input").value : (longLog ??= makeLongLog());
  const chunkSel = $("ichunk");
  const chunk = Number(chunkSel.value) || 0;
  const seq = ++traceSeq;
  pause();
  try {
    const result = await call("trace", { text, settings: settingsKey(), chunk: chunk || 8192 });
    if (seq !== traceSeq) return;
    if (!chunkSel.options.length || chunkSel.dataset.sizes !== result.sizes.join()) {
      chunkSel.dataset.sizes = result.sizes.join();
      chunkSel.replaceChildren(...result.sizes.map((n, i) => new Option(`${n.toLocaleString()} chars (${i + 1}× overlap)`, n)));
      chunkSel.value = String(result.chunk);
    }
    trace = { text, ...result };
    pos = 0;
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
    const bar = document.createElement("span");
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
  $("t-done").style.width = pct(p.emit[0]);
  const win = $("t-win");
  win.style.left = pct(p.window[0]);
  win.style.width = pct(p.window[1] - p.window[0]);
  const span = p.window[1] - p.window[0] || 1;
  $("t-ctx").style.width = `${((p.emit[0] - p.window[0]) / span) * 100}%`;
  $("t-emit").style.width = `${((p.emit[1] - p.emit[0]) / span) * 100}%`;
  $("t-carry").style.width = `${((p.window[1] - p.emit[1]) / span) * 100}%`;
  [...$("bars").children].forEach((b, i) => b.classList.toggle("on", i === pos));

  const notes = [];
  if (p.retreated_by) notes.push(["warn", `The planned boundary at ${p.planned_end.toLocaleString()} would have cut an entity in two, so it moved back ${p.retreated_by} characters (red dashed line). The next pass writes the entity whole.`]);
  if (p.straddlers.length) notes.push(["", `Held back by the previous pass and written whole here: ${p.straddlers.join(", ")}.`]);
  if (p.deferred) notes.push(["", `${p.deferred} earlier pass(es) wrote nothing: a detection covered the whole planned segment, so the engine read more text first.`]);
  $("inotes").replaceChildren(...notes.map(([cls, msg]) => {
    const d = document.createElement("div");
    d.className = `note ${cls}`;
    d.textContent = msg;
    return d;
  }));

  // the scanned window: context | emitted | (actual cut, planned cut) carried
  const all = passes.flatMap((x) => x.findings);
  const win_ = document.createDocumentFragment();
  const band = (cls, s, e) => {
    const el = document.createElement("span");
    el.className = cls;
    el.append(highlighted(text, all, s, e));
    return el;
  };
  if (p.emit[0] > p.window[0]) win_.append(band("b-ctx", p.window[0], p.emit[0]));
  win_.append(band("b-emit", p.emit[0], p.emit[1]));
  const cut = document.createElement("span");
  cut.className = "cut";
  cut.title = "where this pass stopped writing";
  win_.append(cut);
  if (p.window[1] > p.emit[1]) {
    const carry = band("b-carry", p.emit[1], p.window[1]);
    if (p.retreated_by) {
      // the planned cut sits inside the carried text
      const planned = document.createElement("span");
      planned.className = "planned";
      planned.title = "planned boundary: it would have cut an entity";
      const at = p.planned_end;
      carry.replaceChildren(highlighted(text, all, p.emit[1], at), planned, highlighted(text, all, at, p.window[1]));
    }
    win_.append(carry);
  }
  $("iwindow").replaceChildren(win_);
  // open the pane where this pass starts writing, not at the dim context above it
  const emitted = $("iwindow").querySelector(".b-emit");
  $("iwindow").scrollTop = Math.max(0, emitted.offsetTop - 48);
  $("isegment").replaceChildren(redactedNodes(text, p.findings, p.emit[0], p.emit[1]));
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

// ---------------------------------------------------------------- REST console
const REST_TEXT = "email bob@corp.io key AKIAIOSFODNN7EXAMPLE";
function restDefaults() {
  const [method] = $("rest-route").value.split(" ");
  $("rest-body").value = method === "POST" ? JSON.stringify({ text: REST_TEXT }, null, 2) : "";
  $("rest-body").disabled = method !== "POST";
  renderCurl();
}
function renderCurl() {
  const [method, path] = $("rest-route").value.split(" ");
  let cmd = `curl -s ${method === "POST" ? "-X POST " : ""}http://127.0.0.1:8000${path}`;
  if (method === "POST") {
    let body = $("rest-body").value;
    try { body = JSON.stringify(JSON.parse(body)); } catch { /* send as typed */ }
    cmd += ` \\\n  -H 'Content-Type: application/json' \\\n  -d ${shq(body)}`;
  }
  $("rest-curl").textContent = `# with \`safestream serve\` running locally\n${cmd}`;
}
$("rest-route").addEventListener("change", restDefaults);
$("rest-body").addEventListener("input", renderCurl);
$("rest-send").addEventListener("click", async () => {
  const [method, path] = $("rest-route").value.split(" ");
  const status = $("rest-status");
  try {
    const r = await call("rest", { method, path, body: method === "POST" ? $("rest-body").value : "", settings: settingsKey() });
    status.textContent = `${r.status}`;
    status.className = `status ${r.status < 400 ? "ok" : "err"}`;
    $("rest-response").textContent = JSON.stringify(r.body, null, 2);
  } catch (err) {
    status.textContent = "error";
    status.className = "status err";
    $("rest-response").textContent = err.message;
  }
});

// ---------------------------------------------------------------- MCP console
const MCP_TEXT = "deploy key AKIAIOSFODNN7EXAMPLE, notify maria.garcia@corpmail.com";
let mcpId = 1;
const MCP_PRESETS = {
  initialize: () => ({ method: "initialize", params: { protocolVersion: "2024-11-05", clientInfo: { name: "demo", version: "1" } } }),
  list: () => ({ method: "tools/list" }),
  scan: () => ({ method: "tools/call", params: { name: "scan", arguments: { text: MCP_TEXT } } }),
  redact: () => ({ method: "tools/call", params: { name: "redact", arguments: { text: MCP_TEXT } } }),
  explain: () => ({ method: "tools/call", params: { name: "explain_detection", arguments: { text: MCP_TEXT } } }),
};
function mcpPreset(name) {
  $("mcp-body").value = JSON.stringify({ jsonrpc: "2.0", id: mcpId++, ...MCP_PRESETS[name]() }, null, 2);
}
$("mcp-presets").addEventListener("click", (e) => {
  const name = e.target.dataset && e.target.dataset.preset;
  if (name) { mcpPreset(name); $("mcp-send").click(); }
});
$("mcp-send").addEventListener("click", async () => {
  try {
    const reply = await call("mcp", { message: $("mcp-body").value, settings: settingsKey() });
    $("mcp-response").textContent = reply === null ? "(no reply: that was a notification)" : JSON.stringify(reply, null, 2);
  } catch (err) {
    $("mcp-response").textContent = err.message;
  }
});

// ---------------------------------------------------------------- start
showStyleFields();
restDefaults();
mcpPreset("scan");
$("input").value = SAMPLES.log.text;
$("sample-hint").textContent = SAMPLES.log.hint;
renderSnippets();
startEngine()
  .then((result) => {
    info = result;
    $("version").textContent = `v${info.version}`;
    buildTypeList(info.pattern_types);
    $("boot-fill").style.width = "100%";
    $("boot").hidden = true;
    document.body.dataset.ready = "true"; // for the smoke test
    analyze();
  })
  .catch((err) => bootFailed(err.message));
