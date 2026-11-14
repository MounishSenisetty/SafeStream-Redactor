// Browser smoke test for the demo site:  node site/smoke.mjs http://127.0.0.1:8642/ [shot.png]
//
// Exercises every tab and control in a real browser against the real engine. Fails
// if the engine does not start, if any feature answers wrongly, if user text ever
// reaches the address bar, if any request leaves the page's origin, or if the
// browser reports a CSP violation or a console error.
import { createRequire } from "node:module";

// require(): resolves a global or a local `npm install playwright` alike
const { chromium } = createRequire(import.meta.url)("playwright");

const url = process.argv[2];
const origin = new URL(url).origin;
const problems = [];
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) problems.push(what);
};
const text = (sel) => page.textContent(sel);
const until = (fn, arg, timeout = 30_000) => page.waitForFunction(fn, arg, { timeout });
// the radios are visually replaced by their labels; scroll the rail to them first
const pickMode = async (mode) => {
  await page.$eval(`input[name="mode"][value="${mode}"]`, (n) => n.closest("label").scrollIntoView({ block: "center" }));
  await page.check(`input[name="mode"][value="${mode}"]`, { force: true });
};

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
await context.grantPermissions(["clipboard-read", "clipboard-write"]);
const page = await context.newPage();
const offsite = [];
page.on("request", (r) => {
  const u = new URL(r.url());
  if (!["blob:", "data:"].includes(u.protocol) && u.origin !== origin) offsite.push(r.url());
});
const errors = [];
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("pageerror", (e) => errors.push(String(e)));
await page.addInitScript(() => {
  document.addEventListener("securitypolicyviolation", (e) => {
    console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`);
  });
});
// every address the page ever shows, to prove no user text reaches it
const addresses = [];
await page.exposeFunction("__address", (a) => addresses.push(a));
await page.addInitScript(() => {
  const report = () => window.__address && window.__address(location.href);
  for (const fn of ["replaceState", "pushState"]) {
    const orig = history[fn].bind(history);
    history[fn] = (...args) => { const r = orig(...args); report(); return r; };
  }
  addEventListener("hashchange", report);
});

// Chrome's own log also carries what workers trigger (a CSP refusal inside the engine's
// worker never reaches the page's console or its securitypolicyviolation listener)
const cdp = await page.context().newCDPSession(page);
await cdp.send("Log.enable");
cdp.on("Log.entryAdded", ({ entry }) => {
  if (entry.level === "error") errors.push(`[${entry.source}] ${entry.text}`);
});

const started = Date.now();
await page.goto(url);
check(await page.isVisible("#hero-title"), "hero is readable while the engine boots");
await page.waitForSelector("body[data-ready=true]", { timeout: 90_000 });
console.log(`     engine ready in ${((Date.now() - started) / 1000).toFixed(1)} s`);
await until(() => document.querySelector("#m-findings").textContent !== "–");

// --- guided tour: opens by itself on a first visit, steps, and is remembered
await page.waitForSelector("#tour:not([hidden])", { timeout: 5000 }).catch(() => {});
check(await page.isVisible("#tour"), "the tour opens on a first visit");
check((await text("#tour-step")).includes("1 of 6"), "tour shows step 1 of 6");
await page.click("#tour-next");
check((await text("#tour-step")).includes("2 of 6"), "tour steps forward");
await page.keyboard.press("Escape");
check(!(await page.isVisible("#tour")), "Escape closes the tour");
check(await page.evaluate(() => localStorage.getItem("tour")) === "done", "tour completion is remembered");

// --- playground: the sample log is redacted on load
const out = await text("#output");
check(out.includes("user=[REDACTED]") && !out.includes("AKIAIOSFODNN7EXAMPLE"), "sample log is redacted on load");
check(Number(await text("#m-findings")) >= 9, "sample log has at least 9 findings");
check(/^v\d+\.\d+/.test(await text("#version")), "version is shown");
check((await text("#findings tbody")).includes("aws_key"), "findings table lists aws_key");
check((await page.$$("#backdrop mark")).length >= 9, "input box highlights the findings");
check((await text("#type-counts")).includes("email"), "counts by type are shown");
check((await text("#legend")).includes("Credentials"), "colour key pairs colours with labels");

// matched values hidden by default, revealed on demand
check(!(await text("#findings tbody")).includes("AKIA"), "matched values are hidden by default");
await page.keyboard.press("v");
check((await text("#findings tbody")).includes("AKIAIOSFODNN7EXAMPLE"), "'v' reveals matched values");
await page.click("#reveal");

// sorting and filtering
await page.click('th button[data-sort="severity"]');
check((await page.textContent("#findings tbody tr:first-child td:first-child")) === "critical", "sort by severity puts critical first");
check(await page.getAttribute('th:has(button[data-sort="severity"])', "aria-sort") === "descending", "sorted column has aria-sort");
await page.click('#type-counts [data-type="email"]');
check((await page.$$("#findings tbody tr")).length === 1, "a type chip filters the table");
await page.click("#f-clear");
await page.selectOption("#f-sev", "critical");
check((await page.$$("#findings tbody tr")).length === 3, "severity filter keeps the 3 critical findings");
await page.click("#f-clear");

// a highlight and its row are linked, both ways
await page.hover('#output mark[data-i="0"]');
check(await page.$eval('#findings tr[data-i="0"]', (n) => n.classList.contains("linked")), "hovering a highlight marks its row");
await page.mouse.move(0, 0);
await page.focus('#findings tr[data-i="3"] .jump');
check(await page.$eval('#output mark[data-i="3"]', (n) => n.classList.contains("linked")), "focusing a row marks its highlight");
await page.click('#findings tr[data-i="3"] .jump');
check(await page.evaluate(() => document.activeElement.matches('#output mark[data-i="3"]')), "a row's button moves focus to its highlight");
await page.keyboard.press("ArrowRight");
check(await page.evaluate(() => document.activeElement.matches('#output mark[data-i="4"]')), "arrow keys move between findings");

// every sample, the clean one with no findings
const samples = await page.$$eval("#samples [data-sample]", (bs) => bs.map((b) => b.dataset.sample));
check(samples.length === 7, `seven one-click samples (${samples.join(", ")})`);
for (const s of samples) {
  await page.click(`#samples [data-sample="${s}"]`);
  await until(() => !document.body.classList.contains("busy") && document.querySelector("#output").textContent.length > 0);
  await page.waitForTimeout(150);
  const n = Number(await text("#m-findings"));
  check(s === "clean" ? n === 0 : n >= 3, `sample ${s}: ${n} findings`);
}
check((await text("#output-note")).includes("as expected"), "the clean sample explains its empty result");
await page.click('#samples [data-sample="log"]');
await until(() => document.querySelector("#m-findings").textContent === "10");

// drag and drop a file onto the input
await page.evaluate(() => {
  const dt = new DataTransfer();
  dt.items.add(new File(["dropped mail bob@corp.io\n"], "dropped.txt", { type: "text/plain" }));
  const ed = document.getElementById("editor");
  ed.dispatchEvent(new DragEvent("dragenter", { dataTransfer: dt, bubbles: true }));
  ed.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
});
await until(() => document.querySelector("#output").textContent.includes("dropped mail [REDACTED]"));
check(true, "a dropped file is read and redacted");

// live as you type, and the address never carries the text
const marker = "zq-live-marker";
await page.fill("#input", `token for ${marker}: AKIAIOSFODNN7EXAMPLE and bob@corp.io\n`);
await until(() => document.querySelector("#output").textContent.includes("token for zq-live-marker: [REDACTED]"));
check(true, "output follows typing");

// every redaction mode the engine supports in the browser
const modeOut = async (mode, expect) => {
  await pickMode(mode);
  await until((re) => new RegExp(re).test(document.querySelector("#output").textContent), expect.source);
  check(true, `mode ${mode}: ${expect}`);
};
await modeOut("mask", /\*+MPLE/);
await page.fill('input[name="mask_char"]', "#");
await until(() => document.querySelector("#output").textContent.includes("#####"));
check(true, "mask character is applied");
await modeOut("pseudonymize", /<AWS_KEY_[0-9a-f]{16}>/);
await modeOut("hash", /<AWS_KEY:H:[0-9a-f]{16}>/);
await modeOut("fictionalize", /@example\.com/);
check(await page.isDisabled('input[name="mode"][value="encrypt"]'), "encrypt is shown as local only, not simulated");
await modeOut("replace", /: \[REDACTED\] and/);
await page.fill('input[name="replacement"]', "<GONE>");
await until(() => document.querySelector("#output").textContent.includes("<GONE>"));
check(true, "replacement text is applied");

// per-type replacement, custom words and patterns
await page.selectOption("#repl-type", "email");
await page.fill("#repl-text", "<EMAIL>");
await page.click("#repl-add");
await until(() => document.querySelector("#output").textContent.includes("<EMAIL>"));
check(true, "per-type replacement is applied");
await page.fill('textarea[name="custom_words"]', marker);
await until(() => !document.querySelector("#output").textContent.includes("zq-live-marker"));
check(true, "a custom word is redacted");
await page.fill('textarea[name="custom_patterns"]', "(");
await until(() => !document.querySelector("#settings-error").hidden);
check((await text("#settings-error")).length > 30, "an invalid regex shows the engine's message");
await page.fill('textarea[name="custom_patterns"]', "\\bEMP-\\d{5}\\b");
await until(() => document.querySelector("#settings-error").hidden);

// type picker: none, then all
await page.click('#settings [data-types="none"]');
await until(() => document.querySelector("#types-count").textContent.startsWith("(0 of"));
await until(() => !document.querySelector("#output").textContent.includes("<EMAIL>"));
check(true, "no types: only custom rules apply");
await page.click('#settings [data-types="all"]');
await until(() => document.querySelector("#output").textContent.includes("<EMAIL>"));

// opt-in tiers
await page.check('input[name="use_regional"]');
await page.fill("#input", "iban GB82 WEST 1234 5698 7654 32\n");
await until(() => document.querySelector("#findings").textContent.includes("iban"));
check(true, "regional IDs tier finds an IBAN");
await page.uncheck('input[name="use_regional"]');

// policy.toml follows the controls, and the controls follow the TOML
const toml = await page.inputValue("#policy-text");
check(toml.includes('email = "<EMAIL>"') && toml.includes("words = [") && toml.includes('replacement = "<GONE>"'), "policy.toml reflects the controls");
await page.fill("#policy-text", '[detection]\nmin_confidence = 0.75\n\n[redaction]\nmode = "mask"\nmask_keep_last = 2\n');
await until(() => document.querySelector("#policy-status").textContent.startsWith("Valid"));
check(await page.inputValue('input[name="min_confidence"]') === "0.75" && await page.isChecked('input[name="mode"][value="mask"]'), "editing policy.toml updates the controls");
await page.fill("#policy-text", '[redaction]\nreplacment = "x"\n');
await until(() => document.querySelector("#policy-status").classList.contains("err"));
check((await text("#policy-status")).includes("did you mean 'replacement'"), "an invalid policy shows the loader's error");
await page.click("#policy-starter");
await until(() => document.querySelector("#policy-status").textContent.startsWith("Valid"));
check(true, "the init-config starter file is accepted");

// run this yourself: the command, run here, writes the same bytes as the playground
await page.fill("#policy-text", '[redaction]\nmode = "mask"\n');
await until(() => document.querySelector("#policy-status").textContent.startsWith("Valid"));
await page.click('#samples [data-sample="env"]');
await until(() => !document.body.classList.contains("busy") && document.querySelector("#m-findings").textContent !== "–");
await page.waitForTimeout(300);
check((await text("#cli-snippet")).includes("--mode mask"), "the CLI snippet follows the settings");
await page.click("#cli-run");
await until(() => document.querySelector("#cli-result").textContent.includes("exit"));
check((await text("#cli-result")).includes("byte-identical"), "the real CLI writes the same bytes as the playground");
for (const t of ["py", "rest", "mcp"]) {
  await page.click(`#rt-${t}`);
  check((await text(`#${t}-snippet`)).length > 40 && await page.isVisible(`#rp-${t}`), `run-yourself ${t} snippet is shown`);
}
check((await text("#py-snippet")).includes('mode="mask"'), "the Python snippet follows the settings");

// copy, download, determinism
await page.keyboard.press("c");
const clip = await page.evaluate(() => navigator.clipboard.readText());
check(clip.includes("AWS_ACCESS_KEY_ID=*") && !clip.includes("AKIAIOSFODNN7EXAMPLE"), "'c' copies the redacted output");
const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#download-out")]);
check(dl.suggestedFilename().endsWith("env.redacted"), `download is named ${dl.suggestedFilename()}`);
await page.click("#det-btn");
await until(() => document.querySelector("#det-card").textContent.includes("Determinism check"));
check((await text("#det-card")).includes("byte-identical"), "determinism check: four runs, byte-identical");

// --- streaming inspector
await page.keyboard.press("2");
check(await page.getAttribute("#tab-inspector", "aria-selected") === "true", "'2' switches to the Streaming tab");
await until(() => Number(document.querySelector("#i-passes").textContent) > 1, null, 60_000);
const passes = Number(await text("#i-passes"));
check(passes > 3, `inspector replays the long log (${passes} passes)`);
await page.click("#istep");
check((await text("#ipos")).startsWith("2 of"), "inspector steps forward");
await page.check('input[name="isrc"][value="split"]', { force: true });
await until(() => document.querySelector("#i-input").textContent.startsWith("20,") && document.querySelector("#inotes").textContent.includes("moved back"));
check(true, "split secret: the boundary retreats");
await page.click("#istep");
check((await text("#inotes")).includes("written whole here: jwt"), "split secret: the next pass writes the jwt whole");
await page.selectOption("#bench-sizes", { index: 0 });
await page.click("#bench-run");
await until(() => document.querySelector("#bench-out").textContent.includes("peak memory changed"), null, 120_000);
const benchRows = await page.$$eval("#bench-out tbody tr", (rs) => rs.map((r) => r.textContent));
check(benchRows.length === 3 && benchRows.every((r) => r.includes("MB/s")), "generated input: throughput and peak memory per size");

// --- REST console: every endpoint and the error cases
await page.keyboard.press("3");
const rest = async (route) => {
  await page.selectOption("#rest-route", route);
  await page.click("#rest-send");
  await until(() => document.querySelector("#rest-status").textContent !== "");
  await page.waitForTimeout(100);
  return [await text("#rest-status"), await text("#rest-response")];
};
for (const [route, status] of [["POST /redact", "200"], ["POST /scan", "200"], ["GET /detectors", "200"], ["GET /health", "200"], ["GET /version", "200"],
  ["POST /redact|nofield", "400"], ["POST /scan|badjson", "400"], ["GET /nope", "404"]]) {
  await page.evaluate(() => { document.querySelector("#rest-status").textContent = ""; });
  const [st, body] = await rest(route);
  check(st === status, `REST ${route.replace("|", " ")} -> ${st}`);
  if (route === "POST /scan") check(!body.includes("AKIA"), "REST /scan returns no secret text");
}
check((await text("#rest-curl")).includes("curl -s"), "REST shows the matching curl");

// --- MCP console: every preset
await page.keyboard.press("4");
for (const preset of ["initialize", "initialized", "ping", "list", "scan", "redact", "explain", "detectors", "health", "unknown"]) {
  await page.evaluate(() => { document.querySelector("#mcp-response").textContent = ""; });
  await page.click(`[data-preset="${preset}"]`);
  await until(() => document.querySelector("#mcp-response").textContent !== "");
  const reply = await text("#mcp-response");
  const ok = preset === "initialized" ? reply.includes("notification")
    : preset === "unknown" ? reply.includes("error") || reply.includes("isError")
    : reply.includes('"result"') && !reply.includes("AKIAIOSFODNN7EXAMPLE");
  check(ok, `MCP ${preset}`);
}
const tools = await page.evaluate(() => { document.querySelector('[data-preset="list"]').click(); return new Promise((r) => setTimeout(() => r(document.querySelector("#mcp-response").textContent), 400)); });
check(["scan", "redact", "explain_detection", "detectors", "health"].every((t) => tools.includes(`"${t}"`)), "MCP tools/list names all five tools");
check((await text("#mcp-config")).includes("mcp-serve"), "MCP client config is shown");

// --- CI gate: the real CLI, real exit codes
await page.keyboard.press("5");
await until(() => document.querySelector("#ci-verdict").textContent.includes("FAIL"));
check((await text("#ci-verdict")).includes("Exit code 1") && !(await text("#ci-output")).includes("sk_live"), "CI gate: a leaked key fails with exit 1, secret not printed");
await page.click('[data-ci="clean"]');
await page.click("#ci-run");
await until(() => document.querySelector("#ci-verdict").textContent.includes("PASS"));
check(true, "CI gate: a clean diff passes with exit 0");
await page.click('[data-ci="leak"]');
await page.check('input[name="ci-format"][value="--sarif"]', { force: true });
await page.click("#ci-run");
await until(() => document.querySelector("#ci-output").textContent.includes("sarif"));
check((await text("#ci-cmd")).includes("--sarif") && (await text("#ci-verdict")).includes("2 findings"), "CI gate: SARIF report");
check((await text("#ci-precommit")).includes("safestream-detect") && (await text("#ci-action")).includes("upload-sarif"), "CI gate: pre-commit and Action config");

// --- install and trust
await page.keyboard.press("6");
check(await page.isHidden("#rail"), "the settings rail hides on the Install tab");
await page.check('input[name="path"][value="3"]', { force: true });
check((await text("#chooser-out")).includes("MCP server"), "the path chooser answers");
check((await page.$$("#local-only .card")).length >= 6, "local-only features are labelled panels");
await page.keyboard.press("7");
check(await text("#net-count-2") === "0" && await text("#offsite-count") === "0", "offline proof: 0 requests since start, 0 to other sites");
check(await text("#net-count") === "0", "the header counter stayed at 0 through every feature");

// --- help, theme, shareable state
await page.keyboard.press("?");
check(await page.isVisible("#help"), "'?' opens the shortcuts sheet");
await page.keyboard.press("Escape");
await page.keyboard.press("t");
check(await page.evaluate(() => document.documentElement.dataset.theme) !== undefined, "'t' switches theme");
check(addresses.length > 0 && addresses.every((a) => !a.includes(marker) && !a.includes("AKIA") && !a.includes("EMP-")), `the address never carries text or custom rules (${addresses.length} addresses)`);
const shared = await page.evaluate(() => location.hash);
check(shared.includes("tab=trust") && shared.includes("mode=mask"), `settings and tab are in the hash (${shared})`);
const page2 = await context.newPage();
await page2.goto(`${url}#tab=ci&mode=hash&conf=0.8`);
await page2.waitForSelector("body[data-ready=true]", { timeout: 90_000 });
check(await page2.getAttribute("#tab-ci", "aria-selected") === "true" && await page2.isChecked('input[name="mode"][value="hash"]')
  && await page2.inputValue('input[name="min_confidence"]') === "0.8", "a shared link restores tab and settings");
await page2.close();

// the policy is enforced, not just obeyed: a worker built the way the engine's is
// (from a blob: URL) cannot reach another origin
const blocked = await page.evaluate(() => new Promise((resolve) => {
  // resolve only on the browser's own CSP violation event: a network failure is not proof
  const src = "self.addEventListener('securitypolicyviolation', (e) => postMessage(e.effectiveDirective));"
    + "fetch('https://example.com/').then(() => postMessage('sent'), () => setTimeout(() => postMessage('failed, no CSP event'), 500));";
  const w = new Worker(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
  w.onmessage = (e) => resolve(e.data);
}));
check(blocked === "connect-src", `CSP blocks a blob worker from contacting another origin (${blocked})`);
await page.waitForTimeout(300);
// ...and the log hook above sees worker-side violations, so the last check below means something
check(errors.some((e) => e.includes("example.com")), "worker-side CSP violations reach the error log");
errors.splice(0, errors.length, ...errors.filter((e) => !e.includes("example.com")));
offsite.splice(0, offsite.length, ...offsite.filter((u) => !u.startsWith("https://example.com")));

check(offsite.length === 0, `no request left ${origin}${offsite.length ? ": " + offsite.join(", ") : ""}`);
check(errors.length === 0, `no console errors or CSP violations${errors.length ? ": " + errors.join(" | ") : ""}`);

if (process.argv[3]) {
  await page.keyboard.press("1");
  await page.screenshot({ path: process.argv[3], fullPage: false });
}
await browser.close();
if (problems.length) {
  console.log(`${problems.length} check(s) failed`);
  process.exit(1);
}
console.log("smoke test passed");
