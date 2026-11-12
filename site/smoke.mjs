// Browser smoke test for the demo site:  node site/smoke.mjs http://127.0.0.1:8642/
//
// Fails if the engine does not start, if the sample is not redacted, if the
// REST or MCP consoles answer wrongly, if any request leaves the page's origin,
// or if the browser reports a CSP violation or a console error.
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

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
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

// Chrome's own log also carries what workers trigger (a CSP refusal inside the engine's
// worker never reaches the page's console or its securitypolicyviolation listener)
const cdp = await page.context().newCDPSession(page);
await cdp.send("Log.enable");
cdp.on("Log.entryAdded", ({ entry }) => {
  if (entry.level === "error") errors.push(`[${entry.source}] ${entry.text}`);
});

const started = Date.now();
await page.goto(url);
await page.waitForSelector("body[data-ready=true]", { timeout: 90_000 });
console.log(`     engine ready in ${((Date.now() - started) / 1000).toFixed(1)} s`);
await page.waitForFunction(() => document.querySelector("#m-findings").textContent !== "–");

// playground: the sample log is redacted on load
const out = await page.textContent("#output");
check(out.includes("user=[REDACTED]") && !out.includes("AKIAIOSFODNN7EXAMPLE"), "sample log is redacted");
check(Number(await page.textContent("#m-findings")) >= 9, "sample log has at least 9 findings");
check(/^v\d+\.\d+/.test(await page.textContent("#version")), "version is shown");
check((await page.textContent("#findings tbody")).includes("aws_key"), "findings table lists aws_key");

// mask mode
await page.check('input[name="style"][value="mask"]', { force: true });
await page.waitForFunction(() => document.querySelector("#output").textContent.includes("*1111"));
check(true, "mask mode re-renders the output");
await page.check('input[name="style"][value="replace"]', { force: true });

// REST console: POST /scan never returns the matched text
await page.click("#tab-rest");
await page.selectOption("#rest-route", "POST /scan");
await page.click("#rest-send");
await page.waitForFunction(() => document.querySelector("#rest-status").textContent === "200");
const rest = JSON.parse(await page.textContent("#rest-response"));
check(rest.total_detections === 2 && !JSON.stringify(rest).includes("AKIA"), "REST /scan: 2 detections, no secret text");

// MCP console: scan reports metadata only
await page.click("#tab-mcp");
await page.click('[data-preset="scan"]');
await page.waitForFunction(() => document.querySelector("#mcp-response").textContent.includes("structuredContent"));
const mcp = JSON.parse(await page.textContent("#mcp-response"));
const sc = mcp.result.structuredContent;
check(sc.count === 2 && !JSON.stringify(mcp).includes("AKIA"), "MCP scan: 2 findings, no secret text");

// inspector: the long log is replayed in several passes with a bounded window
await page.click("#tab-inspector");
await page.waitForFunction(() => Number(document.querySelector("#i-passes").textContent) > 1, null, { timeout: 60_000 });
const passes = Number(await page.textContent("#i-passes"));
check(passes > 3, `inspector replays the long log (${passes} passes)`);
await page.click("#istep");
check((await page.textContent("#ipos")).startsWith("2 of"), "inspector steps forward");

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

if (process.argv[3]) await page.screenshot({ path: process.argv[3], fullPage: false });
await browser.close();
if (problems.length) {
  console.log(`${problems.length} check(s) failed`);
  process.exit(1);
}
console.log("smoke test passed");
