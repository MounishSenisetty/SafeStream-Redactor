// The SafeStream engine, in a Web Worker.
//
// app.js starts this file from a blob: URL, so the worker inherits the page's
// Content-Security-Policy: connect-src 'self' binds the Python engine as well as
// the page, and the browser itself enforces that nothing leaves this origin.
// Pyodide (CPython compiled to WebAssembly) and the safestream_redactor wheel are
// both served from this site; nothing is fetched from anywhere else.
//
// Protocol: {id, op, args} in, {id, ok, result | error} out.

let engine = null;

async function boot(base) {
  const progress = (stage) => postMessage({ id: 0, progress: stage });
  progress("Loading the Python runtime");
  // a module worker: Pyodide's classic-worker probe (importScripts of a data: URL)
  // then fails harmlessly instead of tripping the CSP
  const { loadPyodide } = await import(base + "pyodide/pyodide.mjs");
  const py = await loadPyodide({ indexURL: base + "pyodide/" });
  progress("Loading SafeStream");
  const [wheel, glue] = await Promise.all([
    fetch(base + "engine/safestream_redactor.whl").then((r) => r.arrayBuffer()),
    fetch(base + "engine.py").then((r) => r.text()),
  ]);
  py.unpackArchive(new Uint8Array(wheel), "wheel");
  py.FS.writeFile("/home/pyodide/demo_engine.py", glue);
  progress("Starting the engine");
  engine = py.pyimport("demo_engine");
  return JSON.parse(engine.info()).result;
}

const ops = {
  analyze: ({ text, settings }) => engine.analyze(text, settings),
  trace: ({ text, settings, chunk }) => engine.trace(text, settings, chunk),
  rest: ({ method, path, body, settings }) => engine.rest(method, path, body, settings),
  mcp: ({ message, settings }) => engine.mcp(message, settings),
};

onmessage = async ({ data: { id, op, args } }) => {
  try {
    if (op === "init") {
      postMessage({ id, ok: true, result: await boot(args.base) });
      return;
    }
    // every Python entry point returns {"ok": ..., "result" | "error": ...} as JSON
    postMessage({ id, ...JSON.parse(ops[op](args)) });
  } catch (err) {
    postMessage({ id, ok: false, error: String((err && err.message) || err).slice(-600) });
  }
};
