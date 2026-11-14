# Command-line reference

The package installs one command, `safestream` (also available as
`safestream-redactor`), with these subcommands:

| Command | What it does |
|---|---|
| `safestream redact INPUT -o OUTPUT` | Redact a file, a directory, or stdin (`-`) |
| `safestream detect INPUT...` | List what would be redacted, without changing anything |
| `safestream deanonymize INPUT -o OUTPUT` | Restore text redacted with `--mode encrypt` (needs the `crypto` extra) |
| `safestream init-config` | Print a documented starter policy file (TOML) |
| `safestream serve` | Run a local REST API (standard library only); see [rest-api.md](rest-api.md) |
| `safestream mcp-serve` | Run a local Model Context Protocol server over stdio; see [MCP.md](MCP.md) |
| `safestream ui` | Open the local web playground (needs the `ui` extra); see [WEB_UI.md](WEB_UI.md) |
| `safestream fanotify --watch DIR` | Linux file-system DLP daemon; see [FANOTIFY.md](FANOTIFY.md) |

Run `safestream <command> --help` for the full option list.

## `redact`

```bash
# redact everything detectable
safestream redact input.txt -o output.txt

# only some entity types, with a custom replacement
safestream redact input.txt -o output.txt --types email,ssn --replace "***"

# keep the last 4 characters visible
safestream redact cards.csv -o masked.csv --mode mask --keep-last 4

# consistent keyed tokens, e.g. <EMAIL_75e802c7c314f5a2> (same input -> same token)
safestream redact input.txt -o output.txt --mode pseudonymize --hmac-key "$SECRET"

# per-type replacement text, plus your own words and regexes
safestream redact input.txt -o output.txt --replace-type email='<EMAIL>' \
    --custom-word ProjectX --custom-regex 'INT-\d+'

# stdin to stdout
cat app.log | safestream redact - -o -

# a whole directory, in parallel; print counts and write a JSON report
safestream redact logs/ -o redacted/ --workers 4 --stats --report run.json
```

Example:

```text
$ printf 'contact bob@corp.io, ssn: 123-45-6789\n' | safestream redact - -o -
contact [REDACTED], ssn: [REDACTED]
```

`--report FILE` writes counts and sizes only, never the matched text.

## `detect`

```bash
safestream detect app.log                     # human-readable list (no secret text)
safestream detect app.log --json              # one JSON object per detection
safestream detect src/*.py --sarif > out.sarif  # SARIF 2.1.0
safestream detect . --fail-on-detect          # exit status 1 if anything is found
safestream detect app.log --show-text         # also print the matched text (local only)
```

```text
$ safestream detect app.log
app.log:3:7: email  conf=0.95
app.log:9:12: ssn  conf=1.00
-- 2 detection(s) (matched text hidden; --show-text reveals it)
```

## `init-config`

```bash
safestream init-config -o policy.toml
safestream redact input.txt -o output.txt --config policy.toml
```

Flags given on the command line override the file. Unknown keys are rejected.

```toml
[detection]
# types = ["email", "ssn", "credit_card"]   # omit for all types
min_confidence = 0.5
use_ner = false
use_entropy = true

[redaction]
mode = "replace"                            # replace | mask | pseudonymize
replacement = "[REDACTED]"
mask_keep_last = 4

[redaction.replacements]
# email = "<EMAIL>"

[custom]
# words = ["ProjectX"]
# patterns = ['\\binternal-[a-z]+\\b']
```

## `serve`

```bash
safestream serve                     # http://127.0.0.1:8000 (loopback only)
safestream serve --port 9000 --config policy.toml --max-body 1048576
```

```bash
curl -s -X POST http://127.0.0.1:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"text": "email bob@corp.io"}'
# {"redacted": "email [REDACTED]", "total_detections": 1, "detections_by_type": {"email": 1}}
```

Endpoints: `GET /health`, `GET /version`, `GET /detectors`, `POST /redact`, `POST /scan`.
Request bodies are never logged.

## `mcp-serve`

Exposes the tools `scan`, `redact`, `explain_detection`, `detectors` and `health` to an MCP
client over stdio. Register it in your client's configuration as:

```json
{ "command": "safestream", "args": ["mcp-serve"] }
```

## `ui`

Opens the local web playground in your browser (requires the `ui` extra):

```bash
pip install 'safestream-redactor[ui]'
safestream ui                          # http://127.0.0.1:8501
```

What each mode does, the large-file path, and the local-only guarantees are described in
[WEB_UI.md](WEB_UI.md).

## Common options (`redact` and `detect`)

| Option | Meaning |
|---|---|
| `--types a,b,c` | Only detect these entity types (default: all) |
| `--backend {python,native,auto}` | `native` uses the Rust core (built from `native/`, see the README); `auto` uses it when installed |
| `--regional` | Also detect IBAN, crypto addresses, UK NINO/NHS, India Aadhaar/PAN |
| `--dates`, `--profile prose` | Also redact dates and times (off by default: logs timestamp every line) |
| `--config FILE` | Load a TOML policy file |
| `--min-confidence X` | Drop detections scoring below `X` (default 0.5) |
| `--custom-word W`, `--custom-regex R` | Always redact these (repeatable) |
| `--no-entropy` | Turn off generic high-entropy secret detection |
| `--ner`, `--onnx MODEL.onnx` | Enable an NER tier (needs its extra) |
| `--encoding ENC` | Input/output encoding (default `utf-8`) |
| `--workers N` | Parallel workers (directories, or one large file) |
| `--memory-limit SIZE` | Stay within a memory budget, e.g. `256MiB` |
| `--enable-plugins` | Load third-party detector plugins (off by default) |
| `--allow-network` | Turn off the network guard (see below) |
| `--offline-hard MODE` | Linux only: kernel-enforced offline mode (`seccomp`, `netns`, `auto`) |

Redaction options (`redact` only): `--mode {replace,mask,pseudonymize,hash,encrypt,fictionalize}`,
`--replace TEXT`, `--replace-type TYPE=TEXT`, `--keep-last N`, `--mask-char C`,
`--hmac-key KEY` (pseudonymize, fictionalize), `--hash-salt SALT` (hash), and
`--encrypt-key KEY` or `SAFESTREAM_ENCRYPT_KEY` (encrypt; needs the `crypto` extra).
Mask mode never leaves more than half of a value visible, so a short value is never shown
in full. `--stats` prints per-type counts to stderr; `--report FILE` writes them as JSON
(counts and sizes only, never matched text).

Detection options (`detect` only): `--json`, `--sarif`, `--fail-on-detect`, and
`--show-text` / `--reveal-matches` (also print the matched text, which is hidden by default
so detect output is safe to log; for local triage only). `detect` accepts
files and directories; directories are walked recursively, skipping symlinks, `.git/`, and
binary files.

While `redact` or `detect` runs, an in-process guard blocks outbound (non-loopback) network
connections by default. On Linux, `--offline-hard` adds a kernel-enforced block on top.

## Exit status

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime error (e.g. unreadable input, invalid config), or `detect --fail-on-detect` found something |
| `2` | Invalid command-line usage (unknown option, missing argument) |
| `3` | The run could not fit in `--memory-limit` |

## Network isolation

While redacting, the CLI installs an **offline network guard** by default: any attempt to
open a non-loopback connection through Python's socket layer raises an error. This is
best-effort, defense-in-depth egress prevention for this process, its plugins, and its
Python dependencies — **not** a hard boundary: native extensions issuing raw syscalls, a
spawned subprocess, or another process on the machine are outside its reach. Pass
`--allow-network` to disable it.

For a **kernel-enforced** boundary that also contains native code and raw syscalls, add
`--offline-hard MODE` (Linux; opt-in, applied before workers fork):

```bash
# block AF_INET/AF_INET6 socket creation process-wide via a seccomp-bpf filter
safestream redact input.txt -o out.txt --offline-hard seccomp

# or enter an empty network namespace (no network at all, loopback included)
safestream redact input.txt -o out.txt --offline-hard netns   # or: auto
```

- **`seccomp`** — installs a seccomp filter that makes IPv4/IPv6 socket *creation*
  fail (`EACCES`) for this process and every child, native code included. `AF_UNIX`
  and already-open sockets are untouched. (Classic seccomp-bpf can't inspect the
  `sockaddr` pointer, so it blocks IP-socket creation outright rather than filtering
  `connect()` by address — the stronger choice for offline use.)
- **`netns`** — `unshare(CLONE_NEWNET)` into a fresh namespace whose only interface is a
  down loopback: no network of any kind. Needs `CAP_SYS_ADMIN` (root) or unprivileged
  user-namespace support (tried as a fallback).
- Both **fall back with a warning** where unsupported, leaving the in-process guard
  active; neither is for `serve`/`mcp-serve` (they need loopback).

For whole-container isolation you control, `docker run --network none ...` remains the
strongest option. See
[SECURITY.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/SECURITY.md) for the full threat model.

## Policy files (TOML)

```toml
# policy.toml
[detection]
types = ["email", "ssn", "credit_card"]

[redaction]
mode = "replace"
replacement = "[GONE]"

[redaction.replacements]
email = "<EMAIL>"

[custom]
words = ["ProjectX"]
```

```bash
safestream redact input.txt -o out.txt --config policy.toml
```

A fuller, ready-to-use policy — NER enabled, plus custom patterns for passport /
driver-licence / bank-account / routing / employee-ID / Slack-ID / DOB values — ships in
[`examples/policy.toml`](../examples/policy.toml). Generate a minimal starter with
`safestream init-config -o policy.toml`.

Policy files fail closed: an unknown section or key (`replacment`), or a value of the
wrong type (`use_entropy = "no"`, `min_confidence = "0.5"`), is an error before any
input is read, never a silent fallback to defaults. CLI flags layer on top of the file:
scalar flags override it, `--custom-word`/`--custom-regex` add to it, and `--types`
scopes every tier exactly as it does without `--config`.

## Detector plugins

Any installed package can add a detection tier by advertising an entry point — no fork
required. Loading is **opt-in**: plugin code runs with full privileges inside a tool that
handles your secrets, so installing a package (perhaps as a transitive dependency) must
not be enough to run it. Enable plugins with `Redactor(load_plugins=True)`,
`safestream ... --enable-plugins`, or `[plugins] enabled = true` in a policy file. If
plugins are installed but not enabled, a one-time warning names them.

```toml
# in your plugin package's pyproject.toml
[project.entry-points."safestream_redactor.detectors"]
my_detector = "my_pkg.detectors:MyDetector"   # a Detector instance or zero-arg factory
```

A detector is anything with a `name` and `detect(text) -> list[Detection]` (the
`Detector` protocol).
