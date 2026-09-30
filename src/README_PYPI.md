# safestream-redactor

[![PyPI](https://img.shields.io/pypi/v/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![License](https://img.shields.io/pypi/l/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)

Detect and redact PII and credentials in text files of any size, with constant memory.
The file is streamed in chunks, so a 100 GB log uses the same memory as a 1 KB one.
Bytes outside a redacted span, line endings included, are left exactly as they were.

## Requirements

- Python 3.10 or newer, on Linux, macOS or Windows.
- No third-party runtime dependencies (`tomli` only on Python 3.10). Optional extras are
  listed below.

## Installation

```bash
pip install safestream-redactor
```

Only need the command-line tool? Install it into an isolated environment with pipx:

```bash
pipx install safestream-redactor
```

Check the install:

```bash
safestream --version                # prints e.g. "safestream 0.4.0"
python -m safestream_redactor --version
```

### Optional extras

| Extra | Install | Adds |
|---|---|---|
| `ner` | `pip install 'safestream-redactor[ner]'` then `python -m spacy download en_core_web_sm` | spaCy person / organisation / location detection (`--ner`) |
| `onnx` | `pip install 'safestream-redactor[onnx]'` | On-device ONNX NER model (`--onnx MODEL.onnx --onnx-vocab VOCAB.json`); you supply the model |

An optional compiled (Rust) core gives the same output as the pure-Python pattern tier,
faster; enable it with `Redactor(backend="native")`. Its wheel is not on PyPI yet, so build
it from source (needs a Rust toolchain):

```bash
pip install "safestream-redactor-native @ git+https://github.com/MounishSenisetty/SafeStream-Redactor#subdirectory=native"
```

Without it, `backend="native"` falls back to pure Python with a warning.

Upgrade or remove:

```bash
pip install --upgrade safestream-redactor
pip uninstall safestream-redactor
```

## Command-line usage

The package installs one command, `safestream`, with five subcommands:

| Command | What it does |
|---|---|
| `safestream redact INPUT -o OUTPUT` | Redact a file, a directory, or stdin (`-`) |
| `safestream detect INPUT...` | List what would be redacted, without changing anything |
| `safestream init-config` | Print a documented starter policy file (TOML) |
| `safestream serve` | Run a local REST API (standard library only) |
| `safestream mcp-serve` | Run a local Model Context Protocol server over stdio |

Run `safestream <command> --help` for the full option list.

### `redact`

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

### `detect`

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

### `init-config`

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

### `serve`

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

### `mcp-serve`

Exposes the tools `scan`, `redact`, `explain_detection`, `detectors` and `health` to an MCP
client over stdio. Register it in your client's configuration as:

```json
{ "command": "safestream", "args": ["mcp-serve"] }
```

### Common options (`redact` and `detect`)

| Option | Meaning |
|---|---|
| `--types a,b,c` | Only detect these entity types (default: all) |
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

Redaction options (`redact` only): `--mode {replace,mask,pseudonymize}`, `--replace TEXT`,
`--replace-type TYPE=TEXT`, `--keep-last N`, `--mask-char C`, `--hmac-key KEY`. Mask mode
never leaves more than half of a value visible, so a short value is never shown in full.

Detection options (`detect` only): `--json`, `--sarif`, `--fail-on-detect`, and
`--show-text` / `--reveal-matches` (also print the matched text, which is hidden by default
so detect output is safe to log; for local triage only). `detect` accepts
files and directories; directories are walked recursively, skipping symlinks, `.git/`, and
binary files.

While `redact` or `detect` runs, an in-process guard blocks outbound (non-loopback) network
connections by default. On Linux, `--offline-hard` adds a kernel-enforced block on top.

### Exit status

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime error (e.g. unreadable input, invalid config), or `detect --fail-on-detect` found something |
| `2` | Invalid command-line usage (unknown option, missing argument) |
| `3` | The run could not fit in `--memory-limit` |

## Entity types

| Group | Types |
|---|---|
| Personal data | `email`, `phone`, `credit_card`, `ssn`, `ipv4`, `ipv6`, `dob`, `id_number` |
| Credentials | `aws_key`, `aws_secret`, `github_token`, `api_key`, `jwt`, `private_key`, `slack_token`, `slack_webhook`, `stripe_key`, `google_api_key`, `sendgrid_key`, `twilio_key`, `npm_token`, `openai_key`, `anthropic_key`, `url_credentials` |
| Generic secrets | `secret` (high-entropy strings with no known format) |
| Names (needs `ner` or `onnx`) | `person`, `org`, `loc` |
| Your own | `custom` (from `--custom-word` / `--custom-regex`) |

## Python API

```python
from safestream_redactor import EntityType, RedactionPolicy, Redactor

redactor = Redactor()
redactor.redact("email bob@corp.io, ssn: 123-45-6789")
# 'email [REDACTED], ssn: [REDACTED]'

# inspect without redacting
[(d.entity_type.value, d.text) for d in redactor.detect("mail bob@corp.io from 10.0.0.1")]
# [('email', 'bob@corp.io'), ('ipv4', '10.0.0.1')]

# choose types and how they are rewritten
Redactor(types=["email"]).redact("bob@corp.io 123-45-6789")
# '[REDACTED] 123-45-6789'
policy = RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})
Redactor(policy=policy).redact("write to bob@corp.io")
# 'write to <EMAIL>'
Redactor(policy=RedactionPolicy(mode="mask", mask_keep_last=4)).redact("card 4111 1111 1111 1111")
# 'card ***************1111'

# your own words and patterns
Redactor(custom_words=["ProjectX"], custom_patterns=[r"INT-\d+"]).redact("ProjectX ticket INT-42")
# '[REDACTED] ticket [REDACTED]'

# file to file with constant memory; the output is written atomically
stats = redactor.redact_file("huge.log", "huge.redacted.log")
stats.summary()   # '2 detection(s): email=1, ssn=1'

# split one large file across processes (same output as a single process)
redactor.redact_file("huge.log", "huge.redacted.log", workers=8)

# any iterable of text chunks (a socket, a generator, a file object)
with open("app.log", newline="") as source:
    for piece in redactor.redact_stream(source):
        print(piece, end="")
```

### Adding a detector from another package

A package can add a detection tier by declaring an entry point. Plugins are **opt-in**:
enable them with `Redactor(load_plugins=True)`, `--enable-plugins`, or
`[plugins] enabled = true` (a warning names any installed plugin that was not loaded):

```toml
[project.entry-points."safestream_redactor.detectors"]
my_detector = "my_package.detectors:MyDetector"
```

A detector is any object with a `name` attribute and a `detect(text) -> list[Detection]` method.

## Limitations

Structured data (e-mails, cards, SSNs, keys, tokens) is detected with high precision.
Names and street addresses in free prose are only detected with the `ner` or `onnx` extra,
and even then on a best-effort basis. Review redacted output before sharing it where a miss
would be costly.

## Links

- Source and full documentation: https://github.com/MounishSenisetty/SafeStream-Redactor
- Issues: https://github.com/MounishSenisetty/SafeStream-Redactor/issues
- Changelog: https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/CHANGELOG.md

## License

MIT
