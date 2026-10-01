# Kernel-assisted interception — architecture RFC

**Status:** proposed (Phase 1 of the kernel-assisted DLP track). Nothing here is
implemented yet. This document fixes the design before any eBPF or daemon code
lands, and records where the original brief was changed and why.

**Scope in one line:** redirect outbound connections and file handoffs from
selected workloads through a local redaction daemon, using eBPF and fanotify for
the interception, **without changing what gets detected**: detection stays in the
existing engine and its byte-identical native core.

---

## 0. Decisions at a glance

| Question | Decision | Section |
| --- | --- | --- |
| Network hook | `cgroup/connect4` + `cgroup/connect6` to redirect, `sockops` to record the original destination, `cgroup/sendmsg4/6` to block UDP/443 (QUIC). **Not** `sk_msg`, TC or TPROXY for v1. | §3 |
| Kernel → user IPC | **Split-TCP transparent redirect** for payload; **BPF ring buffer for audit events only**, never payload. | §4 |
| Token-length changes | TCP is terminated at the daemon, so **no sequence numbers are ever rewritten**. Length changes are handled at the HTTP layer (Content-Length, chunked, HTTP/2 DATA frames). | §5 |
| HTTPS | The redirect alone yields ciphertext. Redaction needs **TLS termination with an operator-provisioned local CA** (opt-in); otherwise the connection is **blocked or passed through by policy**, never silently allowed. | §6 |
| Pattern engine | Reuse the existing native Rust core (the `regex` crate's SIMD literal prefilters). **Vectorscan/Hyperscan stays rejected**: see `PERFORMANCE_BACKENDS.md`. | §7 |
| Detection coverage in the daemon | **Full parity by default**: the Rust daemon hands decoded text to a pool of Python engine workers. A native-only mode is opt-in and states which entity types it drops. | §7 |
| I/O runtime | tokio (epoll). `io_uring` only behind a feature flag, and only if a benchmark shows an end-to-end gain. | §8 |
| Files | fanotify **quarantine-until-scanned** (`FAN_CLOSE_WRITE` scan + `FAN_OPEN_PERM` gate), with a BPF-LSM `file_open` backstop so a daemon crash fails closed. Nothing intercepts `write()` "before disk". | §9 |
| No privileges | Fall back to explicit-proxy mode, then to the existing CLI and library. Never fail open. | §10 |
| Packaging | A separate, opt-in component under `kernel/`. The Python package, its zero-dependency install and the `[native]` wheel are unchanged. | §11 |

---

## 1. Current-state audit

### 1.1 Where the pieces meet today

```
Redactor (redactor.py)                     ← facade; owns detectors + policy
  ├─ detect(text) / redact(text)           ← whole-string
  ├─ redact_stream(chunks)                 ← engine.stream_transform
  │     └─ engine.stream_windows           ← rolling buffer, overlap = 8 KiB,
  │                                          min_emit = chunk_size (64 KiB)
  ├─ redact_file(in, out)                  ← read_chunks → stream_transform → _atomic
  └─ detectors: DeterministicDetector(backend="python"|"native"|"auto")
        └─ _load_native → safestream_native.detect(text)   (native/src/lib.rs)
              returns [(char_start, char_end, type, confidence)]

scheduler.redact_tree   → ProcessPoolExecutor over files   (netguard + RLIMIT_AS per worker)
parallel.redact_file_parallel → byte-range split + seam valve (ADR 0001)
api.serve               → loopback http.server; /scan and /redact
mcp_server.serve_stdio  → newline-delimited JSON over stdio
netguard / netguard_hard → in-process socket guard; opt-in seccomp / netns
memory_budget           → admission control + RLIMIT_AS
```

### 1.2 Facts the design must respect

1. **The engine takes text, not bytes.** `stream_windows` works on `str` chunks
   and character offsets. Anything that intercepts bytes has to decode first,
   using the same encoding and error policy as the CLI.
2. **Streaming holds data back.** A segment is emitted only once it is at least
   `overlap` (8 KiB) characters from the buffer end, and `min_emit` defaults to
   64 KiB. That is fine for files. For a live network stream it means the daemon
   must either buffer a whole message or accept holding up to `overlap`
   characters back. §5.3 shows where each applies.
3. **The native core covers only part of the patterns.** `native/src/lib.rs`
   covers 15 of the 23 deterministic types. `credit_card`, both `phone`
   patterns, the entropy tier, the contextual tier and the optional NER tiers are
   Python only (`NATIVE_CORE.md`). A Rust-only daemon would therefore silently
   **detect less** than the CLI. For a DLP product that is a regression, not an
   optimisation.
4. **The native crate is PyO3-only.** Its detection logic sits in the
   `#[pyfunction] detect` module, which is built as a `cdylib`. A Rust daemon can't
   link it as it stands.
5. **Output-changing backends are refused, with evidence.** re2 and Vectorscan
   were measured and rejected (Unicode `\b`/`\w` divergence, lookaround, no
   end-to-end gain); `fancy-regex` was built and rejected. Every new detection
   path has to pass the same byte-identity gate.
6. **Local-first is the product's core promise** (`ROADMAP.md`, "Guiding
   decision"). A network-facing service must be opt-in and must never become the
   default path. This RFC keeps to that: the daemon listens only on loopback,
   inside the host, and is packaged separately.

---

## 2. Threat model and non-goals

**In scope:** accidental exfiltration of secrets and PII by **unmodified**
workloads on a host the operator controls. Examples are an agent posting
repository contents to an LLM API, a service logging request bodies to a
third-party collector, or a batch job writing PII to a shared drop directory.

**Out of scope, stated so nobody assumes otherwise:**

- A malicious local user with root or `CAP_SYS_ADMIN` who wants to get around
  this. They can detach the programs.
- Processes outside the attached cgroup(s). Interception is scoped per cgroup by
  design.
- Covert channels: DNS tunnelling, timing, steganography inside an allowed
  destination.
- Encrypted traffic when TLS termination is not enabled. §6 turns this from a
  silent gap into an explicit policy.
- Anonymous pipes. fanotify cannot mark pipefs; pipelines keep using
  `… | safestream redact | …`.

---

## 3. Network interception: hook points

### 3.1 Why cgroup socket hooks rather than `sk_msg`, TC or TPROXY

| Mechanism | What it would take here | Verdict |
| --- | --- | --- |
| **`cgroup/connect4/6`** (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`) | Rewrite `user_ip4`/`user_port` at `connect()` time so the client's TCP handshake goes to `127.0.0.1:<daemon>`. No packet mangling, no conntrack, no routing rules. | **Chosen.** Works per cgroup (per workload, per container), is atomic to attach and detach with `bpf_link`, and fails closed if the daemon is down (the client gets `ECONNREFUSED`). |
| `sockops` (`BPF_PROG_TYPE_SOCK_OPS`) | `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` fires on the client socket after the handshake, when the source port is known. | **Chosen as a helper**: it records `(client src ip, src port) → original dst` so the daemon can recover the real destination (§3.3). |
| `cgroup/sendmsg4/6` | Sees UDP `sendmsg`/`sendto` destinations. | **Chosen as a helper**: it refuses UDP/443 (QUIC / HTTP/3) from monitored cgroups so clients fall back to TCP, which can be intercepted. Without this, any HTTP/3 client bypasses everything. |
| `sk_msg` + `sockmap` | Moves bytes between sockets inside the kernel; `bpf_msg_push_data`/`pop_data` can change lengths. | **Rejected for payload.** The verifier's instruction and loop limits rule out running the 23-pattern engine (let alone the Python tiers) in BPF, and the bytes are usually TLS ciphertext anyway. Redirecting to a userspace socket via sockmap just rebuilds `connect4` redirection with more moving parts. |
| TC ingress/egress + `TPROXY` | Packet-level capture and policy routing (`ip rule` + `fwmark`), iptables/nft TPROXY target. | **Deferred to a gateway mode (v2).** It is the right tool when the daemon runs on a router or node and intercepts traffic from **other** hosts or network namespaces it doesn't own. On a single host it adds routing state, conntrack and marking without giving anything `connect4` doesn't. |

### 3.2 Programs and maps

All programs are C compiled with clang (`-target bpf`) against the UAPI
`<linux/bpf.h>`. The sock_addr and sockops context structs are stable UAPI, so
v1 needs **no CO-RE or BTF relocations**, which keeps the build down to clang.
They are loaded by a Rust manager built on **aya**: a pure-Rust loader with no
libbpf, libelf or C dependency at runtime.

```c
// kernel/bpf/intercept.bpf.c   (sketch — Phase 2 fills it in)
struct { __uint(type, BPF_MAP_TYPE_HASH);   /* port → action */  } target_ports;
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); /* dst CIDR allow/deny */ } target_cidrs;
struct { __uint(type, BPF_MAP_TYPE_ARRAY);  /* daemon addr/port, mode, fail policy */ } config;
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); /* socket cookie → orig dst */ } pending;
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); /* (src ip, src port) → orig dst */ } orig_dst;
struct { __uint(type, BPF_MAP_TYPE_RINGBUF);  /* audit events, no payload */ } events;

SEC("cgroup/connect4")   int redirect4(struct bpf_sock_addr *ctx);
SEC("cgroup/connect6")   int redirect6(struct bpf_sock_addr *ctx);   // incl. v4-mapped
SEC("sockops")           int record_origin(struct bpf_sock_ops *ctx);
SEC("cgroup/sendmsg4")   int block_quic4(struct bpf_sock_addr *ctx);
SEC("cgroup/sendmsg6")   int block_quic6(struct bpf_sock_addr *ctx);
```

**`connect4` flow:**

1. `SOCK_DGRAM` to port 443 → return 0 (`EPERM`). A *connected* UDP socket
   sends without an address, so `sendmsg4/6` never sees it; the QUIC block has
   to live in `connect4/6` as well. Any other non-`SOCK_STREAM` socket → allow.
2. Look up `user_port` in `target_ports` and, if configured, `user_ip4` in
   `target_cidrs`. On no match, return 1 (allow, unchanged).
3. Store `pending[bpf_get_socket_cookie(ctx)] = {orig ip, orig port}`.
4. Rewrite `user_ip4 = 127.0.0.1` and `user_port = daemon_port`, then return 1.
5. Emit a `REDIRECTED` event (cookie, cgroup id, pid/tgid, original destination)
   to `events`.

**`sockops` flow** (on `ACTIVE_ESTABLISHED_CB`): look up the socket cookie in
`pending`, move the entry to `orig_dst[(local ip, local port)]`, and delete the
`pending` entry. The daemon's `accept()` returns the peer address, which is the
client's local ip and port, and looks up the real destination by it.

### 3.3 Not intercepting ourselves

The daemon's own upstream `connect()` calls must not be redirected back to
itself. The programs are attached **only** to the workload cgroups the operator
lists (`/sys/fs/cgroup/<slice>`), and the daemon runs in its own cgroup that is
never attached. That makes the exemption structural. A uid or mark check would
break the moment someone runs a workload as the daemon's user.

### 3.4 Target selection

The default target is ports `{80, 443}` plus operator-listed internal ports,
optionally narrowed by destination CIDRs. The operator can list LLM endpoint
hostnames. The manager resolves them and refreshes `target_cidrs` on a timer,
but DNS-derived CIDRs are advisory: CDN-fronted APIs move. The enforceable
policy is **by port, per cgroup**.

---

## 4. Kernel → userspace IPC

| | Transparent socket redirect (chosen for payload) | BPF ring buffer |
| --- | --- | --- |
| Carries | The live TCP byte stream, with backpressure from TCP flow control | Copies of records a BPF program chose to submit |
| Can inject modified data back? | **Yes**: the daemon writes the redacted stream on its own upstream connection | **No**: it is one-way, kernel to user |
| Size limits | None (a stream) | Each record is bounded; payload capture would need per-packet reassembly in userspace |
| Failure behaviour | Daemon down → `ECONNREFUSED` (**fails closed**) | Consumer too slow → records dropped (**fails open** for anything relying on it) |

So payload **never** goes through the ring buffer. It carries audit events
only: redirects, blocked QUIC attempts, attach and detach, and fail-closed
refusals. These events contain no content, which follows the existing rule that
reports record evidence, never content (`report.py`).

---

## 5. Stream resizing: how length changes stay consistent

### 5.1 TCP never has to be patched

Redaction changes lengths: `sk-ant-…` (≈100 bytes) becomes `[REDACTED:ANTHROPIC_KEY]`
(24). Patching TCP sequence and ack numbers in flight (the NAT-helper
approach) means tracking a per-connection delta table, fixing SACK blocks and
retransmissions, and failing badly on any mistake. The split-TCP design **avoids
it by construction**:

```
client ──TCP#1──▶ daemon (127.0.0.1:P) ──TCP#2──▶ upstream
         seq space A          ▲           seq space B
                     parse → decode → redact → re-frame
```

TCP#1 and TCP#2 are independent connections with independent sequence spaces,
each managed by the kernel's own TCP stack. The daemon reads messages from one
and writes different bytes to the other. There is no shared sequence to
desynchronise.

### 5.2 Framing is recomputed at L7, by the protocol library

The daemon is a real HTTP proxy (hyper), not a byte pump. It parses on the
client side and serialises again on the upstream side:

| Framing on the way in | What the daemon emits |
| --- | --- |
| HTTP/1.1 `Content-Length: N` | It buffers the body, up to `max_body_bytes` (default 8 MiB, the same knob and default as `api.py`), redacts it, and sends `Content-Length: N'`. If the body is over the limit, it answers `413` and closes (fails closed). |
| HTTP/1.1 `Transfer-Encoding: chunked` | It decodes the chunks into a text stream, runs `stream_windows`, and emits new chunks sized to the redacted segments. Chunk boundaries are not meaningful in HTTP semantics, so re-chunking is always allowed. |
| HTTP/2 (after TLS termination, via ALPN) | hyper terminates HTTP/2 on both sides. DATA frame lengths and flow-control windows are computed per side by the library. The daemon only sees request and response bodies. |
| `Content-Encoding: gzip`/`br`/`zstd` | It decompresses under a decompressed-size cap (a zip-bomb guard), redacts, re-encodes, and fixes `Content-Length`. An unknown encoding is refused, never passed through unscanned. |
| WebSocket | Deferred to v2. It needs frame-level re-masking and length re-encoding; for now, upgrades from monitored cgroups are refused by policy. |

### 5.3 Where text is redacted inside a body

Redacting raw JSON bytes can break the JSON. A match can span `\"` or `\n`
escapes, and a replacement has to stay a valid JSON string. So bodies with
`Content-Type: application/json` are **parsed, string values redacted after
unescaping, then serialised again**. Other text types (`text/*`, form bodies,
SSE) go through the streaming engine as-is. Binary types follow policy, and the
default is to block them to LLM endpoints.

**Requests** (egress, the primary DLP target) are bounded and small (prompts),
so the daemon buffers them whole: no latency trade-off, and the result is exact.
**Responses** are optional, with SSE handled by feeding the concatenated `data:`
text into `stream_windows`. That delays output by up to `overlap` characters.
The trade-off is deliberate and configurable: lowering `overlap` below
`min_safe_overlap` needs the existing `allow_unsafe_overlap`
opt-in.

---

## 6. HTTPS: the load-bearing constraint

Most LLM and SaaS traffic is TLS. Redirecting it through the daemon gives the
daemon **ciphertext**. No hook point changes that. `sk_msg`, TC and XDP all
see the same encrypted bytes. The realistic options:

| Option | Can redact? | Cost |
| --- | --- | --- |
| **A. TLS termination with a local CA** (the daemon sees the SNI, mints a leaf certificate from a CA the operator installs into the workloads' trust stores, and makes its own verified TLS connection upstream) | **Yes** | Needs the CA in each workload's trust store, which is a deployment step, not a code change. Breaks certificate-pinned clients, which are then **blocked**, not passed. The daemon holds a signing key, so it needs a key-protection story (§10.3). This is the standard enterprise-DLP pattern. |
| B. uprobes on `SSL_write`/`SSL_read` (libssl, BoringSSL, Go `crypto/tls`) | **No**: detect only | Reads plaintext before encryption, but the buffer can't safely be resized (`bpf_probe_write_user` is a debugging helper, taints the kernel, and can't change lengths). Useful for **detect and alert, or kill** (`bpf_send_signal`). Needs per-library offsets; statically linked Go and Rust binaries each need their own. |
| C. Explicit proxy (`HTTPS_PROXY`, SDK `base_url`) | Yes, with A's TLS termination | Needs application configuration. This is the unprivileged fallback (§10). |
| D. Pass-through by SNI allowlist | No | For destinations the operator trusts; recorded as `PASSTHROUGH` audit events. |

**Proposal:** A for listed LLM endpoints; D for an explicit allowlist; **block
everything else** on the targeted ports. B is a later, separate detection-only
tier. The daemon never forwards traffic it could not inspect unless it matches
an explicit pass-through rule.

---

## 7. Detection inside the daemon

### 7.1 Hyperscan/Vectorscan: still no

The brief asks for SIMD multi-pattern matching. The project has already measured
that path and rejected it (`PERFORMANCE_BACKENDS.md`): no lookaround support,
ASCII-only `\b`/`\w` (it **matches spans Python correctly rejects**), no end-to-end
gain, and a heavy native dependency. The existing Rust core already gets SIMD
where it pays off: the `regex` crate's memchr and aho-corasick literal
prefilters run at **400–1200 MB/s** on the credential patterns (`NATIVE_CORE.md`),
with byte-identical output. The daemon reuses that core rather than adding a
second engine with different semantics.

### 7.2 Making the native core linkable

**Implemented** (see `NATIVE_CORE.md`, "The crate as a Rust library").
`native/Cargo.toml` is `crate-type = ["cdylib", "rlib"]`, and PyO3 sits behind an
opt-in `python` feature that maturin enables. The default build is the plain Rust
library, so a Rust consumer needs no feature flags. The detection functions are
plain Rust (`pub fn detect(text: &str) -> Vec<Detection>` in byte offsets,
`detect_char_offsets` in Python's character offsets) with a thin `#[pyfunction]`
wrapper in `src/python.rs`. The Python wheel's API and its spec guard are
unchanged. The `tests/test_native_backend.py` differential gate covers the core
through the wheel, and `cargo test` covers it without Python.

### 7.3 Parity: a Python worker pool behind the Rust daemon

Because of 1.2(3), the default daemon mode is **full parity**:

```
tokio acceptor ─▶ HTTP parse / TLS / decode (Rust)
                 └─▶ bounded mpsc ─▶ Python engine workers (N processes)
                                       Redactor(backend="auto").redact(...)
                                       over a UNIX socketpair, length-prefixed
                 ◀─ redacted text + content-free stats ─┘
```

- The workers are the existing engine with the **same config file** as the CLI,
  so the network path and the CLI detect exactly the same things. This is the
  same rule `api.py` follows: "adds no detection logic of its own".
- Each worker runs under `RLIMIT_AS` (`memory_budget.enforce_address_space_limit`)
  and the seccomp inet block (`netguard_hard`). **A worker cannot open a network
  socket**; only the Rust side can.
- Rough budget: prompts are KBs to low MBs. At ~3 MB/s per Python worker
  (single-core, measured) a 100 KB prompt costs about 30 ms, which is small next
  to LLM latency. Workers scale with cores. `backend="auto"` picks up the native
  fast lane where it is installed.

`--engine native-only` skips the Python pool for throughput-critical internal
ports and **logs at startup which entity types it does not cover**. It is never
the default.

---

## 8. `io_uring` and "zero-copy"

- **Zero-copy doesn't fit redaction.** `splice`/`sendfile` move bytes that are
  not transformed; redaction must bring every byte into userspace, decode it and
  rewrite it (`ZERO_COPY.md` measured input I/O at ~2600–3800× the speed of
  detection). The daemon reuses buffers (`bytes::BytesMut` pools), which is where
  copying can actually be cut.
- **`io_uring` is deferred behind a feature flag.** Detection, not syscall
  overhead, sets the throughput ceiling. `io_uring` operations are submitted
  through a shared ring, so a per-syscall seccomp policy does not see them. That
  weakens the §10.3 sandbox, and several container runtimes' default seccomp
  profiles block `io_uring_setup` outright. The daemon uses tokio (epoll). A
  `uring` feature (tokio-uring or monoio) can be benchmarked in Phase 3 and
  adopted only on a measured end-to-end gain, with the seccomp profile updated
  to match.

---

## 9. File interception

### 9.1 What the kernel interfaces can and cannot do

- `FAN_OPEN_PERM` / `FAN_ACCESS_PERM` / `FAN_OPEN_EXEC_PERM` are **permission
  events on open or read**. The listener answers allow or deny; it **cannot
  change the data** and never sees `write()` calls.
- `FAN_CLOSE_WRITE` is an **asynchronous notification** after a writer closes.
  By then the data is in the page cache and may already be written back.
- BPF-LSM `file_permission` / `file_open` receive the file and the access mask,
  **not** the data being written. They can deny; they can't rewrite anything,
  and a BPF program couldn't run the detection engine anyway.

So "intercept file operations before disk synchronisation" isn't achievable
for redaction with these interfaces, and FUSE would be the only way to rewrite
writes inline, at a large performance and complexity cost. What **is**
achievable, and still a real guarantee, is **redact before consumption**:

### 9.2 Quarantine until scanned

1. The operator lists watched directories (for example an export drop, or a log
   shipper's input).
2. The daemon marks them with `FAN_CLOSE_WRITE | FAN_OPEN_PERM` using
   `FAN_MARK_FILESYSTEM` or `FAN_MARK_MOUNT` scoped to the path.
3. On `FAN_CLOSE_WRITE`, it records `(dev, ino)` as **dirty** in a pinned BPF hash
   map, then scans with the existing engine. It either redacts in place (through
   `_atomic`, so readers see the old file or the new one, never half of each) or
   moves the file to quarantine, depending on policy.
4. On `FAN_OPEN_PERM` from a non-exempt process, it **denies** a dirty inode
   until its scan completes, otherwise allows. The daemon's own scanner is
   exempt by pid.

### 9.3 Failing closed when the daemon dies

When a fanotify group is destroyed (the daemon crashes), the kernel **allows**
pending and future opens, so fanotify alone fails open. To prevent that, a
BPF-LSM program on `file_open` checks the **pinned** dirty-inode map and returns
`-EACCES` for dirty inodes regardless of whether the daemon is alive. The pinned
map outlives the daemon, and a restart re-scans every dirty inode. This needs
`CONFIG_BPF_LSM=y` **and** `bpf` in the active LSM list (`lsm=` boot
parameter), which the manager checks at startup. Without it, file mode starts
with an explicit "fails open on crash" warning, or refuses to start if
`--require-fail-closed` is set.

---

## 10. Degradation and hardening

### 10.1 Capability ladder (checked at startup, reported by `safestream kernel status`)

| Level | Needs | Mode |
| --- | --- | --- |
| 3 | `CAP_BPF` + `CAP_NET_ADMIN` + cgroup v2 + (for files) `CAP_SYS_ADMIN` + BPF-LSM | Transparent network redirect + fail-closed file quarantine |
| 2 | As 3, without BPF-LSM | Transparent network; file mode fails open on crash (warned) |
| 1 | Nothing | **Explicit proxy**: the unprivileged daemon listens on loopback and workloads set `HTTPS_PROXY`. Same redaction path, but needs application configuration. |
| 0 | Nothing | Existing CLI, library, REST API and MCP. **Unchanged.** |

Each level is chosen explicitly (`--mode transparent|proxy`) or by `--mode auto`,
which **reports** the level it reached. It never silently drops to a mode with
weaker guarantees than the operator asked for.

### 10.2 Privilege split

- **`safestream-kmgr`** (privileged, short-lived): loads and verifies the BPF
  objects, pins programs and maps under `/sys/fs/bpf/safestream/`, attaches
  `bpf_link`s to the listed cgroups, then exits. Pinned links keep the programs
  attached. `detach` unpins them.
- **`safestream-proxyd`** (unprivileged uid, own cgroup): the data plane. It
  holds no `CAP_BPF` and no `CAP_NET_ADMIN`. It reads `orig_dst` and consumes
  `events` through pinned map fds, opened via bpffs permissions set by `kmgr`
  (read-only for `orig_dst`).

### 10.3 Data-plane sandbox

- **seccomp allowlist** (not the denylist `netguard_hard` uses): only the
  syscalls tokio, rustls and the socketpair to the workers need.
  `io_uring_setup`, `ptrace`, `process_vm_*` and `bpf` are denied.
- **Egress restricted by its own cgroup hook**: the daemon's cgroup gets a
  `connect4/6` program that allows only the configured upstream ports and CIDRs,
  so a bug in the daemon can't reach arbitrary hosts. A network namespace can't
  do this, because the daemon **needs** egress.
- **Static rlimits**: `RLIMIT_AS` (reusing the admission math), `RLIMIT_NOFILE`,
  and `RLIMIT_CORE=0`.
- `PR_SET_DUMPABLE=0` and `MADV_DONTDUMP` on buffer pools: memory holding secrets
  must never reach a core dump or `/proc/<pid>/mem`.
- Buffers are zeroised on release (the `zeroize` crate). Payload is never logged,
  matching the invariant `api.py` already enforces.
- The CA private key (§6 A) is loaded from a file readable only by the daemon's
  uid, or from a PKCS#11 or TPM handle. Leaf certificates are minted in memory
  and short-lived.

---

## 11. Repository layout (proposed)

```
kernel/                          # separate, opt-in; its own Cargo workspace
  Cargo.toml                     # workspace: kmgr, proxyd, common
  Makefile                       # bpf objects → cargo build → tests
  bpf/
    include/                     # minimal bpf_helpers.h (vendored, dual BSD/GPL)
    intercept.bpf.c              # connect4/6, sockops, sendmsg4/6
    files.bpf.c                  # lsm/file_open backstop (Phase 2b)
  crates/
    common/                      # shared map key/value structs (#[repr(C)])
    kmgr/                        # aya loader: probe, load, pin, attach, detach, status
    proxyd/                      # tokio + hyper + rustls data plane
native/                          # unchanged API; becomes cdylib + rlib (§7.2)
tests/integration/               # root-only; skipped unless SAFESTREAM_KERNEL_TESTS=1
  conftest.py                    # netns + veth fixtures (pyroute2 or iproute2)
  test_transparent_http.py
  test_quic_block.py
  test_fail_closed.py
  test_file_quarantine.py
docs/KERNEL_ARCHITECTURE.md      # this file
```

The Python package gains only a `safestream kernel {status,attach,detach}`
wrapper, which calls `kmgr` when present and otherwise reports level 0 or 1. The
base install stays dependency-free, as the project requires.

---

## 12. Phased plan and exit gates

| Phase | Deliverable | Exit gate (all measured, none assumed) |
| --- | --- | --- |
| 2a | `intercept.bpf.c` + `kmgr` (probe, load, pin, attach, detach, status) | In a netns test: a plain HTTP `connect()` to a target port from an attached cgroup reaches a loopback echo listener, and `orig_dst` holds the real destination. A non-attached cgroup is untouched. UDP/443 gets `EPERM`. Detach leaves no programs or pins behind. |
| 2b | `files.bpf.c` + fanotify quarantine | A reader of a dirty file is denied until the scan finishes. After `kill -9` of the daemon, the reader is **still** denied (LSM backstop), or the test is skipped when BPF-LSM is inactive, with the reason logged. |
| 3a | `proxyd` with HTTP/1.1 (Content-Length + chunked) and the Python worker pool | Redacted upstream body == `Redactor.redact(body)` byte for byte on the corpus. Content-Length is correct. Chunked re-framing is valid. Oversized body → 413. Daemon down → client `ECONNREFUSED`. |
| 3b | TLS termination (rustls, local CA), HTTP/2, content-encoding, JSON-aware redaction | Same parity gate over HTTPS and HTTP/2. JSON bodies stay valid JSON. Pinned client → blocked with an audit event. |
| 3c | Benchmarks | Requests per second and p50/p99 added latency versus direct connections, per engine mode. Only if these show the ceiling is I/O rather than detection is `io_uring` evaluated. |
| 4 | `Makefile`, CI job (GitHub-hosted runners have sudo and cgroup v2), `tests/integration/` over veth pairs | End-to-end transparent redaction verified in CI. Default CI stays green without root, because the integration suite is opt-in. |

### Environment check (this dev container, 2026-09-30)

Kernel 6.18 with `CONFIG_BPF_SYSCALL`, `CGROUP_BPF`, `BPF_LSM`,
`FANOTIFY_ACCESS_PERMISSIONS`, `NETFILTER_XT_TARGET_TPROXY` and `IO_URING` all
`=y`. BTF is present, cgroup v2 is mounted at `/sys/fs/cgroup/unified`, a
`BPF_PROG_LOAD` probe succeeds, and `unshare -n` works. clang 18 and rustc 1.94
are installed, and crates.io is reachable. Not installed: `bpftool`, `iproute2`,
and libbpf headers. None is needed by the design above (UAPI headers only, aya
loader, veth set up through netlink from the test harness). Whether BPF-LSM is
**active** can't be seen here (securityfs isn't mounted), so the Phase 2b gate
probes for it at runtime.

---

## 13. Open decisions (need an owner's call before Phase 3b)

1. **TLS termination (§6 A).** Adopting a local CA is a deployment and policy
   commitment, not just code. If it is declined, the network path redacts
   plaintext HTTP and explicit-proxy traffic only, and **blocks** other TLS on
   targeted ports rather than passing it through.
2. **Default engine mode (§7.3).** The proposal is full parity through the
   Python worker pool, with `native-only` as an opt-in.
3. **Response-side redaction (§5.3).** The proposal is requests only in v1;
   responses and SSE optional, off by default.
4. **Distribution.** The proposal is a separate artifact (a static
   `safestream-kernel` binary and container image) that is never pulled in by
   `pip install safestream-redactor`.
