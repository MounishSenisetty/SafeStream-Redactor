# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/MounishSenisetty/SafeStream-Redactor/security/advisories/new)
rather than opening a public issue. Reports are acknowledged within a week; a fix or
mitigation plan follows in the advisory thread before any public disclosure.

When reporting, include the version, a minimal reproduction, and — for detection-bypass
reports — a sample input that should have been redacted but wasn't. Never include real
credentials or personal data in a report; construct synthetic examples.

## Supported versions

The latest released version receives security fixes. Older versions are not patched;
upgrade to the current release.

## Threat model: what the guarantees do and do not cover

Being explicit about limits is part of the security posture:

- **Offline guard (`netguard`, default)** blocks non-loopback connections made through
  Python's `socket` layer in the current process (and scheduler worker processes). It is
  a strong guard against accidental egress by this tool, its plugins, and its
  dependencies. It is **not** a container/host-level egress policy: native extensions
  making raw syscalls, or other processes on the machine, are out of its reach.
- **Hard offline modes (`--offline-hard`, opt-in, Linux).** For containment that also
  covers native code and raw syscalls, two kernel-enforced modes are available and are
  applied before any worker process is forked (so children inherit them):
  - **`seccomp`** installs a seccomp-bpf filter that makes `socket(2)` for `AF_INET`/
    `AF_INET6` fail with `EACCES` for this process and every child. **Covers:** all new
    IPv4/IPv6 socket creation, native code included. **Does not cover:** already-open
    sockets, `AF_UNIX`/`AF_NETLINK`, or filesystem exfiltration. Classic seccomp-bpf
    cannot read the `sockaddr` pointer, so it cannot allow loopback while blocking
    external by address — it blocks IP-socket *creation* outright (loopback included).
  - **`netns`** enters a new network namespace via `unshare(CLONE_NEWNET)` whose only
    interface is a down loopback. **Covers:** all network access by this process and its
    children — every protocol, loopback included. **Does not cover:** other processes on
    the host, or filesystem exfiltration; requires `CAP_SYS_ADMIN` or unprivileged
    user-namespace support.
  - Both **fail closed to a warning, not an error**: where the kernel refuses the
    operation, the run continues under the in-process guard and says so. Neither applies
    to `serve`/`mcp-serve`, which need loopback.
- **Strongest boundary remains the runtime you control.** For whole-container isolation,
  run with networking disabled (`docker run --network none ...`) in addition to any of
  the above.
- **Detection is probabilistic at the margins.** Tier-1 patterns are validator-backed
  and high-precision, but no detector guarantees complete recall on arbitrary text.
  Treat redacted output as risk-reduced, not certified-clean; keep humans in the loop
  where the stakes require it.
- **Run reports are content-free by design.** They contain entity-type names, counts,
  and sizes only. If you build tooling on top of the detection API, take care not to
  log `Detection.text` yourself.
- **Plugins run with full process privileges, so loading them is opt-in.** Installing
  a package that registers a detector does nothing until you enable plugins with
  `Redactor(load_plugins=True)`, `--enable-plugins`, or `[plugins] enabled = true`; the
  entry-point loader then executes their code. Enable plugins only when you trust
  every installed package that provides one. While plugins are disabled, discovery
  reads entry-point metadata only (to warn about skipped plugins), never plugin code.
- **The web playground (`safestream ui`) is local-only by configuration.** The
  launcher binds Streamlit to 127.0.0.1, turns off its browser usage statistics and
  its "Deploy" button, caps uploads at 5 MiB, and the page installs the offline network
  guard. Starting the page any other way (plain `streamlit run`) keeps Streamlit's
  defaults: all interfaces and telemetry on. The page then shows a warning instead of
  its local-only banner.
- **`detect` hides matched text by default.** Findings are reported by type,
  location, and confidence so the output is safe for CI logs; `--show-text` reveals
  the values for local triage only.
- **Pseudonymization is reversible, not anonymization.** `pseudonymize` mode emits a
  deterministic keyed token (HMAC-SHA256 of the value under your `hmac_key`). This
  preserves referential integrity — the same value always yields the same token — but
  it therefore leaks value equality, and because the mapping is deterministic and
  keyed, anyone holding the key can invert any low-cardinality domain (all SSNs, all
  phone numbers) by brute force. Use a strong, secret, high-entropy key; store it like
  a database credential; and treat the output as pseudonymized (re-identifiable by the
  key holder), never as anonymized. If you need irreversibility, use `replace`/`mask`;
  if you need equality-hiding, a per-value random salt is required (which sacrifices
  the deterministic-token property).
