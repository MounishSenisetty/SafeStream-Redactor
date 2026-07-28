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

- **Offline guard (`netguard`)** blocks non-loopback connections made through Python's
  `socket` layer in the current process (and scheduler worker processes). It is a
  strong guard against accidental egress by this tool, its plugins, and its
  dependencies. It is **not** a container/host-level egress policy: native extensions
  making raw syscalls, or other processes on the machine, are out of its reach. For a
  hard boundary, run the container with networking disabled (`docker run --network
  none ...`) in addition to the guard.
- **Detection is probabilistic at the margins.** Tier-1 patterns are validator-backed
  and high-precision, but no detector guarantees complete recall on arbitrary text.
  Treat redacted output as risk-reduced, not certified-clean; keep humans in the loop
  where the stakes require it.
- **Run reports are content-free by design.** They contain entity-type names, counts,
  and sizes only. If you build tooling on top of the detection API, take care not to
  log `Detection.text` yourself.
- **Plugins run with full process privileges.** Only install detector plugins you
  trust; the entry-point loader executes their code. Plugin loading can be disabled
  entirely with `Redactor(load_plugins=False)`.
