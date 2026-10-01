# File-system DLP: `safestream fanotify`

A Linux daemon that watches directory trees and acts on files that contain
secrets or PII: it logs them, redacts them in place, or blocks reads of them.

```bash
# log what lands in the tree (paths, types and counts; never the matched text)
sudo safestream fanotify --watch /srv/exports --mode audit

# rewrite each file with every detection redacted, right after its writer closes it
sudo safestream fanotify --watch /srv/exports --mode redact --backend native

# deny every read of a file that contains a detection
sudo safestream fanotify --watch /srv/exports --watch /var/log/app --mode block
```

Options: `--config POLICY.toml` (the same detection settings as `redact`),
`--backend native` (the compiled core; same verdicts, much faster), `--max-scan-bytes`
(default 64 MiB), `--fail-open`, `--inotify`, `--enable-plugins`. The daemon runs
with the offline network guard on, and stops cleanly on SIGINT/SIGTERM.

## Modes

| Mode | Kernel interface | What happens |
| --- | --- | --- |
| `audit` | `FAN_CLOSE_WRITE` | After a writer closes a file, scan it and log one JSON line per file with findings. |
| `redact` | `FAN_CLOSE_WRITE` | As `audit`, then rewrite the file atomically (temp file renamed over it) with every detection redacted. The daemon ignores events from its own rewrite. |
| `block` | `FAN_ACCESS_PERM` (`FAN_CLASS_CONTENT`) | Every `read()` of a watched file waits for the daemon's verdict. A file that contains a detection is denied: the reader gets `EPERM`. Verdicts are cached per (device, inode) and invalidated when the size or timestamps change, so a file is scanned once per version; the close-after-write scan pre-fills the cache. |

Log records are JSON lines on stdout:

```json
{"ts": 1790856323.885, "event": "finding", "path": "/srv/exports/a.txt", "types": {"aws_key": 1}, "action": "logged"}
{"ts": 1790856323.886, "event": "blocked", "path": "/srv/exports/a.txt", "pid": 3366, "types": {"aws_key": 1}}
```

`blocked` is logged once per file version and reading process: `FAN_ACCESS_PERM`
fires on every `read()` call. Other events: `watching`, `fallback`, `oversize`,
`error`.

In `block` mode a file that cannot be scanned (larger than `--max-scan-bytes`, or a
read error) is **denied** unless `--fail-open` is given: a DLP control fails closed.

## What fanotify can and cannot do

`fanotify` has no event that exposes a `write()`'s data before it reaches the file.
Permission events (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`) let a daemon allow or deny an
*access*; the pre-content events of Linux 6.14+ (`FAN_PRE_ACCESS`) report the byte
*range* about to be accessed, for hierarchical storage, not the writer's buffer.
So no mode scans a write in flight and refuses it. `block` stops secrets from being
**read back out** of the watched tree (copied, uploaded, attached), and `redact`
removes them right after the writer closes the file. Rejecting the write itself needs
a different mechanism: an LSM or eBPF hook on `write`, or a FUSE file system in front
of the directory.

Other limits:

- **Reads through `mmap`** do not generate `FAN_ACCESS_PERM` events, so `block` does
  not see them.
- **New directories** are marked by a periodic rescan (every 2 s), so a file written
  into a brand-new directory in that window is not covered until the next scan.
- **`redact` has a window**: between the writer's close and the rewrite, another
  process can read the original. Use `block` where that matters.
- **Writes are not blocked**: in `block` mode the writer itself never reads through
  the daemon, and files are still created with the secret in them.
- Inode marks cover each watched directory's direct children, and the daemon marks
  every subdirectory. Hard links to a watched file from outside the tree are reached
  through the same inode only if the directory they live in is watched.

## Privileges and the fallback

`fanotify_init` needs `CAP_SYS_ADMIN`. Without it:

- `audit` and `redact` fall back to **inotify** (`IN_CLOSE_WRITE`, plus files moved
  into the tree), which any user can use on files they can read, and log a
  `fallback` record saying so. `--inotify` selects this backend explicitly.
- `block` **refuses to start** (exit 2): nothing but fanotify permission events can
  enforce it, and the daemon never pretends to protect what it cannot.

## Tests

`tests/test_watch.py` runs the inotify paths and the fallback logic as any user,
and the fanotify paths (real denials, real redaction) only as root. CI runs that file
a second time with `sudo`, so the kernel paths are exercised on every push.
