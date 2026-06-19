# Design: automatic `/etc/hosts` management for reverse mode

## Context

Reverse mode (`--reverse`) requires the user to manually redirect each monitored hostname to `127.0.0.1` in `/etc/hosts` and to remove those lines afterward. This is the most error-prone step in the workflow: it is easy to forget the cleanup, leaving the machine unable to reach the real hosts, and easy to get the ordering wrong (editing `/etc/hosts` before proxyspy has resolved the real upstream IPs, which trips the loopback guard). This feature lets proxyspy add and remove those redirects itself, behind an opt-in flag, so a session is self-contained: start it, use it, Ctrl-C, and the file is back to how it was.

It is deliberately **not** part of the initial reverse-mode cut — it mutates a system file and deserves its own change with its own tests.

## Decisions

* **Opt-in** via `--manage-hosts`. Default reverse-mode behavior is unchanged; `/etc/hosts` is only ever touched when this flag is present.
* **Atomic write + one backup.** On first mutation, copy `/etc/hosts` to `/etc/hosts.proxyspy.bak`. Every write goes to a temp file in `/etc` then `os.replace()` onto `/etc/hosts`, so the file is never observed half-written.
* **Explicit recovery** via `--restore-hosts`: a standalone mode that strips the proxyspy fence from `/etc/hosts` and exits, complementing the automatic self-heal on the next managed start.

## The managed block

proxyspy owns exactly one fenced region and never reads or rewrites anything outside it:

```
# >>> proxyspy >>>
# Managed by proxyspy (PID 12345). Do not edit by hand.
127.0.0.1 repo.anaconda.com
127.0.0.1 anaconda.com
# <<< proxyspy <<<
```

* The fence markers are fixed string constants. Add/remove operate purely by locating these two lines; everything between them is ours, everything else is preserved byte-for-byte (including the user's own entries, comments, and trailing newline conventions).
* Only the **declared, non-loopback-pinned** hosts that proxyspy actually serves are written. `--map`-pinned hosts are still written (the client must still be redirected to us); the pin only affects where *we* connect upstream.

## Sequencing (the load-bearing part)

The ordering is what makes this safe. On a `--manage-hosts` start, in this exact order:

1. **Self-heal:** strip any existing proxyspy block from `/etc/hosts`. A block here means a prior run died without cleaning up; removing it first restores clean DNS.
2. **Resolve:** run the existing startup resolution (`resolve_upstream`) for each declared host. The file is clean at this point, so the OS resolver returns the real upstream IPs. The loopback guard remains as belt-and-suspenders.
3. **Write:** create the backup (once), then write the fresh managed block via the atomic path.
4. **Serve:** `serve_forever()` as today.
5. **Remove:** on exit, strip the block (atomic write) and leave the backup in place.

Because step 1 precedes step 2, a crashed previous run self-corrects on the next start, and the loopback guard stops being load-bearing.

## Cleanup on exit — layered, because SIGKILL can't be caught

* **Clean exit / Ctrl-C:** the existing `try/finally` around `serve_forever()` calls the block-removal in the `finally`.
* **SIGTERM / SIGINT:** install handlers that perform block removal then re-raise / exit. (SIGINT already surfaces as `KeyboardInterrupt`; SIGTERM needs an explicit handler.)
* **SIGKILL / power loss:** uncatchable, so the block *can* be left behind. This is covered by self-heal (step 1) and by `--restore-hosts`, not by signal handling. This layering is intentional: signal handlers are best-effort, self-heal is the guarantee.

## Implementation sketch

All in `proxyspy.py`; the file-mutation logic is isolated so resolution and serving are untouched.

* Constants: `HOSTS_PATH = "/etc/hosts"`, `HOSTS_BAK = "/etc/hosts.proxyspy.bak"`, `FENCE_BEGIN`, `FENCE_END`.
* `def _strip_managed_block(text) -> str`: pure function; returns `text` with the fenced region (inclusive) removed, idempotent if absent. Pure string in / string out so it is trivially unit-testable without touching a real file.
* `def _atomic_write(path, text)`: write to a temp file in the same directory, `flush`+`fsync`, `os.replace(tmp, path)`.
* `def write_managed_hosts(hosts)`: read `/etc/hosts`; if no backup exists, copy to `HOSTS_BAK`; `new = _strip_managed_block(current) + fenced(hosts)`; `_atomic_write`. (Strip-then-append keeps it idempotent across restarts.)
* `def remove_managed_hosts()`: read; `_atomic_write(_strip_managed_block(current))` only if a block is present.
* CLI:
  * `--manage-hosts` (store_true; only valid with `--reverse`).
  * `--restore-hosts` (store_true; standalone — like `--reverse`, forbids a command; calls `remove_managed_hosts()` and returns. Does not require `--reverse`.).
* `main()` wiring (reverse branch only):
  * Before resolution, if `--manage-hosts`: `remove_managed_hosts()` (self-heal).
  * After successful resolution and before `serve_forever()`: `write_managed_hosts(declared_hosts_being_served)`; register a SIGTERM handler and ensure the `finally` removes the block.
  * Log clearly what was written and that it will be removed on exit.

## Permissions & platform

* Editing `/etc/hosts` requires root, which reverse mode already needs for port 443. If the write fails with `PermissionError`, abort startup with a clear message rather than serving with a half-applied state.
* Document Windows' equivalent path (`C:\Windows\System32\drivers\etc\hosts`) as explicitly **out of scope** for this iteration; gate the feature to POSIX and error cleanly elsewhere. (The rest of proxyspy is cross-platform; this piece is not, initially.)

## Verification

* **Unit (no root, no network):** `_strip_managed_block` against fixtures — absent block (no-op), present block (removed, surrounding lines intact), block at start/middle/end of file, missing trailing newline, two blocks (defensive: strip all). `write`/`remove` against a temp file passed via a parameterized path (refactor the path to a parameter so tests don't touch real `/etc/hosts`).
* **Integration (root, gated):** a test marked to skip unless running as root and an env opt-in (e.g. `PROXYSPY_TEST_HOSTS=1`), since it mutates the real `/etc/hosts`. Start `--reverse --manage-hosts --intercept-host example.com`, assert the block appears with the right line, connect through it, stop, assert the block is gone and `/etc/hosts` matches the pre-run content. A second test kills `-9` mid-session, then starts again and asserts self-heal removed the stale block.
* **Manual:** the README reverse-mode workflow, minus the manual `/etc/hosts` edits, plus a `kill -9` + restart to demonstrate self-heal and a `--restore-hosts` run.

## Open question for later

Whether to also manage hosts that arrive via SNI but weren't declared up front (currently those fall through to a direct resolve). For now, `--manage-hosts` only writes declared hosts; on-the-fly hosts still require a manual `/etc/hosts` entry, which is consistent with needing to know them in advance to redirect a client at all.
