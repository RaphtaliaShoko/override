# Self-resilience (critical requirement)

Once `override` starts, nothing that happens to its on-disk executable can crash
it or stop it — including deliberately shredding its own binary.

See also: [architecture.md](architecture.md), [design.md](design.md),
[security.md](security.md).

---

**Mechanism (Linux):** at startup, before touching any target, the process
copies its own executable image (`/proc/self/exe`) into an anonymous,
memory-backed file via `memfd_create(2)` and **re-executes itself from that
memfd** with `fexecve(2)` (an `execveat` on the memfd with `AT_EMPTY_PATH`).
After the re-exec the running image is backed entirely by the anonymous memfd, so
unlinking, truncating, or overwriting the original on-disk file cannot unmap code
pages or trigger `SIGBUS`.

**Loop guard (belt and suspenders).** Two independent checks stop the re-exec
from recurring forever (each recursion would allocate a fresh memfd):

1. a guard environment variable (`OVERRIDE_MEMFD_REEXEC`) set on the child — the
   fast path, no syscall; and
2. an **env-independent** check: after re-exec, `/proc/self/exe` resolves to a
   `/memfd:…` target, which the process detects and refuses to re-exec on.

The env var alone is not sufficient — a sandbox or CI that sanitizes the
environment could strip it between the re-exec and the child's startup, and the
child would then loop. The `/proc/self/exe` check cannot be stripped, so it
breaks the loop even when the env var is gone. (Under `--verbose` the resident
child logs `running from in-memory image`.)

This is combined with the **static musl** build so there are also no shared
objects to lose. The memfd step is **best-effort and non-critical**: if it is
unavailable it logs a note under `--verbose` and continues, relying on the static
image already being resident — see [design.md](design.md).

**Platform scope / limitations:** the in-memory re-exec is implemented on
**Linux** (`memfd_create` ≥ Linux 3.17, `execveat` ≥ 3.19) and on **FreeBSD**
(the equivalent `shm_open(SHM_ANON)` + `fexecve`, with the executable path
resolved through the `kern.proc.pathname` sysctl). On every other platform
(OpenBSD, DragonFly, NetBSD, macOS, …) the re-exec step is a graceful no-op:
build statically so the OS keeps mapped executable pages resident after unlink.
Linux is the primary, fully-tested target; the FreeBSD path compiles for
`x86_64-unknown-freebsd` but the integration test that exercises self-shredding
runs on Linux. The `install.sh` release installer remains Linux-only.

An automated integration test (`self_resilience_shreds_own_binary`) copies the
binary into a temp dir, runs it against dummy files **plus its own copy**, and
asserts it completes and destroys everything.
