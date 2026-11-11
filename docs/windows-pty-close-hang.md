# Windows ConPTY shutdown hang

Investigated on 2026-11-11 on Windows 10 build 19045. The server still accepted
TCP connections on port 2222 but sent no SSH banner. A Tokio worker was blocked
inside `ClosePseudoConsole`, waiting for a headless `conhost.exe` to exit.

## Root cause

`portable-pty` 0.9.0 enabled `PSEUDOCONSOLE_INHERIT_CURSOR` for every session.
On the affected system, conhost was still waiting for a cursor-position report
(`ESC[6n`) when its input pipe closed:

```text
Cursor initialization keeps calling ReadFile
  -> ERROR_BROKEN_PIPE sets the input thread's exit flag
  -> the outer loop checks only the pending cursor report
  -> repeated reads spin while holding the console lock
  -> the shutdown thread cannot acquire that lock
  -> ClosePseudoConsole waits indefinitely
```

Noninvasive, nonsuspending inspection with `cdb -pvr` confirmed:

- Server PID 27568 was waiting on handle `0x330`, which referred to conhost
  PID 31340. Its command line included `--inheritcursor`.
- Conhost thread 29220 had consumed over 17 CPU hours. Its pending-cursor flag
  was still set, while the input object recorded `0x8007006d`
  (`ERROR_BROKEN_PIPE`) and an exit request.
- The shutdown thread was waiting on the console lock owned by thread 29220.

The remaining 15 scheduler workers were parked, with no active I/O polling
observed. The exact Tokio driver-handoff sequence could not be reconstructed
from the stripped release symbols. The original missing cursor response and
input-disconnect trigger are also unknown.

Failure to drain the output pipe can cause a separate ConPTY shutdown deadlock,
but it was not the busy loop identified in this incident.

## Fix

The project patches `portable-pty` 0.9.0 through `[patch.crates-io]`.
All Windows builds and supported sideloaded `conpty.dll` implementations use the
same path. Cursor inheritance is disabled for every fresh SSH terminal.

Shutdown has explicit, observable milestones:

1. Reject new forwarding I/O and start a dedicated output drainer.
2. Stop registered client processes, using their original process handles.
3. Cancel in-flight forwarding reads/writes with `CancelSynchronousIo`, retrying
   across the registration/syscall race, and wait for those operations to end.
4. Release all forwarding pipe handles, including retained reader/writer clones.
5. Call `ClosePseudoConsole` on a separate worker while the reserved output pipe
   is continuously drained to a sink, independent of SSH backpressure.
6. Drain until EOF even if the close call returns early; release the reserved
   pipe, then join both workers. EOF and close-return ordering may vary.
7. Join the Tokio reader task before reporting normal shell exit.

Both OS workers are reserved before HPCON creation, so thread-creation failure
fails PTY creation. `shutdown()` is idempotent; `shutdown_handle()` also observes
Drop cleanup. A successful wait requires stopped clients/I/O, drained output,
closed pipes, a returned close call, and joined workers. Timeouts log the pending
milestones and report failure instead of claiming successful cleanup.

The drainer is necessary in practice: a Windows 10 backpressure regression still
hung when every output reader was closed before the close call. Draining across
the call follows the other shutdown strategy documented by Microsoft.

Unix sources and behavior are unchanged. A broken native implementation can
still exceed the shutdown deadline; the status identifies the stalled stage.

## Verification

Passed on Windows 10 build 19045:

- Project suite: 21 tests passed. Dependency suite: 7 tests passed.
- Release build and formatting checks passed.
- Pending synchronous reads and pipe-full writes are cancelled and joined.
- Retained wrappers no longer own native pipe handles after shutdown.
- Twenty backpressured closes check all milestones and worker joins, with no
  remaining conhosts or accumulating threads. Drop and startup-failure paths are
  also checked.
- An SSH backpressure test uses a four-thread blocking pool and twelve close
  cycles. Each cycle must finish cleanup and join the reader before proceeding;
  fresh connections alone do not count as cleanup success.

Older inbox ConPTY has a separate, confirmed native bug: it leaks one internal
conhost **process handle** per close ([terminal#17903](https://github.com/microsoft/terminal/issues/17903)).
The handle-count check explicitly allows at most that residual per session;
pipe closure, host exit and worker joins are checked independently. This patch
does not claim to fix that OS defect or dereference opaque HPCON internals.

Newer Windows and other platforms have not been tested on-device.

## References

- [ClosePseudoConsole documentation](https://learn.microsoft.com/en-us/windows/console/closepseudoconsole):
  calls return immediately starting with Windows 11 24H2, build 26100;
  earlier versions wait for the pseudoconsole to exit.
- [microsoft/terminal#1810](https://github.com/microsoft/terminal/issues/1810):
  cursor-inheritance shutdown race and the workaround for fresh terminals.
- [microsoft/terminal#17688](https://github.com/microsoft/terminal/issues/17688):
  output-draining requirements and related shutdown deadlocks.
