# Local portable-pty 0.9.0 patch

Source: the unmodified crates.io `portable-pty` 0.9.0 archive (crate SHA256
`b4a596a2b3d2752d94f51fac2d4a96737b8705dddd311a32b9af47211f08671e`).
The package manifest, license, sources, and examples are retained.

The unified Windows patch covers system ConPTY and sideloaded DLLs without OS
build checks:

- `psuedocon.rs`: disable cursor inheritance on every Windows version.
- `conpty.rs` / `shutdown.rs`: track pipe clones and in-flight synchronous I/O;
  reserve close/drain workers before creating an HPCON; stop registered clients,
  cancel forwarding I/O, drain output concurrently with `ClosePseudoConsole`,
  release pipes, and expose a joinable `ShutdownHandle` with monotonic milestones.
- `mod.rs`: share child process handles with cleanup, avoiding PID reuse races.
- `shutdown_tests.rs`: real backpressure, retained clones, failed startup,
  repeated close, process/thread/handle checks, and Drop fallback coverage.
- `Cargo.toml`: enable the existing winapi dependency's I/O cancellation and
  process/thread snapshot modules.

`ConPtyMasterPty::shutdown()` starts an idempotent close;
`shutdown_handle()` also allows observing Drop-initiated cleanup. Success from
`try_wait()` / `wait_timeout()` requires all milestones and both worker joins.

Unix sources and interfaces are unchanged. Windows API caveat: older inbox
ConPTY leaks one internal conhost process handle per close
([terminal#17903](https://github.com/microsoft/terminal/issues/17903)). Resource
tests explicitly allow this OS residual while rejecting accumulating pipe
handles, cleanup threads and live conhosts. This patch does not inspect opaque
HPCON layouts or close unowned handles to compensate for the OS defect.

See `../../docs/windows-pty-close-hang.md` for diagnosis and lifecycle details.
