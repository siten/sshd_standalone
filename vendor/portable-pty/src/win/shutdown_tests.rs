//! Resource checks use real Windows handles/processes, not SSH exit status.
use super::conpty::{ConPtyMasterPty, ConPtySystem};
use crate::{CommandBuilder, MasterPty, PtySize, PtySystem};
use filedescriptor::OwnedHandle;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::mem;
use std::os::windows::io::FromRawHandle;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessHandleCount,
};
use winapi::um::tlhelp32::*;

#[derive(Debug)]
struct Resources {
    handles: u32,
    threads: usize,
    hosts: BTreeSet<u32>,
}

impl Resources {
    fn capture() -> Self {
        let pid = unsafe { GetCurrentProcessId() };
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0) };
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let _snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as _) };
        let mut hosts = BTreeSet::new();
        let mut process: PROCESSENTRY32W = unsafe { mem::zeroed() };
        process.dwSize = mem::size_of_val(&process) as u32;
        let mut more = unsafe { Process32FirstW(snapshot, &mut process) };
        while more != 0 {
            let len = process.szExeFile.iter().position(|c| *c == 0).unwrap();
            let name = String::from_utf16_lossy(&process.szExeFile[..len]).to_ascii_lowercase();
            if process.th32ParentProcessID == pid
                && matches!(name.as_str(), "conhost.exe" | "openconsole.exe")
            {
                hosts.insert(process.th32ProcessID);
            }
            more = unsafe { Process32NextW(snapshot, &mut process) };
        }
        let mut entry: THREADENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of_val(&entry) as u32;
        let mut threads = 0;
        let mut more = unsafe { Thread32First(snapshot, &mut entry) };
        while more != 0 {
            if entry.th32OwnerProcessID == pid {
                threads += 1;
            }
            more = unsafe { Thread32Next(snapshot, &mut entry) };
        }
        drop(_snapshot);
        let mut handles = 0;
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handles) },
            0
        );
        Self {
            handles,
            threads,
            hosts,
        }
    }

    fn await_reclaimed(&self, sessions: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let now = Self::capture();
            // Warmed-up Windows runtime workers can fluctuate slightly. The
            // per-PTY cleanup worker itself must be explicitly joined below.
            // Inbox ConPTY before 24H2 leaks one *internal process handle* per
            // close (microsoft/terminal#17903). Do not dereference opaque HPCONs
            // or double-close possibly reused handles to work around that OS
            // bug. Allow at most that documented residual, never extra pipes,
            // child handles, readers, cleanup threads or running conhosts.
            if now.hosts == self.hosts
                && now.handles <= self.handles + sessions + 4
                && now.threads <= self.threads + 2
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "resources not reclaimed: baseline={:?}, current={:?}",
                self,
                now
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn await_hosts(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Self::capture().hosts != self.hosts {
            assert!(Instant::now() < deadline, "ConPTY host did not exit");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn backpressured_session() {
    let pair = ConPtySystem::default().openpty(PtySize::default()).unwrap();
    let master: &dyn MasterPty = pair.master.as_ref();
    let master = master.downcast_ref::<ConPtyMasterPty>().unwrap();
    let mut command = CommandBuilder::new("cmd.exe");
    command.args(["/D", "/Q", "/C", "echo BACKPRESSURE_READY & for /L %i in (1,1,1000000) do @echo 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]);
    let mut child = pair.slave.spawn_command(command).unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let reading = thread::spawn(move || {
        let mut text = Vec::new();
        let mut buf = [0u8; 1024];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            text.extend_from_slice(&buf[..n]);
            if String::from_utf8_lossy(&text).contains("BACKPRESSURE_READY") {
                ready_tx.send(()).unwrap();
                return reader;
            }
        }
        reader
    });
    let ready = ready_rx.recv_timeout(Duration::from_secs(5));
    if ready.is_err() {
        master
            .shutdown()
            .wait_timeout(Duration::from_secs(5))
            .unwrap();
        panic!("shell failed to start without a cursor reply: {:?}", ready);
    }
    let mut reader = reading.join().unwrap();
    // The child keeps emitting output while no read is issued. Both the pipe
    // and retained wrappers remain open when shutdown begins.
    thread::sleep(Duration::from_millis(100));
    assert!(
        child.try_wait().unwrap().is_none(),
        "output producer exited before the backpressure shutdown"
    );
    let shutdown = master.shutdown();
    let report = shutdown.wait_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        report.children_stopped
            && report.io_stopped
            && report.pipes_closed
            && report.close_returned
            && report.worker_joined
    );
    assert!(
        master.shutdown().try_wait().unwrap().is_some(),
        "shutdown must be idempotent"
    );
    assert!(reader.read(&mut [0u8; 1]).is_err());
    assert!(writer.write_all(b"exit\r\n").is_err());
    assert!(pair.master.try_clone_reader().is_err());
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("shell still alive after ConPTY shutdown");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn repeated_backpressured_shutdown_reclaims_pipes_hosts_and_threads() {
    let _guard = super::SHUTDOWN_TEST_GATE.lock().unwrap();
    let original = Resources::capture();
    backpressured_session();
    // DLL loading and Windows initialization may retain process-wide handles.
    // Warm those up once; all subsequent sessions must return to this baseline.
    original.await_hosts();
    let baseline = Resources::capture();
    for cycle in 0..20 {
        backpressured_session();
        baseline.await_reclaimed(cycle + 1);
    }
}

#[test]
fn drop_fallback_closes_a_pty_even_with_live_reader_and_writer_wrappers() {
    let _guard = super::SHUTDOWN_TEST_GATE.lock().unwrap();
    let original = Resources::capture();
    let warmup = ConPtySystem::default().openpty(PtySize::default()).unwrap();
    let warmup_master: &dyn MasterPty = warmup.master.as_ref();
    warmup_master
        .downcast_ref::<ConPtyMasterPty>()
        .unwrap()
        .shutdown()
        .wait_timeout(Duration::from_secs(5))
        .unwrap();
    drop(warmup);
    original.await_hosts();
    let baseline = Resources::capture();
    let pair = ConPtySystem::default().openpty(PtySize::default()).unwrap();
    let master: &dyn MasterPty = pair.master.as_ref();
    let shutdown = master
        .downcast_ref::<ConPtyMasterPty>()
        .unwrap()
        .shutdown_handle();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    drop(pair);
    let report = shutdown.wait_timeout(Duration::from_secs(5)).unwrap();
    assert!(report.worker_joined && report.close_returned && report.pipes_closed);
    assert!(reader.read(&mut [0u8; 1]).is_err());
    assert!(writer.write_all(b"x").is_err());
    baseline.await_reclaimed(1);
}

#[test]
fn failed_shell_start_still_completes_drop_cleanup() {
    let _guard = super::SHUTDOWN_TEST_GATE.lock().unwrap();
    let original = Resources::capture();
    let pair = ConPtySystem::default().openpty(PtySize::default()).unwrap();
    let master: &dyn MasterPty = pair.master.as_ref();
    let shutdown = master
        .downcast_ref::<ConPtyMasterPty>()
        .unwrap()
        .shutdown_handle();
    assert!(pair
        .slave
        .spawn_command(CommandBuilder::new(
            "C:/nonexistent-pty-regression/shell.exe"
        ))
        .is_err());
    drop(pair);
    let report = shutdown.wait_timeout(Duration::from_secs(5)).unwrap();
    assert!(report.children_stopped && report.output_drained && report.worker_joined);
    original.await_hosts();
}
