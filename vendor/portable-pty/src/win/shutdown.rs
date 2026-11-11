use super::psuedocon::PsuedoCon;
use filedescriptor::{FileDescriptor, OwnedHandle};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::{mpsc, Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use winapi::shared::winerror::{ERROR_BROKEN_PIPE, ERROR_NOT_FOUND};
use winapi::um::handleapi::DuplicateHandle;
use winapi::um::ioapiset::CancelSynchronousIo;
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentThread, GetCurrentThreadId};
use winapi::um::processthreadsapi::{GetExitCodeProcess, TerminateProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::THREAD_TERMINATE;

/// Monotonic shutdown milestones. io_stopped covers application forwarding I/O;
/// the reserved output drainer runs until EOF, possibly after the close call.
/// A successful wait joins both OS workers (the close worker joins the drainer).
#[derive(Clone, Debug, Default)]
pub struct ShutdownStatus {
    pub children_stopped: bool,
    pub io_stopped: bool,
    pub forwarding_pipes_closed: bool,
    pub output_drained: bool,
    pub pipes_closed: bool,
    pub close_returned: bool,
    pub worker_joined: bool,
    pub error: Option<String>,
}

struct Completion {
    status: Mutex<ShutdownStatus>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct ShutdownHandle(Arc<Completion>);

impl ShutdownHandle {
    pub fn status(&self) -> ShutdownStatus {
        self.0.status.lock().unwrap().clone()
    }

    /// Does not block waiting for the worker. None means shutdown is in flight.
    pub fn try_wait(&self) -> io::Result<Option<ShutdownStatus>> {
        let mut worker = self.0.worker.lock().unwrap();
        if worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return Ok(None);
        }
        if let Some(worker) = worker.take() {
            if worker.join().is_err() {
                self.0.status.lock().unwrap().error = Some("ConPTY cleanup worker panicked".into());
            } else {
                self.0.status.lock().unwrap().worker_joined = true;
            }
        }
        let status = self.status();
        if let Some(error) = &status.error {
            return Err(io::Error::other(error.clone()));
        }
        if !(status.children_stopped
            && status.io_stopped
            && status.forwarding_pipes_closed
            && status.output_drained
            && status.pipes_closed
            && status.close_returned
            && status.worker_joined)
        {
            return Err(io::Error::other(format!(
                "incomplete ConPTY shutdown: {:?}",
                status
            )));
        }
        Ok(Some(status))
    }

    pub fn wait_timeout(&self, timeout: Duration) -> io::Result<ShutdownStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("ConPTY shutdown timed out: {:?}", self.status()),
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub(super) fn fail(&self, error: String) {
        self.0.status.lock().unwrap().error = Some(error);
    }
}

#[derive(Default)]
struct IoState {
    stopping: bool,
    active: HashMap<u32, Arc<OwnedHandle>>,
    pipes: Vec<Weak<PipeEndpoint>>,
}

#[derive(Default)]
pub(super) struct PipeIo {
    state: Mutex<IoState>,
    changed: Condvar,
}

// Each calling thread caches a real handle. A pseudo-handle cannot be used to
// cancel another thread, and keeping this handle alive prevents thread-ID reuse.
thread_local! {
    static IO_THREAD: io::Result<Arc<OwnedHandle>> = unsafe {
        let mut handle = std::ptr::null_mut();
        if DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
            &mut handle, THREAD_TERMINATE, 0, 0) == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Arc::new(OwnedHandle::from_raw_handle(handle as _)))
        }
    };
}

struct Operation<'a> {
    io: &'a PipeIo,
    thread: u32,
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.io.state.lock().unwrap().active.remove(&self.thread);
        self.io.changed.notify_all();
    }
}

impl PipeIo {
    pub(super) fn stop(&self) {
        self.state.lock().unwrap().stopping = true;
    }

    fn begin(&self) -> io::Result<Operation<'_>> {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "PTY is shutting down",
            ));
        }
        let thread = unsafe { GetCurrentThreadId() };
        let handle = IO_THREAD.with(|handle| {
            handle
                .as_ref()
                .cloned()
                .map_err(|err| io::Error::other(err.to_string()))
        })?;
        state.active.insert(thread, handle);
        Ok(Operation { io: self, thread })
    }

    pub(super) fn pipe(self: &Arc<Self>, file: FileDescriptor) -> io::Result<Arc<PipeEndpoint>> {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "PTY is shutting down",
            ));
        }
        let pipe = Arc::new(PipeEndpoint {
            file: Mutex::new(Some(file)),
            io: self.clone(),
        });
        state.pipes.push(Arc::downgrade(&pipe));
        Ok(pipe)
    }

    fn stop_and_close(&self, completion: &Completion) {
        let pipes = {
            let mut state = self.state.lock().unwrap();
            state.stopping = true;
            let mut cancellation_error_logged = false;
            while !state.active.is_empty() {
                // Registration precedes the syscall. Retry cancellation to
                // cover the race where the thread has not entered Read/WriteFile
                // yet. Hold the registry lock so a completed operation cannot
                // unregister and run unrelated I/O while we cancel its thread.
                for handle in state.active.values() {
                    if unsafe { CancelSynchronousIo(handle.as_raw_handle() as _) } == 0 {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)
                            && !cancellation_error_logged
                        {
                            log::error!("ConPTY I/O cancellation failed: {}", error);
                            cancellation_error_logged = true;
                        }
                    }
                }
                state = self
                    .changed
                    .wait_timeout(state, Duration::from_millis(5))
                    .unwrap()
                    .0;
            }
            state
                .pipes
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        completion.status.lock().unwrap().io_stopped = true;
        // No in-flight syscalls and no new ones can start. Close the actual
        // handles, even if application reader/writer wrappers are still alive.
        for pipe in pipes {
            drop(pipe.file.lock().unwrap().take());
        }
        completion.status.lock().unwrap().forwarding_pipes_closed = true;
    }
}

pub(super) struct PipeEndpoint {
    file: Mutex<Option<FileDescriptor>>,
    io: Arc<PipeIo>,
}

impl PipeEndpoint {
    pub(super) fn try_clone(&self) -> io::Result<Arc<Self>> {
        let file = self.file.lock().unwrap();
        let file = file
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "PTY pipe is closed"))?;
        self.io.pipe(file.try_clone().map_err(io::Error::other)?)
    }

    fn with_io<T>(
        &self,
        action: impl FnOnce(&mut FileDescriptor) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut file = self.file.lock().unwrap();
        let _operation = self.io.begin()?;
        action(
            file.as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "PTY pipe is closed"))?,
        )
    }
}

pub(super) struct PipeReader(pub Arc<PipeEndpoint>);

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.with_io(|file| file.read(buf))
    }
}

pub(super) struct PipeWriter(pub Arc<PipeEndpoint>);

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.with_io(|file| file.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.with_io(Write::flush)
    }
}

pub(super) struct ShutdownRequest {
    pub con: PsuedoCon,
    pub children: Vec<Arc<Mutex<OwnedHandle>>>,
}

/// Reserve the worker before creating an HPCON. Failure to spawn fails openpty,
/// so Drop never has to allocate a thread or fall back to synchronous cleanup.
pub(super) fn start_worker(
    io: Arc<PipeIo>,
    mut output: FileDescriptor,
) -> io::Result<(mpsc::Sender<ShutdownRequest>, ShutdownHandle)> {
    let (tx, rx) = mpsc::channel::<ShutdownRequest>();
    let completion = Arc::new(Completion {
        status: Mutex::new(ShutdownStatus::default()),
        worker: Mutex::new(None),
    });
    let (drain_tx, drain_rx) = mpsc::channel();
    let drain_completion = completion.clone();
    let drain = thread::Builder::new()
        .name("conpty-drain".into())
        .spawn(move || {
            if drain_rx.recv().is_ok() {
                // Never forward to a bounded SSH queue during shutdown. Drain all
                // remaining output until EOF, including after ClosePseudoConsole
                // returns on newer implementations.
                let result = io::copy(&mut output, &mut io::sink());
                drop(output);
                let mut status = drain_completion.status.lock().unwrap();
                match result {
                    Ok(_) => status.output_drained = true,
                    Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => {
                        status.output_drained = true
                    }
                    Err(error) => {
                        status.error = Some(format!("ConPTY output drain failed: {}", error))
                    }
                }
            }
        })?;
    let worker_completion = completion.clone();
    let worker = thread::Builder::new()
        .name("conpty-close".into())
        .spawn(move || {
            if let Ok(request) = rx.recv() {
                let _ = drain_tx.send(());
                // Stop output producers first. An unresponsive console client must
                // not keep issuing console API calls during old conhost shutdown.
                // Shared process handles identify the original process, not a PID
                // that Windows might already have reused.
                for child in &request.children {
                    let child = child.lock().unwrap();
                    let mut code = 0;
                    let handle = child.as_raw_handle() as _;
                    if unsafe { GetExitCodeProcess(handle, &mut code) } != 0 && code == STILL_ACTIVE
                    {
                        unsafe { TerminateProcess(handle, 1) };
                    }
                }
                for child in &request.children {
                    if unsafe {
                        WaitForSingleObject(child.lock().unwrap().as_raw_handle() as _, 5000)
                    } != WAIT_OBJECT_0
                    {
                        worker_completion.status.lock().unwrap().error =
                            Some("ConPTY client did not terminate within 5 seconds".into());
                    }
                }
                {
                    let mut status = worker_completion.status.lock().unwrap();
                    status.children_stopped = status.error.is_none();
                }
                io.stop_and_close(&worker_completion);
                // This is the only normal owner that destroys PsuedoCon.
                drop(request.con);
                worker_completion.status.lock().unwrap().close_returned = true;
                if drain.join().is_err() {
                    worker_completion.status.lock().unwrap().error =
                        Some("ConPTY drain worker panicked".into());
                }
                let mut status = worker_completion.status.lock().unwrap();
                status.pipes_closed = status.forwarding_pipes_closed;
            } else {
                // Creation failed before an HPCON was transferred. Release the
                // reserved drainer and join it, too.
                drop(drain_tx);
                let _ = drain.join();
            }
        })?;
    *completion.worker.lock().unwrap() = Some(worker);
    Ok((tx, ShutdownHandle(completion)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use filedescriptor::Pipe;

    fn completion() -> Completion {
        Completion {
            status: Mutex::new(ShutdownStatus::default()),
            worker: Mutex::new(None),
        }
    }

    fn await_active(io: &PipeIo) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while io.state.lock().unwrap().active.is_empty() {
            assert!(Instant::now() < deadline, "pipe operation never started");
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn shutdown_cancels_a_pending_read_and_closes_retained_clones() {
        let _guard = super::super::SHUTDOWN_TEST_GATE.lock().unwrap();
        let pipe = Pipe::new().unwrap();
        let io = Arc::new(PipeIo::default());
        let original = io.pipe(pipe.read).unwrap();
        let retained = original.try_clone().unwrap();
        let mut reader = PipeReader(retained.clone());
        let (tx, rx) = mpsc::channel();
        let reading = thread::spawn(move || tx.send(reader.read(&mut [0u8; 16])).unwrap());
        await_active(&io);
        let completion = completion();
        io.stop_and_close(&completion);
        assert!(rx.recv_timeout(Duration::from_secs(3)).unwrap().is_err());
        reading.join().unwrap();
        assert!(completion.status.lock().unwrap().io_stopped);
        assert!(completion.status.lock().unwrap().forwarding_pipes_closed);
        assert!(original.file.lock().unwrap().is_none());
        assert!(retained.file.lock().unwrap().is_none());
        assert!(retained.try_clone().is_err());
        // Keep the write end open until now: EOF cannot have ended the read.
        drop(pipe.write);
    }

    #[test]
    fn shutdown_cancels_a_write_blocked_by_output_backpressure() {
        let _guard = super::super::SHUTDOWN_TEST_GATE.lock().unwrap();
        let pipe = Pipe::new().unwrap();
        let io = Arc::new(PipeIo::default());
        let endpoint = io.pipe(pipe.write).unwrap();
        let mut writer = PipeWriter(endpoint.clone());
        let (tx, rx) = mpsc::channel();
        let writing =
            thread::spawn(move || tx.send(writer.write_all(&vec![b'x'; 1024 * 1024])).unwrap());
        await_active(&io);
        thread::sleep(Duration::from_millis(30));
        assert!(
            rx.try_recv().is_err(),
            "write did not encounter backpressure"
        );
        io.stop_and_close(&completion());
        assert!(rx.recv_timeout(Duration::from_secs(3)).unwrap().is_err());
        writing.join().unwrap();
        assert!(endpoint.file.lock().unwrap().is_none());
        drop(pipe.read);
    }
}
