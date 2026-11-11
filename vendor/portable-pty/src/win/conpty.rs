use crate::cmdbuilder::CommandBuilder;
use crate::win::psuedocon::PsuedoCon;
use crate::win::shutdown::{self, PipeEndpoint, PipeIo, PipeReader, PipeWriter, ShutdownRequest};
use crate::{Child, MasterPty, PtyPair, PtySize, PtySystem, SlavePty};
use anyhow::Error;
use filedescriptor::{OwnedHandle, Pipe};
use std::sync::{mpsc, Arc, Mutex};
use winapi::um::wincon::COORD;

pub use crate::win::shutdown::{ShutdownHandle, ShutdownStatus};

#[derive(Default)]
pub struct ConPtySystem {}

impl PtySystem for ConPtySystem {
    fn openpty(&self, size: PtySize) -> anyhow::Result<PtyPair> {
        let stdin = Pipe::new()?;
        let stdout = Pipe::new()?;
        let io = Arc::new(PipeIo::default());
        let readable = io.pipe(stdout.read.try_clone()?)?;
        let writable = io.pipe(stdin.write)?;
        // Reserve a separate output reader for teardown. It is never exposed
        // to SSH forwarding and is drained concurrently with ClosePseudoConsole.
        let (close_tx, shutdown) = shutdown::start_worker(io.clone(), stdout.read)?;

        let con = PsuedoCon::new(
            COORD {
                X: size.cols as i16,
                Y: size.rows as i16,
            },
            stdin.read,
            stdout.write,
        )?;

        let master = ConPtyMasterPty {
            inner: Arc::new(Mutex::new(Inner {
                con: Some(con),
                readable,
                writable: Some(writable),
                close_tx: Some(close_tx),
                shutdown,
                io,
                children: Vec::new(),
                size,
            })),
        };

        let slave = ConPtySlavePty {
            inner: master.inner.clone(),
        };

        Ok(PtyPair {
            master: Box::new(master),
            slave: Box::new(slave),
        })
    }
}

struct Inner {
    con: Option<PsuedoCon>,
    readable: Arc<PipeEndpoint>,
    writable: Option<Arc<PipeEndpoint>>,
    close_tx: Option<mpsc::Sender<ShutdownRequest>>,
    shutdown: ShutdownHandle,
    io: Arc<PipeIo>,
    children: Vec<Arc<Mutex<OwnedHandle>>>,
    size: PtySize,
}

impl Inner {
    fn begin_shutdown(&mut self) -> ShutdownHandle {
        if let Some(con) = self.con.take() {
            self.io.stop();
            let request = ShutdownRequest {
                con,
                children: std::mem::take(&mut self.children),
            };
            if let Err(err) = self.close_tx.take().unwrap().send(request) {
                // The pre-created worker unexpectedly exited. Never destroy
                // the returned HPCON on the calling (possibly async) thread.
                std::mem::forget(err.0.con);
                self.shutdown
                    .fail("ConPTY cleanup worker disconnected".into());
                log::error!("ConPTY cleanup worker disconnected; HPCON not released");
            }
        }
        self.shutdown.clone()
    }

    pub fn resize(
        &mut self,
        num_rows: u16,
        num_cols: u16,
        pixel_width: u16,
        pixel_height: u16,
    ) -> Result<(), Error> {
        self.con
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PTY is closed"))?
            .resize(COORD {
                X: num_cols as i16,
                Y: num_rows as i16,
            })?;
        self.size = PtySize {
            rows: num_rows,
            cols: num_cols,
            pixel_width,
            pixel_height,
        };
        Ok(())
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

#[derive(Clone)]
pub struct ConPtyMasterPty {
    inner: Arc<Mutex<Inner>>,
}

pub struct ConPtySlavePty {
    inner: Arc<Mutex<Inner>>,
}

impl ConPtyMasterPty {
    /// Observe completion even when shutdown is initiated by the final Drop.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.inner.lock().unwrap().shutdown.clone()
    }

    /// Start an idempotent shutdown shared by all master/slave references.
    /// Readers and writers become unusable; keep the returned handle to verify
    /// forwarding I/O stopped, output drained, all pipes closed, the close API
    /// returned, and both cleanup workers exited.
    pub fn shutdown(&self) -> ShutdownHandle {
        self.inner.lock().unwrap().begin_shutdown()
    }
}

impl MasterPty for ConPtyMasterPty {
    fn resize(&self, size: PtySize) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.resize(size.rows, size.cols, size.pixel_width, size.pixel_height)
    }

    fn get_size(&self) -> Result<PtySize, Error> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.size.clone())
    }

    fn try_clone_reader(&self) -> anyhow::Result<Box<dyn std::io::Read + Send>> {
        Ok(Box::new(PipeReader(
            self.inner.lock().unwrap().readable.try_clone()?,
        )))
    }

    fn take_writer(&self) -> anyhow::Result<Box<dyn std::io::Write + Send>> {
        Ok(Box::new(PipeWriter(
            self.inner
                .lock()
                .unwrap()
                .writable
                .take()
                .ok_or_else(|| anyhow::anyhow!("writer already taken"))?,
        )))
    }
}

impl SlavePty for ConPtySlavePty {
    fn spawn_command(&self, cmd: CommandBuilder) -> anyhow::Result<Box<dyn Child + Send + Sync>> {
        let mut inner = self.inner.lock().unwrap();
        let child = inner
            .con
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PTY is closed"))?
            .spawn_command(cmd)?;
        inner.children.push(child.proc.clone());
        Ok(Box::new(child))
    }
}
