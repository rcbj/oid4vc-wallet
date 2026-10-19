//! One `--ui` window per session.
//!
//! The running window binds `ui.sock`. A later `--ui` connects, writes its
//! URIs, and exits. Binding the socket is the lock: a dead socket file is
//! removed and replaced, and a socket a live peer accepts is left alone.
//! `ui.lock` is an advisory flock held only for that decision, then rewritten
//! with the primary process id.
//!
//! The directory is `$XDG_RUNTIME_DIR/oid4vc-wallet`, or
//! `$XDG_CACHE_HOME/oid4vc-wallet/runtime` when the runtime directory is
//! unset. An empty variable is unset, as in the base-directory spec.
//! `$XDG_CACHE_HOME` defaults to `~/.cache`.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const SOCKET_NAME: &str = "ui.sock";
const LOCK_NAME: &str = "ui.lock";
const LOCK_EX: i32 = 2;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LINE: usize = 8 * 1024 * 1024;
const MAX_URIS: usize = 64;
const POLLIN: i16 = 0x001;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

type Wake = Arc<dyn Fn() + Send + Sync>;

/// Which process paints the `--ui` window.
pub enum Claim {
    /// This process bound `ui.sock` and is accepting handoffs.
    Primary(Incoming),
    /// The URIs were written to the window that is already open.
    HandedOff,
}

/// The bound socket and the queue of URI batches from later processes.
pub struct Incoming {
    /// Kept open for the life of the window. The accept thread holds another
    /// clone; both must stay alive or the name can be claimed again.
    listener: Option<Arc<UnixListener>>,
    rx: Receiver<Vec<String>>,
    wake: Arc<Mutex<Option<Wake>>>,
    /// Write end of a socket pair. Closing it wakes the accept thread.
    stop: Option<UnixStream>,
    thread: Option<JoinHandle<()>>,
}

impl Incoming {
    /// Ask the window to repaint after the next handoff. Replaces any
    /// previous hook. The hook runs on the accept thread.
    pub fn set_wake(&self, wake: impl Fn() + Send + Sync + 'static) {
        *self.wake.lock().unwrap_or_else(|err| err.into_inner()) = Some(Arc::new(wake));
    }

    pub fn try_recv(&self) -> Result<Vec<String>, TryRecvError> {
        self.rx.try_recv()
    }

    #[cfg(test)]
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Vec<String>, mpsc::RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // Closing the write end is level-triggered: `poll` returns even if
        // the socket path was already removed.
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // The accept thread has dropped its clone. This closes the socket.
        drop(self.listener.take());
    }
}

/// `$XDG_RUNTIME_DIR/oid4vc-wallet`, else `$XDG_CACHE_HOME/oid4vc-wallet/runtime`.
pub fn runtime_dir() -> io::Result<PathBuf> {
    let runtime = env_nonempty("XDG_RUNTIME_DIR").map(PathBuf::from);
    let cache = env_nonempty("XDG_CACHE_HOME").map(PathBuf::from);
    let home = if runtime.is_none() && cache.is_none() {
        Some(
            oid4vc_wallet::xdg::home()
                .map_err(|err| io::Error::new(io::ErrorKind::NotFound, err))?,
        )
    } else {
        None
    };
    runtime_dir_from(runtime.as_deref(), cache.as_deref(), home.as_deref())
}

fn runtime_dir_from(
    runtime: Option<&Path>,
    cache: Option<&Path>,
    home: Option<&Path>,
) -> io::Result<PathBuf> {
    if let Some(runtime) = nonempty(runtime) {
        return Ok(runtime.join("oid4vc-wallet"));
    }
    let cache = if let Some(cache) = nonempty(cache) {
        cache.to_path_buf()
    } else {
        let home = nonempty(home)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is unset"))?;
        home.join(".cache")
    };
    Ok(cache.join("oid4vc-wallet").join("runtime"))
}

fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn nonempty(path: Option<&Path>) -> Option<&Path> {
    path.filter(|path| !path.as_os_str().is_empty())
}

/// Bind `dir/ui.sock`, or write `uris` to the listener that already has it.
///
/// An empty list is a focus request: the client sends a lone `.\n`.
pub fn claim_ui(dir: &Path, uris: &[String]) -> io::Result<Claim> {
    ensure_private_dir(dir)?;
    let lock_path = dir.join(LOCK_NAME);
    let mut lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
    lock_exclusive(&lock)?;
    let socket_path = dir.join(SOCKET_NAME);
    if let Some(claim) = handoff_or_reclaim(&socket_path, uris)? {
        return Ok(claim);
    }
    let listener = UnixListener::bind(&socket_path)?;
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));
    write_pid(&mut lock)?;
    Ok(Claim::Primary(start_incoming(listener)?))
}

fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder.create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn lock_exclusive(file: &std::fs::File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    loop {
        // SAFETY: `fd` belongs to `file`. LOCK_EX blocks until this process
        // holds the lock, and the lock drops when `file` is closed.
        let rc = unsafe { flock(fd, LOCK_EX) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

fn write_pid(file: &mut std::fs::File) -> io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    let pid = std::process::id();
    writeln!(file, "{pid}")?;
    file.sync_all()?;
    Ok(())
}

/// `Some(HandedOff)` when a live peer took the URIs. `None` when the caller
/// should bind. A peer that accepts the connection is not unlinked.
fn handoff_or_reclaim(path: &Path, uris: &[String]) -> io::Result<Option<Claim>> {
    if !socket_present(path)? {
        return Ok(None);
    }
    match UnixStream::connect(path) {
        Ok(mut stream) => match exchange(&mut stream, uris) {
            Ok(()) => Ok(Some(Claim::HandedOff)),
            Err(err) if peer_went_away(&err) => match UnixStream::connect(path) {
                Ok(mut stream) => {
                    exchange(&mut stream, uris)?;
                    Ok(Some(Claim::HandedOff))
                }
                Err(err) if stale_socket(&err) => {
                    remove_socket(path)?;
                    Ok(None)
                }
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        },
        Err(err) if stale_socket(&err) => {
            remove_socket(path)?;
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn socket_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn remove_socket(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn stale_socket(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
    )
}

fn peer_went_away(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

fn exchange(stream: &mut UnixStream, uris: &[String]) -> io::Result<()> {
    prepare_stream(stream)?;
    for uri in uris {
        stream.write_all(uri.as_bytes())?;
        stream.write_all(b"\n")?;
    }
    stream.write_all(b".\n")?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "handoff reply closed",
        ));
    }
    if line.trim_end_matches(['\r', '\n']) != "ok" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handoff reply was not ok",
        ));
    }
    Ok(())
}

fn prepare_stream(stream: &mut UnixStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

fn start_incoming(listener: UnixListener) -> io::Result<Incoming> {
    listener.set_nonblocking(true)?;
    let (stop_read, stop_write) = UnixStream::pair()?;
    let listener = Arc::new(listener);
    let thread_listener = Arc::clone(&listener);
    let wake = Arc::new(Mutex::new(None));
    let thread_wake = Arc::clone(&wake);
    let (tx, rx) = mpsc::channel();
    let thread = thread::Builder::new()
        .name("oid4vc-ui-socket".to_string())
        .spawn(move || accept_loop(thread_listener, stop_read, thread_wake, tx))?;
    Ok(Incoming {
        listener: Some(listener),
        rx,
        wake,
        stop: Some(stop_write),
        thread: Some(thread),
    })
}

fn accept_loop(
    listener: Arc<UnixListener>,
    stop: UnixStream,
    wake: Arc<Mutex<Option<Wake>>>,
    tx: Sender<Vec<String>>,
) {
    loop {
        match accept_ready(&listener, &stop) {
            Ok(false) | Err(_) => break,
            Ok(true) => match listener.accept() {
                Ok((mut stream, _)) => {
                    if prepare_stream(&mut stream).is_err() {
                        continue;
                    }
                    let Ok(uris) = read_request(&mut stream) else {
                        continue;
                    };
                    if tx.send(uris).is_err() {
                        break;
                    }
                    let _ = write_ok(&mut stream);
                    fire_wake(&wake);
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            },
        }
    }
}

fn accept_ready(listener: &UnixListener, stop: &UnixStream) -> io::Result<bool> {
    let mut fds = [
        PollFd {
            fd: listener.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        },
        PollFd {
            fd: stop.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a live two-element pollfd array. A negative
        // timeout waits until one fd is ready or the call is interrupted.
        let rc = unsafe { poll(fds.as_mut_ptr(), fds.len(), -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let stop_bits = fds[1].revents;
        if stop_bits & (POLLIN | POLLHUP | POLLERR | POLLNVAL) != 0 {
            return Ok(false);
        }
        let listen_bits = fds[0].revents;
        if listen_bits & POLLIN != 0 {
            return Ok(true);
        }
        if listen_bits & (POLLERR | POLLNVAL | POLLHUP) != 0 {
            return Err(io::Error::other("ui socket closed"));
        }
    }
}

fn read_request(stream: &mut UnixStream) -> io::Result<Vec<String>> {
    let mut reader = BufReader::new(stream);
    let mut uris = Vec::new();
    loop {
        let line = read_line_capped(&mut reader, MAX_LINE)?;
        if line.is_empty() || !line.ends_with(b"\n") {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "handoff closed",
            ));
        }
        let mut line = line;
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line == b"." {
            return Ok(uris);
        }
        if uris.len() == MAX_URIS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many handoff uris",
            ));
        }
        let uri = String::from_utf8(line)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        uris.push(uri);
    }
}

fn read_line_capped(reader: &mut impl BufRead, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(buf);
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map(|pos| pos + 1).unwrap_or(available.len());
        if buf.len().saturating_add(take) > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handoff line is too long",
            ));
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(buf);
        }
    }
}

fn write_ok(stream: &mut UnixStream) -> io::Result<()> {
    stream.write_all(b"ok\n")?;
    stream.flush()?;
    Ok(())
}

fn fire_wake(wake: &Mutex<Option<Wake>>) {
    let wake = wake.lock().unwrap_or_else(|err| err.into_inner()).clone();
    if let Some(wake) = wake {
        wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "oid4vc-wallet-single-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_second_claim_hands_uris_to_the_first() {
        let dir = TempDir::new();
        let Claim::Primary(incoming) = claim_ui(dir.path(), &["local".to_string()]).unwrap() else {
            panic!("first claim should bind");
        };
        assert!(incoming.try_recv().is_err());
        let uris = vec![
            "openid4vp://?client_id=https%3A%2F%2Fverifier.example&request_uri=https%3A%2F%2Fverifier.example%2Fr".to_string(),
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer".to_string(),
        ];
        match claim_ui(dir.path(), &uris).unwrap() {
            Claim::HandedOff => {}
            Claim::Primary(_) => panic!("second claim should hand off"),
        }
        assert_eq!(incoming.recv_timeout(Duration::from_secs(2)).unwrap(), uris);
        match claim_ui(dir.path(), &[]).unwrap() {
            Claim::HandedOff => {}
            Claim::Primary(_) => panic!("an empty claim should hand off"),
        }
        assert!(incoming
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_empty());
        assert!(socket_present(&dir.path().join("ui.sock")).unwrap());
        let pid = fs::read_to_string(dir.path().join("ui.lock")).unwrap();
        assert_eq!(pid.trim(), std::process::id().to_string());
        let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let mode = fs::metadata(dir.path().join("ui.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_dead_socket_is_replaced_and_a_removed_socket_can_bind() {
        let dir = TempDir::new();
        let Claim::Primary(incoming) = claim_ui(dir.path(), &[]).unwrap() else {
            panic!("primary");
        };
        drop(incoming);
        assert!(dir.path().join("ui.sock").exists());
        let Claim::Primary(incoming) = claim_ui(dir.path(), &[]).unwrap() else {
            panic!("a dead socket should be replaced");
        };
        drop(incoming);
        fs::remove_file(dir.path().join("ui.sock")).unwrap();
        match claim_ui(dir.path(), &["openid4vp://again".to_string()]).unwrap() {
            Claim::Primary(incoming) => {
                match claim_ui(dir.path(), &["openid4vp://handed".to_string()]).unwrap() {
                    Claim::HandedOff => {}
                    Claim::Primary(_) => panic!("live socket was replaced"),
                }
                assert_eq!(
                    incoming.recv_timeout(Duration::from_secs(2)).unwrap(),
                    vec!["openid4vp://handed".to_string()]
                );
            }
            Claim::HandedOff => panic!("removed socket should bind"),
        }
    }

    #[test]
    fn a_regular_file_at_the_socket_path_is_replaced() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(dir.path().join("ui.sock"), b"not a socket").unwrap();
        let claim = claim_ui(dir.path(), &[]).unwrap();
        assert!(matches!(&claim, Claim::Primary(_)));
        let mode = fs::metadata(dir.path().join("ui.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        drop(claim);
    }

    #[test]
    fn runtime_dir_prefers_the_runtime_directory_then_cache_then_home() {
        let runtime = Path::new("/run/user/1000");
        let cache = Path::new("/cache");
        let home = Path::new("/home/a");
        assert_eq!(
            runtime_dir_from(Some(runtime), Some(cache), Some(home)).unwrap(),
            PathBuf::from("/run/user/1000/oid4vc-wallet")
        );
        assert_eq!(
            runtime_dir_from(Some(Path::new("")), Some(cache), Some(home)).unwrap(),
            PathBuf::from("/cache/oid4vc-wallet/runtime")
        );
        assert_eq!(
            runtime_dir_from(None, Some(Path::new("")), Some(home)).unwrap(),
            PathBuf::from("/home/a/.cache/oid4vc-wallet/runtime")
        );
        assert!(runtime_dir_from(None, None, None).is_err());
        assert!(runtime_dir_from(None, None, Some(Path::new(""))).is_err());
        let dir = runtime_dir().unwrap();
        let text = dir.display().to_string();
        assert!(
            text.ends_with("/oid4vc-wallet") || text.ends_with("/oid4vc-wallet/runtime"),
            "{text}"
        );
    }
}
