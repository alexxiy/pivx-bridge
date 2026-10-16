//! Stopping on SIGTERM or SIGINT: the indexer threads finish the commit
//! they're in and exit, so a database is never cut off in the middle of
//! a write.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static STOPPING: AtomicBool = AtomicBool::new(false);
static THREADS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
static WAKERS: Mutex<Vec<mpsc::Sender<()>>> = Mutex::new(Vec::new());

/// Name prefixes of the indexer threads and their block fetchers.
const INDEXER_THREADS: [&str; 4] = ["shield-", "addr-open-", "addr-index-", "fetch-"];

/// An indexer thread that panicked would leave its index behind for good,
/// the bridge serving ever older data: exit instead, so the service
/// manager restarts the bridge (the databases survive a stop at any
/// point). Panics while answering requests only fail those requests.
pub fn exit_on_indexer_panic() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        hook(info);
        let name = std::thread::current().name().map(str::to_string).unwrap_or_default();
        if INDEXER_THREADS.iter().any(|p| name.starts_with(p)) {
            log::error!("The {name} thread stopped: exiting");
            std::process::exit(1);
        }
    }));
}

/// Whether the bridge is stopping.
pub fn stopping() -> bool {
    STOPPING.load(Ordering::Relaxed)
}

/// Sleeps for `d`, or less once stopping. False when stopping.
pub fn sleep(d: Duration) -> bool {
    let end = Instant::now() + d;
    while !stopping() {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(200)));
    }
    false
}

/// An indexer thread, waited for when stopping.
pub fn register(thread: JoinHandle<()>) {
    THREADS.lock().unwrap().push(thread);
}

/// A channel an indexer thread waits on, sent to when stopping.
pub fn register_waker(waker: mpsc::Sender<()>) {
    WAKERS.lock().unwrap().push(waker);
}

/// Resolves on SIGTERM or SIGINT.
pub async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

/// Tells the indexer threads to stop and waits up to `timeout` for them.
/// True when all of them stopped.
pub fn stop(timeout: Duration) -> bool {
    STOPPING.store(true, Ordering::Relaxed);
    for waker in WAKERS.lock().unwrap().iter() {
        let _ = waker.send(());
    }
    let deadline = Instant::now() + timeout;
    let threads = std::mem::take(&mut *THREADS.lock().unwrap());
    let mut all = true;
    for thread in threads {
        while !thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if thread.is_finished() {
            let _ = thread.join();
        } else {
            all = false;
        }
    }
    all
}
