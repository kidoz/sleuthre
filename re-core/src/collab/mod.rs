//! Live collaboration broadcaster (MVP).
//!
//! Opens a TCP listener and accepts any number of read-only viewer clients.
//! Every project mutation is published to the server, which forwards a JSON
//! line per event to all connected clients. The protocol is intentionally
//! tiny (line-delimited JSON, no framing, no auth) so clients can be a tail
//! of `nc`, an egui viewer, or a CRDT bridge without a binding library.
//!
//! This is a **broadcast-only** MVP — viewers receive a deterministic stream
//! of edits but cannot send their own. A full multiplayer CRDT (Yjs /
//! Automerge) is the next step; this module establishes the transport so
//! upgrading the payload format is a localized change.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// One published event. The shape is open-ended so callers can stream renames,
/// comments, type edits, or anything else without server-side schema changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabEvent {
    /// Logical event kind (e.g. `"rename"`, `"comment"`, `"snapshot"`).
    pub kind: String,
    /// Originator identifier (user/agent name).
    pub author: String,
    /// Monotonic sequence number, populated by the broadcaster.
    pub seq: u64,
    /// Free-form payload — typically the JSON form of the underlying mutation.
    pub payload: serde_json::Value,
}

/// Handle to a running broadcaster. Drop the handle to ask the worker to exit
/// at the next event boundary; the underlying TCP listener will close.
pub struct CollabBroadcaster {
    tx: Sender<CollabEvent>,
    bound: std::net::SocketAddr,
    shutdown: Arc<Mutex<bool>>,
    worker: Option<JoinHandle<()>>,
}

impl CollabBroadcaster {
    /// Bind a listener and spawn the accept/broadcast worker.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let bound = listener.local_addr()?;
        // Non-blocking accept lets the worker poll for shutdown between
        // connections without holding a thread hostage on `accept`.
        listener.set_nonblocking(true)?;

        let (tx, rx) = channel::<CollabEvent>();
        let shutdown = Arc::new(Mutex::new(false));
        let shutdown_clone = shutdown.clone();
        let worker = std::thread::spawn(move || {
            run_worker(listener, rx, shutdown_clone);
        });

        Ok(Self {
            tx,
            bound,
            shutdown,
            worker: Some(worker),
        })
    }

    /// The address the listener bound to. Useful when the caller passed
    /// `127.0.0.1:0` to let the OS pick a free port.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.bound
    }

    /// Publish an event. Returns `Err` only if the worker has already exited.
    pub fn publish(&self, event: CollabEvent) -> Result<(), String> {
        self.tx.send(event).map_err(|e| e.to_string())
    }
}

impl Drop for CollabBroadcaster {
    fn drop(&mut self) {
        if let Ok(mut s) = self.shutdown.lock() {
            *s = true;
        }
        // Channel close also wakes the worker.
        let _ = self.tx.send(CollabEvent {
            kind: "shutdown".into(),
            author: "broadcaster".into(),
            seq: 0,
            payload: serde_json::Value::Null,
        });
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_worker(listener: TcpListener, rx: Receiver<CollabEvent>, shutdown: Arc<Mutex<bool>>) {
    let mut clients: Vec<TcpStream> = Vec::new();
    let mut next_seq: u64 = 1;

    loop {
        // Drain accept queue.
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    clients.push(stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // Pump events for up to 100ms then re-check the accept queue.
        let event = match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(e) => e,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if shutdown.lock().map(|s| *s).unwrap_or(false) {
                    return;
                }
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };

        if event.kind == "shutdown" {
            return;
        }

        let mut event = event;
        event.seq = next_seq;
        next_seq += 1;
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Send to each client; drop any that error.
        clients.retain_mut(|stream| {
            stream.write_all(line.as_bytes()).is_ok() && stream.write_all(b"\n").is_ok()
        });
    }
}

/// Read a single JSON line from a connected client stream. Useful for tests
/// and lightweight viewer clients.
pub fn read_event(stream: &mut TcpStream) -> std::io::Result<CollabEvent> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim()).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcasts_to_subscriber() {
        let bcast = CollabBroadcaster::bind("127.0.0.1:0").unwrap();
        let addr = bcast.local_addr();

        // Spawn the subscriber on a thread and wait for one event.
        let recv = std::thread::spawn(move || {
            // Retry briefly while the broadcaster sets up its accept loop.
            let mut stream = None;
            for _ in 0..20 {
                if let Ok(s) = TcpStream::connect(addr) {
                    stream = Some(s);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let mut stream = stream.expect("subscriber failed to connect");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            read_event(&mut stream).unwrap()
        });

        // Give the broadcaster's accept loop time to register the subscriber.
        std::thread::sleep(std::time::Duration::from_millis(150));

        bcast
            .publish(CollabEvent {
                kind: "rename".into(),
                author: "alice".into(),
                seq: 0,
                payload: serde_json::json!({ "address": "0x1000", "name": "main" }),
            })
            .unwrap();

        let received = recv.join().unwrap();
        assert_eq!(received.kind, "rename");
        assert_eq!(received.author, "alice");
        assert_eq!(received.seq, 1);
    }
}
