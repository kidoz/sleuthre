//! Live collaboration broadcaster.
//!
//! Opens a TCP listener and accepts any number of viewer clients. The wire
//! format is intentionally tiny (line-delimited JSON, no framing, no auth) so
//! clients can be a tail of `nc`, an egui viewer, or a CRDT bridge without a
//! binding library.
//!
//! Direction:
//! - **Outbound:** every project mutation the host publishes via
//!   [`CollabBroadcaster::publish`] is fanned out to all connected clients.
//! - **Inbound:** any JSON line a client writes back is parsed as a
//!   [`CollabEvent`] and queued for the host to drain via
//!   [`CollabBroadcaster::drain_inbound`]. The host is responsible for
//!   applying inbound mutations (typically by translating to `UndoCommand`
//!   and calling `Project::execute`).
//!
//! Conflict resolution is currently last-writer-wins. A full CRDT layer
//! (Yjs / Automerge) is a localized upgrade — the transport and event
//! envelope are stable.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
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
    inbound_rx: Mutex<Receiver<CollabEvent>>,
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
        let (inbound_tx, inbound_rx) = channel::<CollabEvent>();
        let shutdown = Arc::new(Mutex::new(false));
        let shutdown_clone = shutdown.clone();
        let worker = std::thread::spawn(move || {
            run_worker(listener, rx, inbound_tx, shutdown_clone);
        });

        Ok(Self {
            tx,
            inbound_rx: Mutex::new(inbound_rx),
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

    /// Drain any events sent *back* by viewers (bidirectional collab). Each
    /// event is one line of JSON received on a client socket. Non-blocking;
    /// callers should invoke this once per UI frame.
    pub fn drain_inbound(&self) -> Vec<CollabEvent> {
        let mut out = Vec::new();
        let Ok(rx) = self.inbound_rx.lock() else {
            return out;
        };
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
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

/// Per-client state held by the worker — the socket plus a partial-line buffer
/// for accumulating incoming data across read calls.
struct Client {
    stream: TcpStream,
    rx_buf: Vec<u8>,
}

fn run_worker(
    listener: TcpListener,
    rx: Receiver<CollabEvent>,
    inbound_tx: Sender<CollabEvent>,
    shutdown: Arc<Mutex<bool>>,
) {
    let mut clients: Vec<Client> = Vec::new();
    let mut next_seq: u64 = 1;
    let mut read_buf = [0u8; 4096];

    loop {
        // Drain accept queue.
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let _ = stream.set_nonblocking(true);
                    clients.push(Client {
                        stream,
                        rx_buf: Vec::new(),
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // Drain inbound bytes from each client; complete lines become events.
        clients.retain_mut(|client| {
            loop {
                match client.stream.read(&mut read_buf) {
                    Ok(0) => return false, // connection closed
                    Ok(n) => {
                        client.rx_buf.extend_from_slice(&read_buf[..n]);
                        // Extract complete `\n`-terminated lines.
                        while let Some(pos) = client.rx_buf.iter().position(|&b| b == b'\n') {
                            let line: Vec<u8> = client.rx_buf.drain(..=pos).collect();
                            let trimmed =
                                String::from_utf8_lossy(&line[..line.len().saturating_sub(1)])
                                    .trim()
                                    .to_string();
                            if trimmed.is_empty() {
                                continue;
                            }
                            if let Ok(event) = serde_json::from_str::<CollabEvent>(&trimmed) {
                                let _ = inbound_tx.send(event);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => return false,
                }
            }
            true
        });

        // Pump outbound events for up to 50ms then re-check accept + inbound.
        let event = match rx.recv_timeout(std::time::Duration::from_millis(50)) {
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
        clients.retain_mut(|client| {
            client.stream.write_all(line.as_bytes()).is_ok()
                && client.stream.write_all(b"\n").is_ok()
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
    fn inbound_event_from_client_is_drained() {
        let bcast = CollabBroadcaster::bind("127.0.0.1:0").unwrap();
        let addr = bcast.local_addr();

        // Connect a "viewer" and send an event back to the host.
        let mut stream = None;
        for _ in 0..20 {
            if let Ok(s) = TcpStream::connect(addr) {
                stream = Some(s);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut stream = stream.expect("connect failed");
        let event = CollabEvent {
            kind: "rename".into(),
            author: "viewer".into(),
            seq: 0,
            payload: serde_json::json!({"address": "0x1000", "name": "main"}),
        };
        let line = serde_json::to_string(&event).unwrap() + "\n";
        stream.write_all(line.as_bytes()).unwrap();

        // Wait for the worker to pick it up.
        let mut received = Vec::new();
        for _ in 0..50 {
            received = bcast.drain_inbound();
            if !received.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(received.len(), 1, "expected one inbound event");
        assert_eq!(received[0].kind, "rename");
        assert_eq!(received[0].author, "viewer");
    }

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
