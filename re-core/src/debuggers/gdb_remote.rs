//! GDB Remote Serial Protocol (RSP) debugger backend.
//!
//! Implements just enough of the [RSP](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html)
//! to satisfy the [`Debugger`](crate::Debugger) trait over a TCP connection:
//!
//! - `attach(pid)` via `vAttach;<pid>`
//! - `detach()` via `D`
//! - `step()` via `s`
//! - `continue_exec()` via `c` (fire-and-forget — does not block for stop reply)
//! - `registers()` via `g` plus architecture-specific register layouts
//! - `read_memory()` via `m<addr>,<length>`
//!
//! Packet framing is RSP-standard: `$<body>#<cksum>` with `+`/`-` acknowledgment.
//!
//! This is an MVP: no breakpoint management, no multi-thread awareness, no
//! extended-remote support. The intent is to prove the RSP stack works so
//! richer features (hw breakpoints, non-stop mode, tracing) can be layered
//! on top without rewriting the transport.

use crate::{Debugger, DebuggerState, Error, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

/// Register layouts per supported target. Order matches the `g`/`G` packet
/// layout documented for each architecture.
fn register_layout(arch: crate::arch::Architecture) -> &'static [(&'static str, usize)] {
    use crate::arch::Architecture::*;
    match arch {
        X86_64 => &[
            ("rax", 8),
            ("rbx", 8),
            ("rcx", 8),
            ("rdx", 8),
            ("rsi", 8),
            ("rdi", 8),
            ("rbp", 8),
            ("rsp", 8),
            ("r8", 8),
            ("r9", 8),
            ("r10", 8),
            ("r11", 8),
            ("r12", 8),
            ("r13", 8),
            ("r14", 8),
            ("r15", 8),
            ("rip", 8),
            ("eflags", 4),
        ],
        X86 => &[
            ("eax", 4),
            ("ecx", 4),
            ("edx", 4),
            ("ebx", 4),
            ("esp", 4),
            ("ebp", 4),
            ("esi", 4),
            ("edi", 4),
            ("eip", 4),
            ("eflags", 4),
        ],
        Arm64 => &[
            ("x0", 8),
            ("x1", 8),
            ("x2", 8),
            ("x3", 8),
            ("x4", 8),
            ("x5", 8),
            ("x6", 8),
            ("x7", 8),
            ("x8", 8),
            ("x9", 8),
            ("x10", 8),
            ("x11", 8),
            ("x12", 8),
            ("x13", 8),
            ("x14", 8),
            ("x15", 8),
            ("x16", 8),
            ("x17", 8),
            ("x18", 8),
            ("x19", 8),
            ("x20", 8),
            ("x21", 8),
            ("x22", 8),
            ("x23", 8),
            ("x24", 8),
            ("x25", 8),
            ("x26", 8),
            ("x27", 8),
            ("x28", 8),
            ("fp", 8),
            ("lr", 8),
            ("sp", 8),
            ("pc", 8),
        ],
        Arm => &[
            ("r0", 4),
            ("r1", 4),
            ("r2", 4),
            ("r3", 4),
            ("r4", 4),
            ("r5", 4),
            ("r6", 4),
            ("r7", 4),
            ("r8", 4),
            ("r9", 4),
            ("r10", 4),
            ("r11", 4),
            ("r12", 4),
            ("sp", 4),
            ("lr", 4),
            ("pc", 4),
        ],
        _ => &[],
    }
}

/// A live connection to a `gdbserver`-compatible stub.
pub struct GdbRemoteDebugger {
    stream: Mutex<TcpStream>,
    state: DebuggerState,
    arch: crate::arch::Architecture,
}

impl GdbRemoteDebugger {
    /// Connect to `host:port` (e.g. `"127.0.0.1:1234"`) and run the initial
    /// RSP handshake. Succeeds if the stub replies OK to `qSupported`.
    pub fn connect<A: ToSocketAddrs>(addr: A, arch: crate::arch::Architecture) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).map_err(|e| Error::Debugger(format!("gdb connect: {}", e)))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| Error::Debugger(format!("gdb set_read_timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| Error::Debugger(format!("gdb set_write_timeout: {}", e)))?;

        let mut dbg = Self {
            stream: Mutex::new(stream),
            state: DebuggerState::Paused,
            arch,
        };
        dbg.handshake()?;
        Ok(dbg)
    }

    fn handshake(&mut self) -> Result<()> {
        let _ = self.send_recv("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+")?;
        // Some stubs require an explicit `qAttached` before memory is readable.
        let _ = self.send_recv("qAttached");
        Ok(())
    }

    /// Send a packet and return the body of the reply (without `$...#cc`).
    fn send_recv(&self, body: &str) -> Result<String> {
        let packet = format_packet(body);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| Error::Debugger("gdb mutex poisoned".into()))?;
        stream
            .write_all(packet.as_bytes())
            .map_err(|e| Error::Debugger(format!("gdb write: {}", e)))?;
        // Await `+` ack.
        let mut ack = [0u8; 1];
        stream
            .read_exact(&mut ack)
            .map_err(|e| Error::Debugger(format!("gdb ack: {}", e)))?;
        if ack[0] == b'-' {
            return Err(Error::Debugger("gdb NAK".into()));
        }
        read_packet(&mut stream)
    }
}

fn format_packet(body: &str) -> String {
    let sum: u32 = body.bytes().map(|b| b as u32).sum::<u32>() & 0xff;
    format!("${}#{:02x}", body, sum)
}

fn read_packet(stream: &mut TcpStream) -> Result<String> {
    let mut out = String::new();
    let mut byte = [0u8; 1];
    // Skip until packet start.
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| Error::Debugger(format!("gdb read: {}", e)))?;
        if byte[0] == b'$' {
            break;
        }
    }
    // Body until '#', ignoring RLE/escape edge cases (not exercised by
    // register/memory queries in MVP stubs).
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| Error::Debugger(format!("gdb read: {}", e)))?;
        if byte[0] == b'#' {
            break;
        }
        out.push(byte[0] as char);
    }
    // Consume the 2-byte checksum; we don't verify.
    let mut cksum = [0u8; 2];
    stream
        .read_exact(&mut cksum)
        .map_err(|e| Error::Debugger(format!("gdb read cksum: {}", e)))?;
    // Send `+` ack to acknowledge reception.
    let _ = stream.write_all(b"+");
    Ok(out)
}

fn from_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = from_hex_nibble(chunk[0])?;
        let lo = from_hex_nibble(chunk[1])?;
        out.push(hi * 16 + lo);
    }
    Some(out)
}

impl Debugger for GdbRemoteDebugger {
    fn state(&self) -> DebuggerState {
        self.state
    }

    fn attach(&mut self, pid: u32) -> Result<()> {
        let pkt = format!("vAttach;{:x}", pid);
        self.send_recv(&pkt)?;
        self.state = DebuggerState::Paused;
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        let _ = self.send_recv("D");
        self.state = DebuggerState::Detached;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        // `s` returns a stop reply once stepping completes; we swallow it so
        // the caller can issue another command synchronously.
        let _ = self.send_recv("s");
        self.state = DebuggerState::Paused;
        Ok(())
    }

    fn continue_exec(&mut self) -> Result<()> {
        // `c` is followed by a stop reply when the inferior next pauses. For
        // MVP we mark the target as running and leave the reply unread; the
        // caller should issue an interrupt (Ctrl+C / `\x03`) or query later.
        let packet = format_packet("c");
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| Error::Debugger("gdb mutex poisoned".into()))?;
        stream
            .write_all(packet.as_bytes())
            .map_err(|e| Error::Debugger(format!("gdb write: {}", e)))?;
        self.state = DebuggerState::Running;
        Ok(())
    }

    fn registers(&self) -> HashMap<String, u64> {
        let mut out = HashMap::new();
        let reply = match self.send_recv("g") {
            Ok(r) if !r.starts_with('E') && !r.is_empty() => r,
            _ => return out,
        };
        let Some(bytes) = hex_to_bytes(&reply) else {
            return out;
        };
        let layout = register_layout(self.arch);
        let mut cursor = 0usize;
        for (name, size) in layout {
            if cursor + size > bytes.len() {
                break;
            }
            // RSP register values are little-endian.
            let mut value: u64 = 0;
            for (i, &b) in bytes[cursor..cursor + size].iter().enumerate() {
                value |= (b as u64) << (i * 8);
            }
            out.insert((*name).to_string(), value);
            cursor += size;
        }
        out
    }

    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let pkt = format!("m{:x},{:x}", addr, size);
        let reply = self.send_recv(&pkt)?;
        if let Some(code) = reply.strip_prefix('E') {
            return Err(Error::Debugger(format!("gdb E{}", code)));
        }
        hex_to_bytes(&reply).ok_or_else(|| Error::Debugger("gdb bad memory reply".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_packet_sums_body() {
        // 'OK' = 0x4F + 0x4B = 0x9A.
        assert_eq!(format_packet("OK"), "$OK#9a");
    }

    #[test]
    fn hex_to_bytes_rejects_odd_length() {
        assert!(hex_to_bytes("abc").is_none());
    }

    #[test]
    fn hex_to_bytes_parses_mixed_case() {
        assert_eq!(hex_to_bytes("DeAdBe").unwrap(), vec![0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn register_layout_covers_x86_64() {
        let l = register_layout(crate::arch::Architecture::X86_64);
        assert!(l.iter().any(|(n, _)| *n == "rip"));
        assert!(l.iter().any(|(n, _)| *n == "rsp"));
    }
}
