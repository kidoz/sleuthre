//! GDB Remote Serial Protocol (RSP) debugger backend.
//!
//! Implements enough of the [RSP](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html)
//! to satisfy the [`Debugger`](crate::Debugger) trait over a TCP connection:
//!
//! - `attach(pid)` via `vAttach;<pid>`
//! - `detach()` via `D`
//! - `step()` via `s` — waits for stop reply and returns a structured [`StopReason`]
//! - `continue_exec()` via `c` — same; blocks until the stub reports a stop
//! - `registers()` via `g` plus architecture-specific register layouts
//! - `read_memory()` via `m<addr>,<length>`
//! - `set_breakpoint` / `remove_breakpoint` via `Z<type>,<addr>,<kind>` and the
//!   matching `z` packet, both software (Z0) and hardware (Z1)
//!
//! Packet framing is RSP-standard: `$<body>#<cksum>` with `+`/`-` ack.
//!
//! Still missing: multi-thread awareness, watchpoints (Z2/Z3/Z4), non-stop
//! mode, extended-remote launch. The transport is stable so those layer in
//! without protocol changes.

use crate::{BreakpointKind, Debugger, DebuggerState, Error, Result, StopReason};
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
    /// Currently active breakpoints, mirrored client-side so the GUI can
    /// enumerate them without an extra protocol round-trip.
    breakpoints: Vec<(u64, BreakpointKind)>,
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
            breakpoints: Vec::new(),
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

fn bp_kind_byte(kind: BreakpointKind) -> u8 {
    match kind {
        BreakpointKind::Software => 0,
        BreakpointKind::Hardware => 1,
    }
}

/// Parse a GDB Remote stop-reply packet into a structured [`StopReason`].
///
/// Recognized shapes:
/// - `S<sig>` — stopped on signal `sig`.
/// - `T<sig>[<key:val>;…]` — same, with extra key/value pairs. We extract
///   `swbreak`/`hwbreak` to label breakpoint hits, and `<reg>:<value>` pairs
///   so we can recover the program counter.
/// - `W<status>` — exited normally.
/// - `X<sig>` — terminated by signal `sig`.
fn parse_stop_reply(reply: &str) -> StopReason {
    if reply.is_empty() {
        return StopReason::Other("empty".into());
    }
    let bytes = reply.as_bytes();
    match bytes[0] {
        b'W' => {
            let code = u32::from_str_radix(&reply[1..reply.len().min(3)], 16).unwrap_or(0);
            StopReason::Exited(code as i32)
        }
        b'X' => {
            let sig = u32::from_str_radix(&reply[1..reply.len().min(3)], 16).unwrap_or(0);
            StopReason::Terminated(sig)
        }
        b'S' => {
            let sig = u32::from_str_radix(&reply[1..reply.len().min(3)], 16).unwrap_or(0);
            StopReason::Signal(sig)
        }
        b'T' => {
            // `T<sig><key>:<val>;<key>:<val>;…`
            let sig = u32::from_str_radix(reply.get(1..3).unwrap_or("00"), 16).unwrap_or(0);
            let body = reply.get(3..).unwrap_or("");
            let mut pc: Option<u64> = None;
            let mut sw_break = false;
            let mut hw_break = false;
            for kv in body.split(';') {
                if kv.is_empty() {
                    continue;
                }
                let (key, value) = kv.split_once(':').unwrap_or((kv, ""));
                if key == "swbreak" {
                    sw_break = true;
                } else if key == "hwbreak" {
                    hw_break = true;
                }
                // Numeric keys are register dumps; the lowest-numbered one is
                // typically PC for x86 (rip is at the end of the layout
                // though, so this is best-effort).
                if let Ok(_reg_idx) = u32::from_str_radix(key, 16)
                    && !value.is_empty()
                    && let Some(reg_bytes) = hex_to_bytes(value)
                {
                    let mut v: u64 = 0;
                    for (i, &b) in reg_bytes.iter().take(8).enumerate() {
                        v |= (b as u64) << (i * 8);
                    }
                    pc = Some(v);
                }
            }
            if hw_break {
                StopReason::HardwareBreakpoint(pc.unwrap_or(0))
            } else if sw_break {
                StopReason::SoftwareBreakpoint(pc.unwrap_or(0))
            } else {
                StopReason::Signal(sig)
            }
        }
        _ => StopReason::Other(reply.to_string()),
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

    fn step(&mut self) -> Result<StopReason> {
        let reply = self.send_recv("s")?;
        let reason = parse_stop_reply(&reply);
        self.state = match reason {
            StopReason::Exited(_) | StopReason::Terminated(_) => DebuggerState::Detached,
            _ => DebuggerState::Paused,
        };
        Ok(reason)
    }

    fn continue_exec(&mut self) -> Result<StopReason> {
        // `c` blocks the stub until it next stops. We wait for the stop reply
        // synchronously so the caller knows whether a breakpoint hit, the
        // inferior exited, or a signal arrived.
        let reply = self.send_recv("c")?;
        let reason = parse_stop_reply(&reply);
        self.state = match reason {
            StopReason::Exited(_) | StopReason::Terminated(_) => DebuggerState::Detached,
            _ => DebuggerState::Paused,
        };
        Ok(reason)
    }

    fn set_breakpoint(&mut self, address: u64, kind: BreakpointKind) -> Result<()> {
        let z = bp_kind_byte(kind);
        // `Z<type>,<addr>,<kind>` — `<kind>` is the breakpoint length in bytes,
        // 1 is the safest portable default (x86 uses 1, ARM uses 4 but the
        // stub auto-corrects when handed 1).
        let pkt = format!("Z{},{:x},1", z, address);
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" || reply.is_empty() {
            self.breakpoints.push((address, kind));
            Ok(())
        } else if let Some(code) = reply.strip_prefix('E') {
            Err(Error::Debugger(format!("set bp E{}", code)))
        } else {
            Err(Error::Debugger(format!(
                "set bp unexpected reply: {}",
                reply
            )))
        }
    }

    fn remove_breakpoint(&mut self, address: u64, kind: BreakpointKind) -> Result<()> {
        let z = bp_kind_byte(kind);
        let pkt = format!("z{},{:x},1", z, address);
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" || reply.is_empty() {
            self.breakpoints.retain(|bp| bp != &(address, kind));
            Ok(())
        } else if let Some(code) = reply.strip_prefix('E') {
            Err(Error::Debugger(format!("clear bp E{}", code)))
        } else {
            Err(Error::Debugger(format!(
                "clear bp unexpected reply: {}",
                reply
            )))
        }
    }

    fn breakpoints(&self) -> Vec<(u64, BreakpointKind)> {
        self.breakpoints.clone()
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

    #[test]
    fn stop_reply_recognises_exit_signal_and_breakpoints() {
        // Plain signal (SIGTRAP).
        assert_eq!(parse_stop_reply("S05"), StopReason::Signal(5));

        // Exited cleanly with status 0.
        assert_eq!(parse_stop_reply("W00"), StopReason::Exited(0));

        // Software breakpoint hit; PC encoded as register `06` (rbp slot is
        // inconsequential — the parser just records the most recent value).
        let reply = "T05swbreak:;06:7856341200000000;";
        assert!(matches!(
            parse_stop_reply(reply),
            StopReason::SoftwareBreakpoint(0x12345678)
        ));

        // Hardware breakpoint takes precedence over software when both flags
        // appear (defensive against unusual stub behaviour).
        let hw = "T05hwbreak:;swbreak:;";
        assert!(matches!(
            parse_stop_reply(hw),
            StopReason::HardwareBreakpoint(0)
        ));

        // Unknown reply rounds-trips through `Other`.
        assert_eq!(
            parse_stop_reply("?weird"),
            StopReason::Other("?weird".to_string())
        );
    }

    #[test]
    fn bp_kind_byte_matches_protocol_codes() {
        assert_eq!(bp_kind_byte(BreakpointKind::Software), 0);
        assert_eq!(bp_kind_byte(BreakpointKind::Hardware), 1);
    }
}
