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
//! Packet framing is RSP-standard: `$<body>#<cksum>` with `+`/`-` ack, and
//! reply bodies are decoded for run-length encoding and `}`-escapes (see
//! [`decode_rsp_body`]) so register dumps and `qXfer` payloads survive intact.
//!
//! Watchpoints (Z2/Z3/Z4), thread-scoped breakpoints, register/memory writes
//! (`P`/`M`), and shared-library enumeration (`qXfer:libraries-svr4`) are all
//! supported. Still missing: non-stop mode and extended-remote `vRun` launch
//! (local launch is handled out-of-band by spawning a `gdbserver` child).

use crate::{BreakpointKind, Debugger, DebuggerState, Error, Result, StopReason, WatchpointHit};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

/// Upper bound on a single RSP packet body (and on leading garbage before a
/// packet start), so a hostile or buggy stub that never frames a packet can't
/// hang the reader or exhaust memory. Real register/`qXfer` payloads are far
/// smaller than this.
const MAX_PACKET_BODY: usize = 16 * 1024 * 1024;
/// Upper bound on `qfThreadInfo`/`qsThreadInfo` rounds, so a stub that never
/// replies `l` can't loop forever.
const MAX_THREAD_ROUNDS: usize = 4096;
/// Socket timeout for request/response exchanges. Resume waits (`c`/`s`)
/// deliberately bypass it — see [`GdbRemoteDebugger::resume_and_wait`].
const READ_TIMEOUT: Duration = Duration::from_secs(5);

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

/// A cheaply-cloneable handle that can asynchronously interrupt a running
/// inferior even while the owning [`GdbRemoteDebugger`] has been moved into a
/// worker thread for a blocking `continue`/`step`. It holds a `try_clone` of
/// the RSP socket; writing the unframed `0x03` (Ctrl+C) byte reaches the same
/// connection the worker is blocked reading on, so the worker returns shortly.
pub struct InterruptHandle {
    stream: TcpStream,
}

impl InterruptHandle {
    pub fn interrupt(&mut self) -> Result<()> {
        self.stream
            .write_all(&[0x03])
            .map_err(|e| Error::Debugger(format!("gdb interrupt write: {}", e)))
    }
}

/// A live connection to a `gdbserver`-compatible stub.
pub struct GdbRemoteDebugger {
    stream: Mutex<TcpStream>,
    state: DebuggerState,
    arch: crate::arch::Architecture,
    /// Currently active breakpoints, mirrored client-side so the GUI can
    /// enumerate them without an extra protocol round-trip. The optional
    /// `Option<u64>` is the thread id when scoped, or `None` for process-wide.
    breakpoints: Vec<(u64, BreakpointKind, Option<u64>)>,
    /// Thread ids reported by the stub the last time `threads()` was called.
    threads_cache: std::sync::Mutex<Vec<u64>>,
    /// Currently active thread (used to scope `g`/`m` operations on multi-threaded stubs).
    active_thread: std::sync::Mutex<Option<u64>>,
}

impl GdbRemoteDebugger {
    /// Connect to `host:port` (e.g. `"127.0.0.1:1234"`) and run the initial
    /// RSP handshake. Succeeds if the stub replies OK to `qSupported`.
    pub fn connect<A: ToSocketAddrs>(addr: A, arch: crate::arch::Architecture) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).map_err(|e| Error::Debugger(format!("gdb connect: {}", e)))?;
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|e| Error::Debugger(format!("gdb set_read_timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| Error::Debugger(format!("gdb set_write_timeout: {}", e)))?;

        let mut dbg = Self {
            stream: Mutex::new(stream),
            state: DebuggerState::Paused,
            arch,
            breakpoints: Vec::new(),
            threads_cache: std::sync::Mutex::new(Vec::new()),
            active_thread: std::sync::Mutex::new(None),
        };
        dbg.handshake()?;
        Ok(dbg)
    }

    /// Produce an [`InterruptHandle`] that shares this debugger's socket, so
    /// the UI can stop a running inferior while the debugger itself is borrowed
    /// by a worker thread mid-`continue`.
    pub fn interrupt_handle(&self) -> Result<InterruptHandle> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| Error::Debugger("gdb mutex poisoned".into()))?;
        let clone = stream
            .try_clone()
            .map_err(|e| Error::Debugger(format!("gdb try_clone: {}", e)))?;
        Ok(InterruptHandle { stream: clone })
    }

    /// Direct write of a single byte to the underlying socket — used by
    /// [`Debugger::interrupt`] to send the unframed `\x03` (Ctrl+C) byte.
    fn write_raw(&self, byte: u8) -> Result<()> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| Error::Debugger("gdb mutex poisoned".into()))?;
        stream
            .write_all(&[byte])
            .map_err(|e| Error::Debugger(format!("gdb interrupt write: {}", e)))?;
        Ok(())
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

    /// Send a resume packet (`c`/`s`) and block until the stub's stop reply.
    ///
    /// Unlike [`send_recv`](Self::send_recv), the wait for the stop reply runs
    /// with the socket read timeout disabled: the inferior may run arbitrarily
    /// long before it next stops, and timing out mid-wait would both report a
    /// spurious failure and leave the eventual stop reply unread in the
    /// socket, desynchronizing every later exchange. The escape hatch is the
    /// interrupt path — an unframed `\x03` via [`InterruptHandle`] forces a
    /// stop reply onto this same connection. The normal timeout is restored
    /// before returning.
    fn resume_and_wait(&self, body: &str) -> Result<String> {
        let packet = format_packet(body);
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| Error::Debugger("gdb mutex poisoned".into()))?;
        stream
            .write_all(packet.as_bytes())
            .map_err(|e| Error::Debugger(format!("gdb write: {}", e)))?;
        let mut ack = [0u8; 1];
        stream
            .read_exact(&mut ack)
            .map_err(|e| Error::Debugger(format!("gdb ack: {}", e)))?;
        if ack[0] == b'-' {
            return Err(Error::Debugger("gdb NAK".into()));
        }
        stream
            .set_read_timeout(None)
            .map_err(|e| Error::Debugger(format!("gdb set_read_timeout: {}", e)))?;
        let result = read_packet(&mut stream);
        // Best-effort restore; a failure surfaces on the next plain exchange.
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        result
    }
}

fn format_packet(body: &str) -> String {
    let sum: u32 = body.bytes().map(|b| b as u32).sum::<u32>() & 0xff;
    format!("${}#{:02x}", body, sum)
}

fn read_packet(stream: &mut TcpStream) -> Result<String> {
    let mut byte = [0u8; 1];
    // Skip until packet start, bounded so a stub flooding non-`$` data can't hang us.
    let mut skipped = 0usize;
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| Error::Debugger(format!("gdb read: {}", e)))?;
        if byte[0] == b'$' {
            break;
        }
        skipped += 1;
        if skipped > MAX_PACKET_BODY {
            return Err(Error::Debugger("gdb: no packet start within limit".into()));
        }
    }
    // Collect the raw body until '#'. RSP escapes any literal '#'/'$'/'}'/'*'
    // in data as `}` followed by (char ^ 0x20), so a bare '#' always
    // terminates the packet — we can scan for it before decoding.
    let mut raw: Vec<u8> = Vec::new();
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| Error::Debugger(format!("gdb read: {}", e)))?;
        if byte[0] == b'#' {
            break;
        }
        if raw.len() >= MAX_PACKET_BODY {
            return Err(Error::Debugger("gdb: packet body exceeds limit".into()));
        }
        raw.push(byte[0]);
    }
    // Consume the 2-byte checksum; we don't verify.
    let mut cksum = [0u8; 2];
    stream
        .read_exact(&mut cksum)
        .map_err(|e| Error::Debugger(format!("gdb read cksum: {}", e)))?;
    // Send `+` ack to acknowledge reception.
    let _ = stream.write_all(b"+");
    Ok(decode_rsp_body(&raw))
}

/// Decode an RSP packet body, resolving the two compression mechanisms real
/// stubs (gdbserver, QEMU) use even on register/memory replies:
///
/// - **Escape:** a `}` byte means "the next byte XOR `0x20`" — used to embed a
///   literal `#`/`$`/`}`/`*` in the payload.
/// - **Run-length encoding:** `<char>*<n>` repeats the byte *preceding* the `*`
///   an additional `n - 29` times (so `0* ` — where the third byte is the
///   space `0x20 = 32` — expands to four `0`s).
///
/// Without this, runs of `00` in a `g` register dump or the `qXfer` library
/// XML arrive truncated. Payloads are ASCII (hex or XML), so we return a
/// `String` built from the decoded bytes.
fn decode_rsp_body(raw: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'}' => {
                if let Some(&next) = raw.get(i + 1) {
                    out.push(next ^ 0x20);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'*' => {
                let prev = out.last().copied();
                match (prev, raw.get(i + 1).copied()) {
                    (Some(prev), Some(n)) => {
                        let extra = (n as i32 - 29).max(0) as usize;
                        for _ in 0..extra {
                            out.push(prev);
                        }
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out.iter().map(|&b| b as char).collect()
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
        BreakpointKind::WriteWatch => 2,
        BreakpointKind::ReadWatch => 3,
        BreakpointKind::AccessWatch => 4,
    }
}

/// The `kind` argument of a `Z`/`z` packet.
///
/// For execute breakpoints (Z0/Z1) it encodes the breakpoint instruction size
/// the stub should plant, which is architecture-specific — gdbserver rejects a
/// mismatch (`E01`), so a hardcoded x86 `1` breaks software breakpoints on
/// every fixed-width-instruction target. For watchpoints (Z2..Z4) it is the
/// size of the watched region instead.
fn bp_kind_length(arch: crate::arch::Architecture, kind: BreakpointKind) -> u32 {
    use crate::arch::Architecture::*;
    match kind {
        BreakpointKind::Software | BreakpointKind::Hardware => match arch {
            // 4-byte breakpoint instructions (BRK / BKPT / BREAK / EBREAK).
            // 32-bit ARM assumes ARM mode — Thumb sites would need kind 2/3,
            // which requires mode knowledge we don't track yet. RISC-V stubs
            // accept 4 (non-compressed EBREAK) as the safe default.
            Arm | Arm64 | Mips | Mips64 | RiscV32 | RiscV64 => 4,
            // x86 `int3` and anything unknown.
            _ => 1,
        },
        // Default to a 4-byte watch region — the most common case for ints
        // and pointer-low halves on 32-bit targets. Users can customize via
        // a future API; for now this matches `gdb`'s default.
        _ => 4,
    }
}

/// Map a register name to its `(gdb regnum, byte width)` using the `g`-packet
/// layout order. The regnum used by the `P` write packet is the same index as
/// in the `g`/`p` packets, so the position in [`register_layout`] is canonical.
fn regnum_and_size(arch: crate::arch::Architecture, name: &str) -> Option<(usize, usize)> {
    register_layout(arch)
        .iter()
        .enumerate()
        .find(|(_, (n, _))| *n == name)
        .map(|(idx, (_, size))| (idx, *size))
}

/// Build a `P<regnum>=<hex>` write-register packet. The value is encoded as the
/// register's raw little-endian bytes, exactly `width` bytes wide — over- or
/// under-shooting the width makes the stub reply `E`. Returns `None` for an
/// unknown register on this architecture.
fn build_p_packet(arch: crate::arch::Architecture, name: &str, value: u64) -> Option<String> {
    let (regnum, size) = regnum_and_size(arch, name)?;
    let le = value.to_le_bytes();
    let mut hex = String::with_capacity(size * 2);
    for &b in &le[..size] {
        hex.push_str(&format!("{:02x}", b));
    }
    Some(format!("P{:x}={}", regnum, hex))
}

/// Build an `M<addr>,<len>:<hex>` write-memory packet. The data is a raw byte
/// image (not endianness-swapped), matching what `m` returns.
fn build_m_packet(addr: u64, data: &[u8]) -> String {
    let mut hex = String::with_capacity(data.len() * 2);
    for &b in data {
        hex.push_str(&format!("{:02x}", b));
    }
    format!("M{:x},{:x}:{}", addr, data.len(), hex)
}

/// Read the value of an XML attribute `key="value"` from a single tag's text.
fn attr_value(tag: &str, key: &str) -> Option<String> {
    let needle = format!("{}=\"", key);
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

/// Parse an address attribute that may be `0x`-prefixed hex or decimal.
fn parse_addr_attr(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse().ok().or_else(|| u64::from_str_radix(t, 16).ok())
    }
}

/// Split a `qXfer` read reply into its more-to-come marker (`m` = more, `l` =
/// last) and the payload chunk. Returns `None` for an empty reply or an
/// unexpected marker. Uses `strip_prefix`, not a byte-index `split_at` — the
/// decoded reply is untrusted and may begin with a multi-byte char, where a
/// byte split would panic on the char boundary.
fn qxfer_chunk(reply: &str) -> Option<(bool, &str)> {
    if let Some(chunk) = reply.strip_prefix('m') {
        Some((true, chunk))
    } else if let Some(chunk) = reply.strip_prefix('l') {
        Some((false, chunk))
    } else {
        None
    }
}

/// Parse a `qXfer:libraries-svr4` document into `(name, load_address)` pairs.
///
/// Handles the svr4 form (`<library name=... l_addr="0x..."/>`) and the older
/// libraries form (`<library name=...><segment address="0x.."/></library>`).
/// The container element `<library-list-svr4 …>` is skipped.
fn parse_libraries_svr4_xml(xml: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<library") {
        let after = &rest[pos + "<library".len()..];
        rest = after;
        // Distinguish a real `<library ...>` entry from the `<library-list-…>`
        // container by the delimiter that follows the element name.
        if !after.starts_with([' ', '\t', '\n', '\r', '/', '>']) {
            continue;
        }
        let tag_end = after.find('>').unwrap_or(after.len());
        let tag = &after[..tag_end];
        let Some(name) = attr_value(tag, "name") else {
            continue;
        };
        let addr = attr_value(tag, "l_addr")
            .as_deref()
            .and_then(parse_addr_attr)
            .or_else(|| {
                // Older form: a nested <segment address="0x..."> after the tag.
                let segment_region = &after[tag_end..];
                segment_region.find("<segment").and_then(|sp| {
                    let seg_tag = &segment_region[sp..];
                    let seg_end = seg_tag.find('>').unwrap_or(seg_tag.len());
                    attr_value(&seg_tag[..seg_end], "address")
                        .as_deref()
                        .and_then(parse_addr_attr)
                })
            });
        if let Some(addr) = addr {
            out.push((name, addr));
        }
    }
    out
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
            let code = u32::from_str_radix(reply.get(1..reply.len().min(3)).unwrap_or(""), 16)
                .unwrap_or(0);
            StopReason::Exited(code as i32)
        }
        b'X' => {
            let sig = u32::from_str_radix(reply.get(1..reply.len().min(3)).unwrap_or(""), 16)
                .unwrap_or(0);
            StopReason::Terminated(sig)
        }
        b'S' => {
            let sig = u32::from_str_radix(reply.get(1..reply.len().min(3)).unwrap_or(""), 16)
                .unwrap_or(0);
            StopReason::Signal(sig)
        }
        b'T' => {
            // `T<sig><key>:<val>;<key>:<val>;…`
            let sig = u32::from_str_radix(reply.get(1..3).unwrap_or("00"), 16).unwrap_or(0);
            let body = reply.get(3..).unwrap_or("");
            let mut pc: Option<u64> = None;
            let mut sw_break = false;
            let mut hw_break = false;
            let mut watch: Option<(WatchpointHit, u64)> = None;
            for kv in body.split(';') {
                if kv.is_empty() {
                    continue;
                }
                let (key, value) = kv.split_once(':').unwrap_or((kv, ""));
                match key {
                    "swbreak" => sw_break = true,
                    "hwbreak" => hw_break = true,
                    // Watch kv pairs carry the accessed data address in hex.
                    "watch" | "rwatch" | "awatch" => {
                        let kind = match key {
                            "watch" => WatchpointHit::Write,
                            "rwatch" => WatchpointHit::Read,
                            _ => WatchpointHit::Access,
                        };
                        let data_addr = u64::from_str_radix(value, 16).unwrap_or(0);
                        watch = Some((kind, data_addr));
                    }
                    _ => {}
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
            if let Some((kind, data_address)) = watch {
                StopReason::Watchpoint {
                    kind,
                    pc: pc.unwrap_or(0),
                    data_address,
                }
            } else if hw_break {
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
        let reply = self.resume_and_wait("s")?;
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
        let reply = self.resume_and_wait("c")?;
        let reason = parse_stop_reply(&reply);
        self.state = match reason {
            StopReason::Exited(_) | StopReason::Terminated(_) => DebuggerState::Detached,
            _ => DebuggerState::Paused,
        };
        Ok(reason)
    }

    fn set_breakpoint(&mut self, address: u64, kind: BreakpointKind) -> Result<()> {
        self.set_breakpoint_internal(address, kind, None)
    }

    fn set_breakpoint_for_thread(
        &mut self,
        address: u64,
        kind: BreakpointKind,
        thread_id: u64,
    ) -> Result<()> {
        self.set_breakpoint_internal(address, kind, Some(thread_id))
    }

    fn remove_breakpoint(&mut self, address: u64, kind: BreakpointKind) -> Result<()> {
        let z = bp_kind_byte(kind);
        let len = bp_kind_length(self.arch, kind);
        let pkt = format!("z{},{:x},{}", z, address, len);
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" || reply.is_empty() {
            self.breakpoints
                .retain(|bp| bp.0 != address || bp.1 != kind);
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
        self.breakpoints.iter().map(|(a, k, _)| (*a, *k)).collect()
    }

    fn breakpoints_scoped(&self) -> Vec<(u64, BreakpointKind, Option<u64>)> {
        self.breakpoints.clone()
    }

    fn threads(&self) -> Vec<u64> {
        // RSP enumerates with `qfThreadInfo` followed by repeated
        // `qsThreadInfo` until the stub replies `l`. Each reply is `m<tid>[,<tid>...]`.
        let mut out = Vec::new();
        let mut packet = "qfThreadInfo".to_string();
        let mut rounds = 0usize;
        while let Ok(reply) = self.send_recv(&packet) {
            rounds += 1;
            if rounds > MAX_THREAD_ROUNDS {
                break; // stub never sent the terminating `l`
            }
            if reply.is_empty() || reply == "l" {
                break;
            }
            let Some(rest) = reply.strip_prefix('m') else {
                break;
            };
            for tok in rest.split(',') {
                if let Ok(tid) = u64::from_str_radix(tok.trim(), 16) {
                    out.push(tid);
                }
            }
            packet = "qsThreadInfo".to_string();
        }
        if let Ok(mut cache) = self.threads_cache.lock() {
            *cache = out.clone();
        }
        out
    }

    fn set_active_thread(&mut self, tid: u64) -> Result<()> {
        // `Hg<tid>` selects the thread for subsequent `g`/`m` operations.
        let pkt = format!("Hg{:x}", tid);
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" || reply.is_empty() {
            if let Ok(mut active) = self.active_thread.lock() {
                *active = Some(tid);
            }
            Ok(())
        } else if let Some(code) = reply.strip_prefix('E') {
            Err(Error::Debugger(format!("Hg E{}", code)))
        } else {
            Err(Error::Debugger(format!("Hg unexpected: {}", reply)))
        }
    }

    fn interrupt(&mut self) -> Result<()> {
        // `\x03` is the standard RSP all-stop interrupt — sent unframed
        // (no `$...#cc` envelope) so the stub reads it even when the link
        // is already mid-packet from a `c` reply.
        self.write_raw(0x03)
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

    fn modules(&self) -> Vec<(String, u64)> {
        // Read the svr4 library list via qXfer, accumulating chunks until the
        // stub signals the last one with the `l` marker. Any error / empty /
        // unsupported reply degrades to whatever was gathered (usually none).
        let mut xml = String::new();
        let mut offset = 0usize;
        for _ in 0..64 {
            let pkt = format!("qXfer:libraries-svr4:read::{:x},{:x}", offset, 0x1000);
            let reply = match self.send_recv(&pkt) {
                Ok(r) => r,
                Err(_) => break,
            };
            if reply.starts_with('E') {
                break;
            }
            let Some((more, chunk)) = qxfer_chunk(&reply) else {
                break; // empty or unexpected marker
            };
            xml.push_str(chunk);
            offset += chunk.len();
            if !more {
                break;
            }
        }
        parse_libraries_svr4_xml(&xml)
    }

    fn write_register(&mut self, name: &str, value: u64) -> Result<()> {
        let pkt = build_p_packet(self.arch, name, value)
            .ok_or_else(|| Error::Debugger(format!("unknown register {}", name)))?;
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" {
            Ok(())
        } else if reply.is_empty() {
            // Empty reply is RSP's "packet not supported" — never report a
            // write that did not happen as success.
            Err(Error::Debugger(
                "stub does not support register writes (P)".into(),
            ))
        } else if let Some(code) = reply.strip_prefix('E') {
            Err(Error::Debugger(format!("write reg E{}", code)))
        } else {
            Err(Error::Debugger(format!(
                "write reg unexpected reply: {}",
                reply
            )))
        }
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let pkt = build_m_packet(addr, data);
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" {
            Ok(())
        } else if reply.is_empty() {
            // Empty reply is RSP's "packet not supported" — never report a
            // write that did not happen as success.
            Err(Error::Debugger(
                "stub does not support memory writes (M)".into(),
            ))
        } else if let Some(code) = reply.strip_prefix('E') {
            Err(Error::Debugger(format!("write mem E{}", code)))
        } else {
            Err(Error::Debugger(format!(
                "write mem unexpected reply: {}",
                reply
            )))
        }
    }
}

impl GdbRemoteDebugger {
    /// Internal: set a breakpoint with optional thread scope. The RSP `Z`
    /// packet supports a `;X<thread>` suffix on stubs that advertise
    /// `swbreak+`/`hwbreak+` capability — see the gdbserver protocol docs.
    /// Stubs that don't recognize the suffix simply ignore it and apply the
    /// breakpoint process-wide, which matches our default trait impl.
    fn set_breakpoint_internal(
        &mut self,
        address: u64,
        kind: BreakpointKind,
        thread_id: Option<u64>,
    ) -> Result<()> {
        let z = bp_kind_byte(kind);
        let len = bp_kind_length(self.arch, kind);
        let pkt = match thread_id {
            Some(tid) => format!("Z{},{:x},{};X{:x}", z, address, len, tid),
            None => format!("Z{},{:x},{}", z, address, len),
        };
        let reply = self.send_recv(&pkt)?;
        if reply == "OK" || reply.is_empty() {
            self.breakpoints.push((address, kind, thread_id));
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
    fn decode_rsp_body_expands_rle() {
        // `0* ` — the space (0x20 = 32) encodes a count of 32 - 29 = 3, so the
        // preceding `0` is repeated three additional times: four `0`s total.
        assert_eq!(decode_rsp_body(b"0* "), "0000");
        // A plain payload passes through untouched.
        assert_eq!(decode_rsp_body(b"deadbeef"), "deadbeef");
    }

    #[test]
    fn decode_rsp_body_unescapes() {
        // `}` + (0x23 ^ 0x20 = 0x03) yields a literal '#' (0x23).
        assert_eq!(decode_rsp_body(b"}\x03"), "#");
        // `}` + (0x7d ^ 0x20 = 0x5d) yields a literal '}' (0x7d).
        assert_eq!(decode_rsp_body(b"}]"), "}");
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
    fn stop_reply_tolerates_non_ascii_bytes() {
        // A malformed reply whose decoded bytes put a multi-byte char across the
        // signal-code slice must not panic (regression for char-boundary
        // slicing of the W/X/S signal codes).
        assert!(matches!(
            parse_stop_reply("SA\u{80}"),
            StopReason::Signal(_)
        ));
        assert!(matches!(
            parse_stop_reply("WA\u{80}"),
            StopReason::Exited(_)
        ));
        assert!(matches!(
            parse_stop_reply("XA\u{80}"),
            StopReason::Terminated(_)
        ));
    }

    #[test]
    fn bp_kind_byte_matches_protocol_codes() {
        assert_eq!(bp_kind_byte(BreakpointKind::Software), 0);
        assert_eq!(bp_kind_byte(BreakpointKind::Hardware), 1);
        assert_eq!(bp_kind_byte(BreakpointKind::WriteWatch), 2);
        assert_eq!(bp_kind_byte(BreakpointKind::ReadWatch), 3);
        assert_eq!(bp_kind_byte(BreakpointKind::AccessWatch), 4);
    }

    #[test]
    fn regnum_maps_rip_to_16() {
        use crate::arch::Architecture::X86_64;
        assert_eq!(regnum_and_size(X86_64, "rip"), Some((16, 8)));
        assert_eq!(regnum_and_size(X86_64, "rax"), Some((0, 8)));
        assert_eq!(regnum_and_size(X86_64, "nope"), None);
    }

    #[test]
    fn p_packet_format() {
        use crate::arch::Architecture::X86_64;
        // rax (regnum 0), full 8 bytes, little-endian.
        assert_eq!(
            build_p_packet(X86_64, "rax", 0x1122334455667788),
            Some("P0=8877665544332211".to_string())
        );
    }

    #[test]
    fn eflags_writes_4_bytes() {
        use crate::arch::Architecture::X86_64;
        // eflags is regnum 17 (0x11) and only 4 bytes wide — the high half of
        // the u64 must be dropped or the stub rejects the write.
        assert_eq!(
            build_p_packet(X86_64, "eflags", 0x246),
            Some("P11=46020000".to_string())
        );
    }

    #[test]
    fn m_packet_format() {
        assert_eq!(
            build_m_packet(0x1000, &[0xde, 0xad, 0xbe, 0xef]),
            "M1000,4:deadbeef"
        );
    }

    #[test]
    fn parse_libraries_svr4_xml_extracts_name_and_base() {
        let xml = "<library-list-svr4 version=\"1.0\" main-lm=\"0x5\">\
            <library name=\"/lib/x86_64-linux-gnu/libc.so.6\" lm=\"0x10\" \
                     l_addr=\"0x7ffff7a00000\" l_ld=\"0x20\"/>\
            <library name=\"/lib64/ld-linux-x86-64.so.2\" l_addr=\"0x7ffff7fd0000\"/>\
            </library-list-svr4>";
        let libs = parse_libraries_svr4_xml(xml);
        assert_eq!(libs.len(), 2);
        assert_eq!(libs[0].0, "/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(libs[0].1, 0x7ffff7a00000);
        assert_eq!(libs[1].0, "/lib64/ld-linux-x86-64.so.2");
        assert_eq!(libs[1].1, 0x7ffff7fd0000);
    }

    #[test]
    fn parse_libraries_svr4_xml_handles_segment_form() {
        let xml = "<library name=\"a.so\"><segment address=\"0x400000\"/></library>";
        assert_eq!(
            parse_libraries_svr4_xml(xml),
            vec![("a.so".to_string(), 0x400000)]
        );
    }

    #[test]
    fn parse_libraries_svr4_xml_empty_when_unsupported() {
        assert!(parse_libraries_svr4_xml("").is_empty());
    }

    #[test]
    fn qxfer_chunk_is_panic_free_on_non_ascii_marker() {
        // A hostile stub can lead the reply with a byte >= 0x80, which
        // decode_rsp_body turns into a multi-byte char; a byte-index
        // split_at(1) would panic on the char boundary here.
        let decoded = decode_rsp_body(&[0x80, b'x']);
        assert_eq!(qxfer_chunk(&decoded), None);
        assert_eq!(qxfer_chunk("m<library/>"), Some((true, "<library/>")));
        assert_eq!(qxfer_chunk("l"), Some((false, "")));
        assert_eq!(qxfer_chunk(""), None);
    }

    #[test]
    fn watchpoints_use_4_byte_region() {
        use crate::arch::Architecture::X86_64;
        assert_eq!(bp_kind_length(X86_64, BreakpointKind::WriteWatch), 4);
        assert_eq!(bp_kind_length(X86_64, BreakpointKind::Hardware), 1);
    }

    #[test]
    fn execute_breakpoint_kind_tracks_instruction_width() {
        use crate::arch::Architecture::*;
        // x86 plants a 1-byte int3; fixed-width ISAs need their instruction
        // size or gdbserver rejects the Z packet with E01.
        assert_eq!(bp_kind_length(X86, BreakpointKind::Software), 1);
        assert_eq!(bp_kind_length(X86_64, BreakpointKind::Hardware), 1);
        for arch in [Arm, Arm64, Mips, Mips64, RiscV32, RiscV64] {
            assert_eq!(bp_kind_length(arch, BreakpointKind::Software), 4);
            assert_eq!(bp_kind_length(arch, BreakpointKind::Hardware), 4);
        }
    }
}
