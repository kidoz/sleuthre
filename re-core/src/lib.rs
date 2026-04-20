pub mod analysis;
pub mod arch;
pub mod collab;
pub mod db;
pub mod debuggers;
pub mod debuginfo;
pub mod disasm;
pub mod error;
pub mod formats;
pub mod il;
pub mod import;
pub mod loader;
pub mod memory;
pub mod plugin;
pub mod project;
pub mod scripting;
pub mod signatures;
pub mod typelib;
pub mod types;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DebuggerState {
    Detached,
    Running,
    Paused,
}

/// Why an inferior stopped after `step()` or `continue_exec()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Single-step completed.
    Step,
    /// A software breakpoint at the given address was hit.
    SoftwareBreakpoint(u64),
    /// A hardware breakpoint at the given address was hit.
    HardwareBreakpoint(u64),
    /// A watchpoint fired. `pc` is the instruction that triggered the
    /// access; `data_address` is the memory location that was read or
    /// written. `kind` indicates which flavour of watch (write/read/access).
    Watchpoint {
        kind: WatchpointHit,
        pc: u64,
        data_address: u64,
    },
    /// The inferior received a POSIX signal (e.g. 5 = SIGTRAP).
    Signal(u32),
    /// The inferior exited normally.
    Exited(i32),
    /// The inferior was killed by a signal.
    Terminated(u32),
    /// The stub returned a stop reply we couldn't classify.
    Other(String),
}

/// Kind of watchpoint that fired in a [`StopReason::Watchpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchpointHit {
    Write,
    Read,
    Access,
}

/// Type of breakpoint or watchpoint to set. Maps directly to the GDB Remote
/// Serial Protocol `Z<type>` codes:
///
/// | Variant         | RSP code | Description |
/// |-----------------|----------|-------------|
/// | `Software`      | `Z0`     | Software (INT3-style) execute breakpoint |
/// | `Hardware`      | `Z1`     | Hardware execute breakpoint |
/// | `WriteWatch`    | `Z2`     | Watchpoint that fires on memory write |
/// | `ReadWatch`     | `Z3`     | Watchpoint that fires on memory read |
/// | `AccessWatch`   | `Z4`     | Watchpoint that fires on either |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    Software,
    Hardware,
    WriteWatch,
    ReadWatch,
    AccessWatch,
}

pub trait Debugger {
    fn state(&self) -> DebuggerState;
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn detach(&mut self) -> Result<()>;
    fn step(&mut self) -> Result<StopReason>;
    fn continue_exec(&mut self) -> Result<StopReason>;
    fn registers(&self) -> std::collections::HashMap<String, u64>;
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>>;

    /// Enumerate threads currently visible to the stub. Default: empty (single-thread targets).
    fn threads(&self) -> Vec<u64> {
        Vec::new()
    }

    /// Switch the active thread used by subsequent register/memory queries.
    /// Default: not supported.
    fn set_active_thread(&mut self, _tid: u64) -> Result<()> {
        Err(Error::Debugger("thread switching not supported".into()))
    }

    /// Send an asynchronous interrupt (Ctrl+C / 0x03) to the running inferior
    /// so a `continue_exec` blocked in another thread returns. Default: error.
    fn interrupt(&mut self) -> Result<()> {
        Err(Error::Debugger("interrupt not supported".into()))
    }

    /// Set a breakpoint. The default implementation records nothing — concrete
    /// backends (e.g. `GdbRemoteDebugger`) override.
    fn set_breakpoint(&mut self, _address: u64, _kind: BreakpointKind) -> Result<()> {
        Err(Error::Debugger("breakpoints not supported".into()))
    }

    /// Set a breakpoint scoped to a specific thread. The stub may translate
    /// this into a thread-conditional breakpoint or apply it process-wide
    /// depending on its capabilities. Default delegates to `set_breakpoint`
    /// (process-wide).
    fn set_breakpoint_for_thread(
        &mut self,
        address: u64,
        kind: BreakpointKind,
        _thread_id: u64,
    ) -> Result<()> {
        self.set_breakpoint(address, kind)
    }

    /// Remove a breakpoint previously set with [`set_breakpoint`].
    fn remove_breakpoint(&mut self, _address: u64, _kind: BreakpointKind) -> Result<()> {
        Err(Error::Debugger("breakpoints not supported".into()))
    }

    /// Enumerate currently-set breakpoints. Each entry is `(address, kind, optional thread)`.
    fn breakpoints(&self) -> Vec<(u64, BreakpointKind)> {
        Vec::new()
    }

    /// Enumerate breakpoints with thread scope. Default falls back to the
    /// process-wide list with `None` for the thread.
    fn breakpoints_scoped(&self) -> Vec<(u64, BreakpointKind, Option<u64>)> {
        self.breakpoints()
            .into_iter()
            .map(|(a, k)| (a, k, None))
            .collect()
    }

    /// Walk the frame-pointer chain starting at the current RBP/EBP and
    /// return the saved return addresses, deepest call first.
    ///
    /// This is the classic "no DWARF needed" approach: at each frame the
    /// previous frame pointer lives at `[fp]` and the saved return address
    /// at `[fp + ptr_size]`. Works on any function compiled with frame
    /// pointers enabled (most non-`-fomit-frame-pointer` builds, all debug
    /// builds). Stops on a `NULL` fp or after `max_depth` frames.
    fn frame_pointer_backtrace(
        &self,
        arch: crate::arch::Architecture,
        max_depth: usize,
    ) -> Vec<u64> {
        let regs = self.registers();
        let (fp_name, ip_name) = match arch {
            crate::arch::Architecture::X86_64 => ("rbp", "rip"),
            crate::arch::Architecture::X86 => ("ebp", "eip"),
            crate::arch::Architecture::Arm64 => ("fp", "pc"),
            crate::arch::Architecture::Arm => ("r11", "pc"),
            _ => return Vec::new(),
        };
        let mut out = Vec::new();
        if let Some(&pc) = regs.get(ip_name) {
            out.push(pc);
        }
        let Some(&start_fp) = regs.get(fp_name) else {
            return out;
        };
        let ptr_size = arch.pointer_size();
        let mut fp = start_fp;
        for _ in 0..max_depth {
            if fp == 0 {
                break;
            }
            let bytes = match self.read_memory(fp, ptr_size * 2) {
                Ok(b) => b,
                Err(_) => break,
            };
            if bytes.len() < ptr_size * 2 {
                break;
            }
            let next_fp = read_le_pointer(&bytes[..ptr_size]);
            let saved_ip = read_le_pointer(&bytes[ptr_size..ptr_size * 2]);
            if saved_ip != 0 {
                out.push(saved_ip);
            }
            // Frame pointers grow toward higher addresses on a descending
            // stack; a non-monotonic step indicates a corrupt frame chain
            // or end-of-stack — bail out instead of looping forever.
            if next_fp <= fp {
                break;
            }
            fp = next_fp;
        }
        out
    }
}

fn read_le_pointer(bytes: &[u8]) -> u64 {
    match bytes.len() {
        4 => u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as u64,
        8 => u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

pub struct MockDebugger {
    pub state: DebuggerState,
}

impl Default for MockDebugger {
    fn default() -> Self {
        Self {
            state: DebuggerState::Detached,
        }
    }
}

impl Debugger for MockDebugger {
    fn state(&self) -> DebuggerState {
        self.state
    }
    fn attach(&mut self, _pid: u32) -> Result<()> {
        self.state = DebuggerState::Paused;
        Ok(())
    }
    fn detach(&mut self) -> Result<()> {
        self.state = DebuggerState::Detached;
        Ok(())
    }
    fn step(&mut self) -> Result<StopReason> {
        Ok(StopReason::Step)
    }
    fn continue_exec(&mut self) -> Result<StopReason> {
        self.state = DebuggerState::Running;
        Ok(StopReason::Signal(0))
    }
    fn registers(&self) -> std::collections::HashMap<String, u64> {
        let mut regs = std::collections::HashMap::new();
        if self.state != DebuggerState::Detached {
            regs.insert("rax".to_string(), 0x12345678);
            regs.insert("rbx".to_string(), 0x0);
            regs.insert("rcx".to_string(), 0x401000);
            regs.insert("rsp".to_string(), 0x7ffffff0);
            regs.insert("rip".to_string(), 0x401050);
        }
        regs
    }
    fn read_memory(&self, _addr: u64, size: usize) -> Result<Vec<u8>> {
        Ok(vec![0; size])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Tiny fake stub that lets us drive `frame_pointer_backtrace` over a
    /// synthetic in-memory stack.
    struct FakeStack {
        regs: HashMap<String, u64>,
        memory: HashMap<u64, Vec<u8>>,
    }

    impl Debugger for FakeStack {
        fn state(&self) -> DebuggerState {
            DebuggerState::Paused
        }
        fn attach(&mut self, _: u32) -> Result<()> {
            Ok(())
        }
        fn detach(&mut self) -> Result<()> {
            Ok(())
        }
        fn step(&mut self) -> Result<StopReason> {
            Ok(StopReason::Step)
        }
        fn continue_exec(&mut self) -> Result<StopReason> {
            Ok(StopReason::Signal(5))
        }
        fn registers(&self) -> HashMap<String, u64> {
            self.regs.clone()
        }
        fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
            let bytes = self
                .memory
                .get(&addr)
                .cloned()
                .unwrap_or_else(|| vec![0; size]);
            Ok(bytes)
        }
    }

    fn put_u64(map: &mut HashMap<u64, Vec<u8>>, addr: u64, prev_fp: u64, ret: u64) {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&prev_fp.to_le_bytes());
        buf.extend_from_slice(&ret.to_le_bytes());
        map.insert(addr, buf);
    }

    #[test]
    fn frame_pointer_backtrace_walks_three_frames() {
        // Synthetic stack:
        //   frame at 0x10000  (innermost) → prev_fp=0x10100, ret=0xAAAA1
        //   frame at 0x10100              → prev_fp=0x10200, ret=0xAAAA2
        //   frame at 0x10200  (outermost) → prev_fp=0,        ret=0xAAAA3
        let mut memory = HashMap::new();
        put_u64(&mut memory, 0x10000, 0x10100, 0xAAAA1);
        put_u64(&mut memory, 0x10100, 0x10200, 0xAAAA2);
        put_u64(&mut memory, 0x10200, 0, 0xAAAA3);
        let mut regs = HashMap::new();
        regs.insert("rip".into(), 0xDEAD);
        regs.insert("rbp".into(), 0x10000);
        let dbg = FakeStack { regs, memory };
        let bt = dbg.frame_pointer_backtrace(crate::arch::Architecture::X86_64, 16);
        // Expected: current PC, then return addresses deepest-first.
        assert_eq!(bt, vec![0xDEAD, 0xAAAA1, 0xAAAA2, 0xAAAA3]);
    }

    #[test]
    fn backtrace_stops_on_corrupt_chain() {
        // Inner frame points at a *lower* address — defensive bail-out.
        let mut memory = HashMap::new();
        put_u64(&mut memory, 0x20000, 0x10000, 0xBBB);
        let mut regs = HashMap::new();
        regs.insert("rip".into(), 0xC0DE);
        regs.insert("rbp".into(), 0x20000);
        let dbg = FakeStack { regs, memory };
        let bt = dbg.frame_pointer_backtrace(crate::arch::Architecture::X86_64, 16);
        assert_eq!(bt, vec![0xC0DE, 0xBBB]);
    }
}
