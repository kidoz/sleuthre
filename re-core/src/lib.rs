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
    /// The inferior received a POSIX signal (e.g. 5 = SIGTRAP).
    Signal(u32),
    /// The inferior exited normally.
    Exited(i32),
    /// The inferior was killed by a signal.
    Terminated(u32),
    /// The stub returned a stop reply we couldn't classify.
    Other(String),
}

/// Type of breakpoint to set. Maps directly to the GDB Remote Serial
/// Protocol `Z<type>` codes (0=software, 1=hardware-execute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    Software,
    Hardware,
}

pub trait Debugger {
    fn state(&self) -> DebuggerState;
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn detach(&mut self) -> Result<()>;
    fn step(&mut self) -> Result<StopReason>;
    fn continue_exec(&mut self) -> Result<StopReason>;
    fn registers(&self) -> std::collections::HashMap<String, u64>;
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>>;

    /// Set a breakpoint. The default implementation records nothing — concrete
    /// backends (e.g. `GdbRemoteDebugger`) override.
    fn set_breakpoint(&mut self, _address: u64, _kind: BreakpointKind) -> Result<()> {
        Err(Error::Debugger("breakpoints not supported".into()))
    }

    /// Remove a breakpoint previously set with [`set_breakpoint`].
    fn remove_breakpoint(&mut self, _address: u64, _kind: BreakpointKind) -> Result<()> {
        Err(Error::Debugger("breakpoints not supported".into()))
    }

    /// Enumerate currently-set breakpoints.
    fn breakpoints(&self) -> Vec<(u64, BreakpointKind)> {
        Vec::new()
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
