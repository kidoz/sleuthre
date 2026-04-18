pub mod analysis;
pub mod arch;
pub mod db;
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

pub trait Debugger {
    fn state(&self) -> DebuggerState;
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn detach(&mut self) -> Result<()>;
    fn step(&mut self) -> Result<()>;
    fn continue_exec(&mut self) -> Result<()>;
    fn registers(&self) -> std::collections::HashMap<String, u64>;
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>>;
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
    fn step(&mut self) -> Result<()> {
        Ok(())
    }
    fn continue_exec(&mut self) -> Result<()> {
        self.state = DebuggerState::Running;
        Ok(())
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
