//! Concrete [`Debugger`](crate::Debugger) backends.
//!
//! At present only [`GdbRemoteDebugger`] is supplied — a minimum-viable
//! implementation of the GDB Remote Serial Protocol (RSP) that can talk to
//! `gdbserver`, QEMU's gdbstub, LLDB's platform server in gdb compatibility
//! mode, or any other RSP-speaking stub.
pub mod gdb_remote;

pub use gdb_remote::GdbRemoteDebugger;
