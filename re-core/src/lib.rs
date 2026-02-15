pub mod analysis;
pub mod arch;
pub mod db;
pub mod debuginfo;
pub mod disasm;
pub mod error;
pub mod il;
pub mod loader;
pub mod memory;
pub mod plugin;
pub mod project;
pub mod signatures;
pub mod typelib;
pub mod types;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
