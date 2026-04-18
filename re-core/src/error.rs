use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Loader error: {0}")]
    Loader(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Debug info error: {0}")]
    DebugInfo(String),

    #[error("Debugger error: {0}")]
    Debugger(String),

    #[error("Unknown error")]
    Unknown,
}
