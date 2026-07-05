use nix::errno::Errno;
use oneshot::RecvError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DebugError>;

#[derive(Error, Debug)]
pub enum DebugError {
    #[error("PTrace error with errno: {0}")]
    PtraceError(#[from] Errno),
    #[error("Recv Channel error: {0}")]
    RecvChannelError(#[from] RecvError),
}
