use nix::{errno::Errno, sys::ptrace, unistd::Pid};
use oneshot::{RecvError, SendError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DebugError>;

#[derive(Error, Debug)]
pub enum DebugError {
    #[error("ptrace {op} failed using pid {pid}: {code}")]
    Ptrace {
        op: &'static str,
        pid: Pid,
        code: Errno,
    },
    #[error(transparent)]
    Channel(#[from] ChannelError),
}

#[derive(Error, Debug, Clone, Copy)]
pub enum ChannelError {
    #[error("oneshot recv failed during {op}")]
    OneshotRecv { op: &'static str },
    #[error("oneshot send failed during {op}")]
    OneshotSend { op: &'static str },
    #[error("async mpsc send failed during {op}")]
    AsyncMpscSend { op: &'static str },
    #[error("std mpsc send failed during {op}")]
    StdMpscSend { op: &'static str },
}

pub trait FromPtraceExt<T> {
    fn with_err(self, op: &'static str, pid: Pid) -> Result<T>;
}

impl<T> FromPtraceExt<T> for std::result::Result<T, Errno> {
    fn with_err(self, op: &'static str, pid: Pid) -> Result<T> {
        self.map_err(|code| DebugError::Ptrace { op, pid, code })
    }
}
pub trait FromOneshotSend<T> {
    fn with_err(self, op: &'static str) -> Result<T>;
}

impl<T> FromOneshotRecv<T> for std::result::Result<T, oneshot::RecvError> {
    fn with_err(self, op: &'static str) -> Result<T> {
        self.map_err(|_| DebugError::Channel(ChannelError::OneshotSend { op }))
    }
}

pub trait FromOneshotRecv<T> {
    fn with_err(self, op: &'static str) -> Result<T>;
}

impl<T, U> FromOneshotSend<T> for std::result::Result<T, oneshot::SendError<U>> {
    fn with_err(self, op: &'static str) -> Result<T> {
        self.map_err(|_| DebugError::Channel(ChannelError::OneshotSend { op }))
    }
}

pub trait FromMpscSend<T> {
    fn with_err(self, op: &'static str) -> Result<T>;
}

impl<T> FromMpscSend<T> for std::result::Result<T, futures::channel::mpsc::SendError> {
    fn with_err(self, op: &'static str) -> Result<T> {
        self.map_err(|_| DebugError::Channel(ChannelError::AsyncMpscSend { op }))
    }
}

pub trait FromStdMpscSend<T> {
    fn with_err(self, op: &'static str) -> Result<T>;
}

impl<T, U> FromStdMpscSend<T> for std::result::Result<T, std::sync::mpsc::SendError<U>> {
    fn with_err(self, op: &'static str) -> Result<T> {
        self.map_err(|_| DebugError::Channel(ChannelError::StdMpscSend { op }))
    }
}
