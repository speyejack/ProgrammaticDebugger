use nix::{
    libc::siginfo_t,
    sys::{ptrace, signal::Signal, wait::WaitStatus},
    unistd::Pid,
};

use crate::Result;

pub enum PtraceRequest {
    Attach(Pid, oneshot::Sender<Result<()>>),
    Seize(Pid, ptrace::Options, oneshot::Sender<Result<()>>),
    Continue(Pid, Option<Signal>, oneshot::Sender<Result<()>>),
    Step(Pid, Option<Signal>, oneshot::Sender<Result<()>>),
    Cmd(Box<dyn FnOnce() + Send>),
}

pub struct StopBatch {
    pub events: Vec<(WaitStatus, Option<siginfo_t>)>,
    pub was_interrupt: bool,
}
