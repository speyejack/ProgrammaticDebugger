use nix::{
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};

use crate::Result;

pub enum PtraceRequest {
    Attach(oneshot::Sender<Result<()>>),
    Seize(ptrace::Options, oneshot::Sender<Result<()>>),
    Continue(Option<Signal>, oneshot::Sender<Result<()>>),
    Step(Option<Signal>, oneshot::Sender<Result<()>>),
    Cmd(Box<dyn FnOnce(Pid) + Send>),
}
