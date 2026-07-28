#![allow(dead_code)]
use std::{
    ffi::c_long,
    sync::{Arc, Mutex, mpsc},
};

use nix::{
    errno::Errno,
    libc::{ptrace_syscall_info, siginfo_t, user_regs_struct},
    poll::PollTimeout,
    sys::{
        eventfd::{EfdFlags, EventFd},
        ptrace::{self, AddressType, RegisterSet},
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use oneshot::AsyncReceiver;

use crate::{
    Result,
    comms::ProcCmd,
    debug_thread::{INTERRUPT_SIGNAL, ProcThread, StopBatch},
    err::{
        DebugError, FromMpscSend, FromOneshotRecv, FromOneshotSend, FromPtraceExt, FromStdMpscSend,
    },
};

#[derive(Debug, Clone)]
pub struct DebugHandle {
    pub interrupting: Arc<Mutex<bool>>,
    pub sig_pid: Pid,
    pub cmds: mpsc::Sender<ProcCmd>,
}

impl DebugHandle {
    pub fn setup_debugger(
        pid: Pid,
    ) -> Result<(
        DebugHandle,
        ProcThread,
        futures::channel::mpsc::Receiver<Result<StopBatch>>,
    )> {
        let (send, recv) = mpsc::channel();
        let interrupting = Arc::new(std::sync::Mutex::new(false));
        let (event_send, event_recv) = futures::channel::mpsc::channel(10);
        let thread = ProcThread::new(pid, interrupting.clone(), recv, event_send);

        let handle = DebugHandle {
            interrupting,
            sig_pid: pid,
            cmds: send,
        };

        Ok((handle, thread, event_recv))
    }

    pub async fn send_interrupt(&self) -> Result<()> {
        let mut is_interrupting = self.interrupting.lock().expect("Poisoned Interrupt Lock");

        if !*is_interrupting {
            *is_interrupting = true;
            drop(is_interrupting);
            tracing::debug!("Handle sending interrupt signal");
            nix::sys::signal::kill(self.sig_pid, INTERRUPT_SIGNAL)
                .with_err("handle interrupting process", self.sig_pid)?;
        }
        // let _ = self.alert_fd.write(1);
        Ok(())
    }

    // Taken from ptrace

    pub async fn attach(&self) -> Result<()> {
        let (send, recv) = oneshot::async_channel();
        self.cmds
            .send(ProcCmd::Attach(send))
            .with_err("handle attach cmd")?;

        recv.await.with_err("handle attach cmd")?
    }

    pub async fn seize(&self, options: ptrace::Options) -> Result<()> {
        let (send, recv) = oneshot::async_channel();
        self.cmds
            .send(ProcCmd::Seize(options, send))
            .with_err("handle seize cmd")?;

        recv.await.with_err("handle seize cmd")?
    }

    pub async fn cont<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let (send, recv) = oneshot::async_channel();
        self.cmds
            .send(ProcCmd::Continue(sig.into(), send))
            .with_err("handle continue cmd")?;

        recv.await.with_err("handle continue cmd")?
    }

    pub async fn step<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let (send, recv) = oneshot::async_channel();
        self.cmds
            .send(ProcCmd::Step(sig.into(), send))
            .with_err("handle step cmd")?;

        recv.await.with_err("handle step cmd")?
    }

    pub async fn raw_attach(&self) -> Result<()> {
        self.send_cmd(move |pid| ptrace::attach(pid), "attach")
            .await
    }

    pub async fn raw_cont<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let t = sig.into();
        self.send_cmd(move |pid| ptrace::cont(pid, t), "continue")
            .await
    }

    pub async fn raw_waitpid<T>(&self, flags: T) -> Result<WaitStatus>
    where
        T: Into<Option<WaitPidFlag>>,
    {
        let options = flags.into();

        self.send_cmd(move |pid| waitpid(pid, options), "waitpid")
            .await
    }

    pub async fn detach<T>(self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let t = sig.into();
        self.send_cmd(move |pid| ptrace::detach(pid, t), "detach")
            .await
    }

    pub async fn getevent(&self) -> Result<i64> {
        self.send_cmd(move |pid| ptrace::getevent(pid), "getevent")
            .await
    }

    pub async fn getregs(&self) -> Result<user_regs_struct> {
        self.send_cmd(move |pid| ptrace::getregs(pid), "getregs")
            .await
    }

    pub async fn getregset<S: RegisterSet>(&self) -> Result<S::Regs>
    where
        <S as RegisterSet>::Regs: Send + 'static,
    {
        self.send_cmd(move |pid| ptrace::getregset::<S>(pid), "getregset")
            .await
    }

    pub async fn getsiginfo(&self) -> Result<siginfo_t> {
        self.send_cmd(move |pid| ptrace::getsiginfo(pid), "getsiginfo")
            .await
    }

    pub async fn raw_interrupt(&self) -> Result<()> {
        self.send_cmd(move |pid| ptrace::interrupt(pid), "interrupt")
            .await
    }

    pub async fn kill(self) -> Result<()> {
        self.send_cmd(move |pid| ptrace::kill(pid), "kill").await
    }

    pub async fn read(&self, addr: u64) -> Result<c_long> {
        self.send_cmd(move |pid| ptrace::read(pid, addr as AddressType), "read")
            .await
    }

    pub async fn read_user(&self, offset: usize) -> Result<c_long> {
        self.send_cmd(
            move |pid| ptrace::read_user(pid, offset as AddressType),
            "read_user",
        )
        .await
    }

    pub async fn raw_seize(&self, options: ptrace::Options) -> Result<()> {
        self.send_cmd(move |pid| ptrace::seize(pid, options), "seize")
            .await
    }

    pub async fn setoptions(&self, options: ptrace::Options) -> Result<()> {
        self.send_cmd(move |pid| ptrace::setoptions(pid, options), "setoptions")
            .await
    }

    pub async fn setregs(&self, regs: user_regs_struct) -> Result<()> {
        self.send_cmd(move |pid| ptrace::setregs(pid, regs), "setregs")
            .await
    }

    pub async fn setregset<S>(&self, regs: S::Regs) -> Result<()>
    where
        S: RegisterSet + Send + 'static,
        <S as RegisterSet>::Regs: Send + 'static,
    {
        self.send_cmd(move |pid| ptrace::setregset::<S>(pid, regs), "setregset")
            .await
    }

    pub async fn setsiginfo(&self, sig: siginfo_t) -> Result<()> {
        self.send_cmd(move |pid| ptrace::setsiginfo(pid, &sig), "setsiginfo")
            .await
    }

    pub async fn raw_step<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::step(pid, sig), "step")
            .await
    }

    pub async fn syscall<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::syscall(pid, sig), "syscall")
            .await
    }

    pub async fn syscall_info(&self) -> Result<ptrace_syscall_info> {
        self.send_cmd(move |pid| ptrace::syscall_info(pid), "syscall_info")
            .await
    }

    pub async fn sysemu<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::sysemu(pid, sig), "sysemu")
            .await
    }
    pub async fn sysemu_step<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::sysemu_step(pid, sig), "sysemu_step")
            .await
    }

    pub async fn write(&self, addr: u64, data: c_long) -> Result<()> {
        self.send_cmd(
            move |pid| ptrace::write(pid, addr as AddressType, data),
            "write",
        )
        .await
    }

    pub async fn write_user(&self, offset: usize, data: c_long) -> Result<()> {
        self.send_cmd(
            move |pid| ptrace::write_user(pid, offset as AddressType, data),
            "write_user",
        )
        .await
    }

    async fn send_cmd<T, F>(&self, func: F, op: &'static str) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Pid) -> std::result::Result<T, Errno> + Send + 'static,
    {
        let (send, recv) = oneshot::async_channel();

        let wrapper = move |pid| {
            let res = func(pid).with_err(op, pid);
            let _ = send.send(res);
        };

        self.cmds
            .send(ProcCmd::Cmd(Box::new(wrapper)))
            .with_err("handle cmd")?;

        let data = recv.await.with_err("handle cmd")?;

        data
    }
}
