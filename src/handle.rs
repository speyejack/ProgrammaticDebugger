#![allow(dead_code)]
use std::{
    ffi::c_long,
    sync::{Arc, mpsc},
};

use nix::{
    libc::{ptrace_syscall_info, siginfo_t, user_regs_struct},
    sys::{
        eventfd::{EfdFlags, EventFd},
        ptrace::{self, AddressType, RegisterSet},
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};

use crate::{Result, comms::ProcCmd, debug_thread::ProcThread, err::DebugError};

pub struct DebugHandle {
    pub alert_fd: Arc<EventFd>,
    pub cmds: mpsc::Sender<ProcCmd>,
}
impl DebugHandle {
    pub fn setup_debugger(pid: Pid) -> Result<(DebugHandle, ProcThread)> {
        let alert_fd = Arc::new(EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap());
        let (send, recv) = mpsc::channel();
        let thread = ProcThread::new(pid, recv, alert_fd.clone());

        let handle = DebugHandle {
            alert_fd,
            cmds: send,
        };

        Ok((handle, thread))
    }

    pub async fn send_interrupt(&mut self) {
        let _ = self.alert_fd.write(1);
    }

    pub async fn wait_pid(&mut self, flags: Option<WaitPidFlag>) -> Result<WaitStatus> {
        let (send, recv) = oneshot::async_channel();
        self.cmds.send(ProcCmd::WaitPid(flags, send)).unwrap();

        recv.await?
    }

    pub async fn wait_event(&mut self, flags: Option<WaitPidFlag>) -> Result<(WaitStatus, bool)> {
        let (send, recv) = oneshot::async_channel();
        self.cmds.send(ProcCmd::WaitEvent(flags, send)).unwrap();

        recv.await?
    }

    // Taken from ptrace

    pub async fn attach(&mut self) -> Result<()> {
        self.send_cmd(move |pid| ptrace::attach(pid)).await
    }

    pub async fn cont<T>(&mut self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let t = sig.into();
        self.send_cmd(move |pid| ptrace::cont(pid, t)).await
    }

    pub async fn detach<T>(mut self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let t = sig.into();
        self.send_cmd(move |pid| ptrace::detach(pid, t)).await
    }

    pub async fn getevent(&mut self) -> Result<i64> {
        self.send_cmd(move |pid| ptrace::getevent(pid)).await
    }

    pub async fn getregs(&mut self) -> Result<user_regs_struct> {
        self.send_cmd(move |pid| ptrace::getregs(pid)).await
    }

    pub async fn getregset<S: RegisterSet>(&mut self) -> Result<S::Regs>
    where
        <S as RegisterSet>::Regs: Send + 'static,
    {
        self.send_cmd(move |pid| ptrace::getregset::<S>(pid)).await
    }

    pub async fn getsiginfo(&mut self) -> Result<siginfo_t> {
        self.send_cmd(move |pid| ptrace::getsiginfo(pid)).await
    }

    pub async fn raw_interrupt(&mut self) -> Result<()> {
        self.send_cmd(move |pid| ptrace::interrupt(pid)).await
    }

    pub async fn kill(mut self) -> Result<()> {
        self.send_cmd(move |pid| ptrace::kill(pid)).await
    }

    pub async fn read(&mut self, addr: usize) -> Result<c_long> {
        self.send_cmd(move |pid| ptrace::read(pid, addr as AddressType))
            .await
    }

    pub async fn read_user(&mut self, offset: usize) -> Result<c_long> {
        self.send_cmd(move |pid| ptrace::read_user(pid, offset as AddressType))
            .await
    }

    pub async fn seize(&mut self, options: ptrace::Options) -> Result<()> {
        self.send_cmd(move |pid| ptrace::seize(pid, options)).await
    }

    pub async fn setoptions(&mut self, options: ptrace::Options) -> Result<()> {
        self.send_cmd(move |pid| ptrace::setoptions(pid, options))
            .await
    }

    pub async fn setregs(&mut self, regs: user_regs_struct) -> Result<()> {
        self.send_cmd(move |pid| ptrace::setregs(pid, regs)).await
    }

    pub async fn setregset<S>(&mut self, regs: S::Regs) -> Result<()>
    where
        S: RegisterSet + Send + 'static,
        <S as RegisterSet>::Regs: Send + 'static,
    {
        self.send_cmd(move |pid| ptrace::setregset::<S>(pid, regs))
            .await
    }

    pub async fn setsiginfo(&mut self, sig: siginfo_t) -> Result<()> {
        self.send_cmd(move |pid| ptrace::setsiginfo(pid, &sig))
            .await
    }

    pub async fn step<T>(&mut self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::step(pid, sig)).await
    }

    pub async fn syscall<T>(&mut self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::syscall(pid, sig)).await
    }

    pub async fn syscall_info(&mut self) -> Result<ptrace_syscall_info> {
        self.send_cmd(move |pid| ptrace::syscall_info(pid)).await
    }

    pub async fn sysemu<T>(&mut self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::sysemu(pid, sig)).await
    }
    pub async fn sysemu_step<T>(&mut self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_cmd(move |pid| ptrace::sysemu_step(pid, sig))
            .await
    }

    pub async fn write(&mut self, addr: usize, data: c_long) -> Result<()> {
        self.send_cmd(move |pid| ptrace::write(pid, addr as AddressType, data))
            .await
    }

    pub async fn write_user(&mut self, offset: usize, data: c_long) -> Result<()> {
        self.send_cmd(move |pid| ptrace::write_user(pid, offset as AddressType, data))
            .await
    }

    async fn send_cmd<T, F, E>(&mut self, func: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Pid) -> std::result::Result<T, E> + Send + 'static,
        E: Into<DebugError> + Send + 'static,
    {
        let (send, recv) = oneshot::async_channel();

        let wrapper = move |pid| {
            let res = func(pid);
            let _ = send.send(res);
        };

        self.cmds.send(ProcCmd::Cmd(Box::new(wrapper))).unwrap();
        let data = recv.await?;

        data.map_err(Into::into)
    }
}
