#[cfg(feature = "mmap")]
use std::num::NonZeroU64;
use std::sync::Arc;

use futures::SinkExt;
use futures::channel::mpsc;
use nix::libc::user_regs_struct;
#[cfg(feature = "mmap")]
use nix::sys::mman::{MapFlags, ProtFlags};

use crate::{
    Result, TraceeHandle,
    breakpoint::HardwareBreakpoint,
    debugger::{DebuggerMessage, TaskID},
    err::{FromMpscSend, FromOneshotRecv},
};

pub struct Task {
    pub(crate) id: TaskID,
    pub(crate) sender: futures::channel::mpsc::Sender<DebuggerMessage>,
    pub(crate) debug_handle: Arc<TraceeHandle>,
}

impl Task {
    pub async fn create_task(&mut self) -> Result<Self> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::CreateNewTask(send))
            .await
            .with_err("task creation")?;
        let id = reply.await.with_err("task creation")?;

        Ok(Task {
            id,
            sender: self.sender.clone(),
            debug_handle: self.debug_handle.clone(),
        })
    }

    pub async fn req_shutdown(mut self) {
        let _ = self.sender.send(DebuggerMessage::GracefulShutdown).await;
    }

    pub async fn complete(mut self) {
        let (send, reply) = oneshot::channel();
        let _ = self
            .sender
            .send(DebuggerMessage::RemoveTask((self.id, send)))
            .await;
        let _ = reply.await;
    }

    pub fn handle(&self) -> &TraceeHandle {
        &self.debug_handle
    }

    pub async fn cont(&mut self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::Continue((self.id, send)))
            .await
            .with_err("task continue")?;
        Ok(reply.await.with_err("task continue")?)
    }

    pub async fn step(&mut self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::Step((self.id, send)))
            .await
            .with_err("task step")?;
        Ok(reply.await.with_err("task continue")?)
    }

    pub async fn request_control(&mut self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::ReqControl((self.id, send)))
            .await
            .with_err("task req control")?;
        Ok(reply.await.with_err("task req control")?)
    }

    pub async fn interrupt(&mut self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::Interrupt((self.id, send)))
            .await
            .with_err("task interrupt")?;
        reply.await.with_err("task interrupt")??;
        Ok(())
    }

    pub async fn create_hw_bkpt(&mut self) -> Option<TaskBkPt> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::CreateHwBreakpoint((self.id, send)))
            .await
            .ok()?;
        let out = reply.await.unwrap();
        if let Some((bk, channel)) = out {
            Some(TaskBkPt {
                bk_pt: bk,
                sender: self.sender.clone(),
                recv: channel,
            })
        } else {
            None
        }
    }

    pub async fn call_syscall(
        &mut self,
        mut sys_regs: user_regs_struct,
    ) -> Result<user_regs_struct> {
        self.request_control().await?;

        let orig_regs = self.handle().getregs().await?;
        let prev_data = self.handle().read(orig_regs.rip).await?;
        sys_regs.rip = orig_regs.rip;

        self.handle().write(orig_regs.rip, 0x9090050F).await?;
        self.handle().setregs(sys_regs).await?;

        self.handle().raw_step(None).await?;
        self.handle().raw_waitpid(None).await?;

        let new_regs = self.handle().getregs().await?;
        self.handle().setregs(orig_regs).await?;
        self.handle().write(orig_regs.rip, prev_data).await?;

        Ok(new_regs)
    }

    pub async fn call_func(&mut self, mut func_regs: user_regs_struct) -> Result<user_regs_struct> {
        self.request_control().await?;

        let orig_regs = self.handle().getregs().await?;
        let prev_data = self.handle().read(orig_regs.rip).await?;
        func_regs.rip = orig_regs.rip;

        self.handle().write(orig_regs.rip, 0x90ccd0ff).await?;
        self.handle().setregs(func_regs).await?;

        self.handle().raw_cont(None).await?;
        self.handle().raw_waitpid(None).await?;

        let new_regs = self.handle().getregs().await?;
        self.handle().setregs(orig_regs).await?;
        self.handle().write(orig_regs.rip, prev_data).await?;

        Ok(new_regs)
    }

    #[cfg(feature = "mmap")]
    pub async fn call_mmap(
        &mut self,
        addr: Option<NonZeroU64>,
        length: u64,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<u64> {
        let mut regs = self.handle().getregs().await?;
        let addr = addr.map(|x| x.into()).unwrap_or(0);
        let length = length.into();
        let flags = flags | MapFlags::MAP_ANONYMOUS;

        regs.rax = 9;
        regs.rdi = addr;
        regs.rsi = length;
        regs.rdx = prot.bits() as u64;
        regs.r10 = flags.bits() as u64;
        regs.r8 = 0_u64.wrapping_sub(1);
        regs.r9 = 0;

        let out = self.call_syscall(regs).await?;

        Ok(out.rax)
    }
}

pub struct TaskBkPt {
    bk_pt: HardwareBreakpoint,
    sender: mpsc::Sender<DebuggerMessage>,
    recv: mpsc::Receiver<user_regs_struct>,
}

impl TaskBkPt {
    pub fn current(&self) -> HardwareBreakpoint {
        self.bk_pt
    }

    pub async fn modify<F>(&mut self, func: F) -> Result<()>
    where
        F: FnOnce(HardwareBreakpoint) -> HardwareBreakpoint,
    {
        let bp = func(self.bk_pt);
        self.bk_pt = bp;

        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::ModifyHwBreakpoint((bp, send)))
            .await
            .with_err("breakpoint modify")?;
        println!("Send msg");
        Ok(reply.await.with_err("breakpoint modify")?)
    }

    pub async fn delete(&mut self, bp: HardwareBreakpoint) -> Result<()> {
        self.bk_pt = bp;
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::DeleteHwBreakpoint((bp, Some(send))))
            .await
            .with_err("breakpoint delete")?;
        Ok(reply.await.with_err("breakpoint delete")?)
    }

    pub async fn wait_break(&mut self) -> Option<user_regs_struct> {
        self.recv.recv().await.ok()
    }
}

impl Drop for TaskBkPt {
    fn drop(&mut self) {
        let _ = self
            .sender
            .try_send(DebuggerMessage::DeleteHwBreakpoint((self.bk_pt, None)));
    }
}
