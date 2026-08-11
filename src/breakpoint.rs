use std::mem::offset_of;

#[derive(Debug, Clone, Copy)]
pub struct HardwareBreakpoint {
    pub(crate) id: usize,
    pub is_enabled: bool,
    pub loc: i64,
    pub size: HwBreakpointSize,
    pub condition: HwBreakpointCond,
}

impl HardwareBreakpoint {
    pub(crate) fn new(id: usize) -> Self {
        Self {
            id,
            is_enabled: false,
            loc: 0,
            size: Default::default(),
            condition: Default::default(),
        }
    }

    pub fn set_enable(&self, is_enabled: bool) -> HardwareBreakpoint {
        HardwareBreakpoint {
            is_enabled,
            ..*self
        }
    }

    pub fn location(&self, location: i64) -> HardwareBreakpoint {
        HardwareBreakpoint {
            loc: location,
            ..*self
        }
    }

    pub fn size(&self, size: HwBreakpointSize) -> HardwareBreakpoint {
        HardwareBreakpoint { size, ..*self }
    }

    pub fn condition(&self, condition: HwBreakpointCond) -> HardwareBreakpoint {
        HardwareBreakpoint { condition, ..*self }
    }

    pub(crate) fn dx_addr(&self) -> usize {
        let debug_offset = offset_of!(nix::libc::user, u_debugreg);

        debug_offset + self.id * 8
    }

    pub(crate) fn d6_addr() -> usize {
        let debug_offset = offset_of!(nix::libc::user, u_debugreg);
        let d6o = debug_offset + 6 * 8;

        d6o
    }

    pub(crate) fn d7_addr() -> usize {
        let debug_offset = offset_of!(nix::libc::user, u_debugreg);
        let d7o = debug_offset + 7 * 8;

        d7o
    }

    pub(crate) fn d7_set(&self) -> i64 {
        0b01 << (self.id * 2)  // Enable
            | 0b1 << (16 + self.id) // recommended to have this local exact breakpoint
            | self.condition.to_binary() << (16 + self.id * 2)
            | self.size.to_binary() << (18 + self.id * 2)
    }

    pub(crate) fn d7_mask(&self) -> i64 {
        Self::d7_mask_for_id(self.id)
    }

    pub(crate) fn d7_mask_for_id(id: usize) -> i64 {
        0b11 << (id * 2)  // Enable
            | 0b1 << (16 + id) // recommended to have this local exact breakpoint
            | 0b11 << (16 + id * 2)
            | 0b11 << (18 + id * 2)
    }
}

impl HwBreakpointSize {
    pub fn to_binary(&self) -> i64 {
        match self {
            HwBreakpointSize::Bytes1 => 0b00,
            HwBreakpointSize::Bytes2 => 0b01,
            HwBreakpointSize::Bytes4 => 0b11,
            HwBreakpointSize::Bytes8 => 0b10,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum HwBreakpointCond {
    #[default]
    Execute,
    Write,
    Access,
}

impl HwBreakpointCond {
    pub fn to_binary(&self) -> i64 {
        match self {
            HwBreakpointCond::Execute => 0b00,
            HwBreakpointCond::Write => 0b01,
            HwBreakpointCond::Access => 0b11,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum HwBreakpointSize {
    #[default]
    Bytes1,
    Bytes2,
    Bytes4,
    Bytes8,
}
