use crate::vm::MshvOps;
use anyhow::anyhow;
use hypervisor::arch::emulator::{
    PlatformEmulator,
    PlatformError::{
        self, GetCpuStateFailure, MemoryReadFailure, MemoryWriteFailure, SetCpuStateFailure,
        TranslateVirtualAddress,
    },
};
use hypervisor::arch::x86::emulator::{CpuStateManager, EmulatorCpuState};
use iced_x86::Register;
use mshv_bindings::*;
use mshv_bindings::{SpecialRegisters, StandardRegisters};

#[no_mangle]
pub extern "C" fn print_decoded_insn(instruction_ptr: *const u8, instruction_len: usize) {
    let insn_bytes = unsafe { std::slice::from_raw_parts(instruction_ptr, instruction_len) };
    let mut decoder = iced_x86::Decoder::new(64, insn_bytes, iced_x86::DecoderOptions::NONE);
    let mut insn = iced_x86::Instruction::default();
    if decoder.can_decode() {
        decoder.decode_out(&mut insn);
        println!(
            "insn = {}, code = {:?}, op_code ={:#x}",
            insn,
            insn.code(),
            insn.op_code().op_code(),
        );
    }
}

struct Initial {
    gva: u64,
    gpa: u64,
}

pub struct QemuPlatform<'a> {
    cpu_fd: i32,
    initial: Initial,
    ops: &'a MshvOps,
}

impl<'a> QemuPlatform<'a> {
    pub fn new(
        ops: &'a MshvOps,
        cpu_fd: i32,
        initial_gva: u64,
        initial_gpa: u64,
    ) -> QemuPlatform<'a> {
        Self {
            cpu_fd,
            initial: Initial {
                gva: initial_gva,
                gpa: initial_gpa,
            },
            ops,
        }
    }
}

impl<'a> PlatformEmulator for QemuPlatform<'a> {
    type CpuState = EmulatorCpuState;

    fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
        let size = data.len();
        let data = data.as_mut_ptr();
        let i = &self.initial;
        let ret = (self.ops.read_memory_fn)(self.cpu_fd, i.gva, i.gpa, gva, data, size);
        if ret != 0 {
            return Err(MemoryReadFailure(anyhow!("code: {}", ret)));
        }
        Ok(())
    }

    fn fetch(&self, ip: u64, instruction_bytes: &mut [u8]) -> Result<(), PlatformError> {
        let rip_gva = self.cpu_state(0)?.linearize(Register::CS, ip, false)?;

        let flags = HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_EXECUTE;
        let mut gpa = 0;
        let ret = (self.ops.translate_gva_fn)(self.cpu_fd, rip_gva, &mut gpa, flags.into());
        if ret != 0 {
            return Err(TranslateVirtualAddress(anyhow!("code: {}", ret)));
        }
        let size = instruction_bytes.len();

        let ret = (self.ops.guest_mem_read_fn)(
            rip_gva,
            instruction_bytes.as_mut_ptr(),
            size,
            false,
            true,
        );
        if ret != 0 {
            return Err(MemoryReadFailure(anyhow!("code: {}", ret)));
        }
        Ok(())
    }

    fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
        let size = data.len();
        let i = &self.initial;
        let data = data.as_ptr();

        let ret = (self.ops.write_memory_fn)(self.cpu_fd, i.gva, i.gpa, gva, data, size);
        if ret != 0 {
            return Err(MemoryWriteFailure(anyhow!("code: {}", ret)));
        }
        Ok(())
    }

    fn cpu_state(&self, _cpu_id: usize) -> Result<Self::CpuState, PlatformError> {
        let mut regs = StandardRegisters::default();
        let mut sregs = SpecialRegisters::default();
        let ret = (self.ops.get_cpu_state_fn)(self.cpu_fd, &mut regs, &mut sregs);
        if ret != 0 {
            return Err(GetCpuStateFailure(anyhow!("code: {}", ret)));
        }
        let emu_state = EmulatorCpuState {
            regs: regs.into(),
            sregs: sregs.into(),
        };
        Ok(emu_state)
    }

    fn set_cpu_state(&self, _cpu_id: usize, state: Self::CpuState) -> Result<(), PlatformError> {
        let regs: StandardRegisters = state.regs.into();
        let sregs: SpecialRegisters = state.sregs.into();

        let ret = (self.ops.set_cpu_state_fn)(self.cpu_fd, &regs, &sregs);
        if ret != 0 {
            return Err(SetCpuStateFailure(anyhow!("code: {}", ret)));
        }
        Ok(())
    }
}

