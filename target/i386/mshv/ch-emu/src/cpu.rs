use std::panic;

use hypervisor::arch::x86::emulator::Emulator;
use hypervisor::mshv::MshvHypervisor;
use hypervisor::CpuVendor;
use mshv_bindings::{SpecialRegisters, StandardRegisters};

use crate::qemu_platform::QemuPlatform;
use crate::vm::MshvOps;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub enum MshvCpuVendor {
    #[default]
    Unknown,
    Intel,
    AMD,
}

impl From<MshvCpuVendor> for CpuVendor {
    fn from(c: MshvCpuVendor) -> Self {
        match c {
            MshvCpuVendor::Unknown => CpuVendor::Unknown,
            MshvCpuVendor::Intel => CpuVendor::Intel,
            MshvCpuVendor::AMD => CpuVendor::AMD,
        }
    }
}

#[repr(C)]
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

#[repr(C)]
pub struct CpuId {
    entries: *mut CpuIdEntry,
    len: usize,
}

#[no_mangle]
pub extern "C" fn create_cpuid_ch(
    id: u8,
    cpu_vendor: MshvCpuVendor,
    die: u8,
    ncore_per_die: u8,
    thread_per_core: u8,
) -> *mut CpuId {
    let mshv = MshvHypervisor::new().unwrap();
    let phys_bits = arch::get_host_cpu_phys_bits(&mshv);
    let config = arch::CpuidConfig {
        sgx_epc_sections: None,
        phys_bits,
        kvm_hyperv: false,
        amx: false,
    };
    let mut cpuid = arch::generate_common_cpuid(&mshv, &config).unwrap();
    let topology = Some((ncore_per_die, die, thread_per_core));
    arch::x86_64::set_cpuid_mgns(id, &mut cpuid, cpu_vendor.into(), topology);

    let mut cpuid_entries = Vec::new();
    for entry in cpuid.as_slice().iter() {
        cpuid_entries.push(CpuIdEntry {
            function: entry.function,
            index: entry.index,
            flags: entry.flags,
            eax: entry.eax,
            ebx: entry.ebx,
            ecx: entry.ecx,
            edx: entry.edx,
            padding: [0; 3],
        });
    }

    let len = cpuid_entries.len();
    let entries = cpuid_entries.into_boxed_slice();
    let entries = Box::into_raw(entries) as *mut CpuIdEntry;
    Box::into_raw(Box::new(CpuId { entries, len }))
}

#[no_mangle]
pub extern "C" fn emulate_ch(
    cpu_fd: i32,
    initial_gva: u64,
    initial_gpa: u64,
    instruction_ptr: *const u8,
    instruction_len: usize,
    emu_ops: *const MshvOps,
) {
    let ops = unsafe { *emu_ops };

    // Create a new emulator.
    let mut qemu_platform = QemuPlatform::new(&ops, cpu_fd, initial_gva, initial_gpa);
    let mut emul = Emulator::new(&mut qemu_platform);

    // Emulate the trapped instruction, and only the first one.
    // cpu_id is not used in emulator
    let instruction_bytes = unsafe { std::slice::from_raw_parts(instruction_ptr, instruction_len) };
    let new_state = match emul.emulate_first_insn(0, instruction_bytes) {
        Ok(s) => s,
        Err(e) => {
            panic!("{:#?}", e);
        }
    };

    // Set CPU state back.
    let standard_regs: StandardRegisters = new_state.regs.into();
    let special_regs: SpecialRegisters = new_state.sregs.into();

    let ret = (ops.set_cpu_state_fn)(cpu_fd, &standard_regs, &special_regs);
    if ret != 0 {
        panic!("failed to set cpu state. code = {}", ret);
    }
}
