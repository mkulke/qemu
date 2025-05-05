use hypervisor::HypervisorVmError;
use mshv_bindings::{SpecialRegisters, StandardRegisters};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MshvOps {
    // c-h vmops impls
    guest_mem_write_fn:
        unsafe extern "C" fn(gpa: u64, *const u8, size: usize, is_secure_mode: bool) -> i32,
    pub guest_mem_read_fn: extern "C" fn(
        gpa: u64,
        *mut u8,
        size: usize,
        is_secure_mode: bool,
        instruction_fetch: bool,
    ) -> i32,
    pio_read_fn: unsafe extern "C" fn(port: u64, data: *mut u8, size: usize, is_secure_mode: bool),
    pio_write_fn:
        unsafe extern "C" fn(port: u64, data: *const u8, size: usize, is_secure_mode: bool) -> i32,

    // qemu ops functions
    pub read_memory_fn: extern "C" fn(i32, u64, u64, u64, *mut u8, usize) -> i32,
    pub write_memory_fn: extern "C" fn(i32, u64, u64, u64, *const u8, usize) -> i32,
    pub set_cpu_state_fn:
        extern "C" fn(i32, *const StandardRegisters, *const SpecialRegisters) -> i32,
    pub get_cpu_state_fn: extern "C" fn(i32, *mut StandardRegisters, *mut SpecialRegisters) -> i32,
    pub translate_gva_fn: extern "C" fn(i32, u64, *mut u64, u64) -> i32,
}

impl hypervisor::VmOps for MshvOps {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> Result<usize, HypervisorVmError> {
        let size = buf.len();
        let ret = unsafe { (self.guest_mem_write_fn)(gpa, buf.as_ptr(), size, false) };
        if ret != 0 {
            Err(HypervisorVmError::GuestMemWrite(anyhow::anyhow!(
                "write {} {:?}",
                gpa,
                buf
            )))
        } else {
            Ok(size)
        }
    }

    fn guest_mem_read(&self, gpa: u64, buf: &mut [u8]) -> Result<usize, HypervisorVmError> {
        let size = buf.len();
        (self.guest_mem_read_fn)(gpa, buf.as_mut_ptr(), size, false, false);
        Ok(size)
    }

    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> Result<(), HypervisorVmError> {
        let size = data.len();
        (self.guest_mem_read_fn)(gpa, data.as_mut_ptr(), size, false, false);
        Ok(())
    }

    fn mmio_write(&self, gpa: u64, data: &[u8]) -> Result<(), HypervisorVmError> {
        let size = data.len();
        unsafe {
            (self.guest_mem_write_fn)(gpa, data.as_ptr(), size, false);
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, port: u64, data: &mut [u8]) -> Result<(), HypervisorVmError> {
        let size = data.len();
        unsafe {
            (self.pio_read_fn)(port, data.as_mut_ptr(), size, false);
        }
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, port: u64, data: &[u8]) -> Result<(), HypervisorVmError> {
        let size = data.len();
        unsafe {
            (self.pio_write_fn)(port, data.as_ptr(), size, false);
        }
        Ok(())
    }
}

