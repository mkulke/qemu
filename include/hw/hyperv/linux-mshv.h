/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interfaces for /dev/mshv* devices and derived fds
 * Includes:
 * - VMM APIs for parent (nested/baremetal root) partition APIs
 * - VMM APIs for VTL0 APIs
 * - Debug and performance metrics APIs
 *
 * This file is divided into sections containing data structures and IOCTLs for
 * a particular set of related devices or derived file descriptors.
 *
 * The IOCTL definitions are at the end of each section. They are grouped by
 * device/fd, so that new IOCTLs can easily be added with a monotonically
 * increasing number.
 */

#ifndef HW_HYPERV_LINUX_MSHV_H
#define HW_HYPERV_LINUX_MSHV_H

#include <linux/types.h>

#define MSHV_IOCTL	0xB8

/**
 * struct mshv_user_mem_region - arguments for MSHV_SET_GUEST_MEMORY
 * @size: Size of the memory region (bytes). Must be aligned to PAGE_SIZE
 * @guest_pfn: Base guest page number to map
 * @userspace_addr: Base address of userspace memory. Must be aligned to
 *                  PAGE_SIZE
 * @flags: Bitmask of 1 << MSHV_SET_MEM_BIT_*. If (1 << MSHV_SET_MEM_BIT_UNMAP)
 *         is set, ignore other bits.
 * @rsvd: MBZ
 *
 * Map or unmap a region of userspace memory to Guest Physical Addresses (GPA).
 * Mappings can't overlap in GPA space or userspace.
 * To unmap, these fields must match an existing mapping.
 */
struct mshv_user_mem_region {
	__u64 size;
	__u64 guest_pfn;
	__u64 userspace_addr;
	__u8 flags;
	__u8 rsvd[7];
};

enum {
	MSHV_SET_MEM_BIT_WRITABLE,
	MSHV_SET_MEM_BIT_EXECUTABLE,
	MSHV_SET_MEM_BIT_UNMAP,
	MSHV_SET_MEM_BIT_COUNT
};
#define MSHV_SET_MEM_FLAGS_MASK ((1 << MSHV_SET_MEM_BIT_COUNT) - 1)

enum {
	MSHV_PT_BIT_LAPIC,
	MSHV_PT_BIT_X2APIC,
	MSHV_PT_BIT_GPA_SUPER_PAGES,
	MSHV_PT_BIT_COUNT,
};
#define MSHV_PT_FLAGS_MASK ((1 << MSHV_PT_BIT_COUNT) - 1)

enum {
	MSHV_PT_ISOLATION_NONE,
	MSHV_PT_ISOLATION_SNP,
	MSHV_PT_ISOLATION_COUNT,
};

enum {
	MSHV_IOEVENTFD_BIT_DATAMATCH,
	MSHV_IOEVENTFD_BIT_PIO,
	MSHV_IOEVENTFD_BIT_DEASSIGN,
	MSHV_IOEVENTFD_BIT_COUNT,
};
#define MSHV_IOEVENTFD_FLAGS_MASK	((1 << MSHV_IOEVENTFD_BIT_COUNT) - 1)

union hv_interrupt_control {
	__u64 as_uint64;
	struct {
		__u32 interrupt_type; /* enum hv_interrupt type */
		__u32 level_triggered : 1;
		__u32 logical_dest_mode : 1;
		__u32 rsvd : 30;
	};
};

struct hv_input_assert_virtual_interrupt {
	__u64 partition_id;
	union hv_interrupt_control control;
	__u64 dest_addr; /* cpu's apic id */
	__u32 vector;
	__u8 target_vtl;
	__u8 rsvd_z0;
	__u16 rsvd_z1;
};

struct mshv_user_ioeventfd {
	__u64 datamatch;
	__u64 addr;	   /* legal pio/mmio address */
	__u32 len;	   /* 1, 2, 4, or 8 bytes    */
	__s32 fd;
	__u32 flags;
	__u8  rsvd[4];
};

struct mshv_user_irq_entry {
	__u32 gsi;
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
};

struct mshv_user_irq_table {
	__u32 nr;
	__u32 rsvd; /* MBZ */
	struct mshv_user_irq_entry entries[0];
};

enum {
	MSHV_IRQFD_BIT_DEASSIGN,
	MSHV_IRQFD_BIT_RESAMPLE,
	MSHV_IRQFD_BIT_COUNT,
};
#define MSHV_IRQFD_FLAGS_MASK	((1 << MSHV_IRQFD_BIT_COUNT) - 1)

struct mshv_user_irqfd {
	__s32 fd;
	__s32 resamplefd;
	__u32 gsi;
	__u32 flags;
};

/**
 * struct mshv_create_partition - arguments for MSHV_CREATE_PARTITION
 * @pt_flags: Bitmask of 1 << MSHV_PT_BIT_*
 * @pt_isolation: MSHV_PT_ISOLATION_*
 *
 * Returns a file descriptor to act as a handle to a guest partition.
 * At this point the partition is not yet initialized in the hypervisor.
 * Some operations must be done with the partition in this state, e.g. setting
 * so-called "early" partition properties. The partition can then be
 * initialized with MSHV_INITIALIZE_PARTITION.
 */
struct mshv_create_partition {
	__u64 pt_flags;
	__u64 pt_isolation;
};

/* /dev/mshv */
#define MSHV_CREATE_PARTITION	_IOW(MSHV_IOCTL, 0x00, struct mshv_create_partition)

/* Partition fds created with MSHV_CREATE_PARTITION */
#define MSHV_INITIALIZE_PARTITION	_IO(MSHV_IOCTL, 0x00)
#define MSHV_SET_GUEST_MEMORY		_IOW(MSHV_IOCTL, 0x02, struct mshv_user_mem_region)
#define MSHV_IRQFD					_IOW(MSHV_IOCTL, 0x03, struct mshv_user_irqfd)
#define MSHV_IOEVENTFD			    _IOW(MSHV_IOCTL, 0x04, struct mshv_user_ioeventfd)
#define MSHV_SET_MSI_ROUTING		_IOW(MSHV_IOCTL, 0x05, struct mshv_user_irq_table)
// TODO: replace with MSHV_ROOT_HVCALL#ASSERT_VIRTUAL_INTERRUPT
#define MSHV_ASSERT_INTERRUPT		_IOW(MSHV_IOCTL, 0xF1, struct mshv_assert_interrupt)

/**
 * struct mshv_root_hvcall - arguments for MSHV_ROOT_HVCALL
 * @code: Hypercall code (HVCALL_*)
 * @reps: in: Rep count ('repcount')
 *	  out: Reps completed ('repcomp'). MBZ unless rep hvcall
 * @in_sz: Size of input incl rep data. <= HV_HYP_PAGE_SIZE
 * @out_sz: Size of output buffer. <= HV_HYP_PAGE_SIZE. MBZ if out_ptr is 0
 * @status: in: MBZ
 *	    out: HV_STATUS_* from hypercall
 * @rsvd: MBZ
 * @in_ptr: Input data buffer (struct hv_input_*). If used with partition or
 *	    vp fd, partition id field is added by kernel.
 * @out_ptr: Output data buffer (optional)
 */
struct mshv_root_hvcall {
	__u16 code;
	__u16 reps;
	__u16 in_sz;
	__u16 out_sz;
	__u16 status;
	__u8 rsvd[6];
	__u64 in_ptr;
	__u64 out_ptr;
};

/* Generic hypercall */
#define MSHV_ROOT_HVCALL		_IOWR(MSHV_IOCTL, 0x07, struct mshv_root_hvcall)

/* From hvgdk_mini.h */

#define HV_X64_MSR_GUEST_OS_ID		0x40000000
#define HV_X64_MSR_SINT0			0x40000090
#define HV_X64_MSR_SINT1			0x40000091
#define HV_X64_MSR_SINT2			0x40000092
#define HV_X64_MSR_SINT3			0x40000093
#define HV_X64_MSR_SINT4			0x40000094
#define HV_X64_MSR_SINT5			0x40000095
#define HV_X64_MSR_SINT6			0x40000096
#define HV_X64_MSR_SINT7			0x40000097
#define HV_X64_MSR_SINT8			0x40000098
#define HV_X64_MSR_SINT9			0x40000099
#define HV_X64_MSR_SINT10			0x4000009A
#define HV_X64_MSR_SINT11			0x4000009B
#define HV_X64_MSR_SINT12			0x4000009C
#define HV_X64_MSR_SINT13			0x4000009D
#define HV_X64_MSR_SINT14			0x4000009E
#define HV_X64_MSR_SINT15			0x4000009F
#define HV_X64_MSR_SCONTROL			0x40000080
#define HV_X64_MSR_SIEFP			0x40000082
#define HV_X64_MSR_SIMP				0x40000083
#define HV_X64_MSR_REFERENCE_TSC	0x40000021
#define HV_X64_MSR_EOM				0x40000084

/* From  github.com/rust-vmm/mshv-bindings/src/x86_64/regs.rs */

#define IA32_MSR_TSC 			0x00000010
#define IA32_MSR_EFER 			0xC0000080
#define IA32_MSR_KERNEL_GS_BASE 0xC0000102
#define IA32_MSR_APIC_BASE 		0x0000001B
#define IA32_MSR_PAT 			0x0277
#define IA32_MSR_SYSENTER_CS 	0x00000174
#define IA32_MSR_SYSENTER_ESP 	0x00000175
#define IA32_MSR_SYSENTER_EIP 	0x00000176
#define IA32_MSR_STAR 			0xC0000081
#define IA32_MSR_LSTAR 			0xC0000082
#define IA32_MSR_CSTAR 			0xC0000083
#define IA32_MSR_SFMASK 		0xC0000084

#define IA32_MSR_MTRR_CAP 		0x00FE
#define IA32_MSR_MTRR_DEF_TYPE 	0x02FF
#define IA32_MSR_MTRR_PHYSBASE0 0x0200
#define IA32_MSR_MTRR_PHYSMASK0 0x0201
#define IA32_MSR_MTRR_PHYSBASE1 0x0202
#define IA32_MSR_MTRR_PHYSMASK1 0x0203
#define IA32_MSR_MTRR_PHYSBASE2 0x0204
#define IA32_MSR_MTRR_PHYSMASK2 0x0205
#define IA32_MSR_MTRR_PHYSBASE3 0x0206
#define IA32_MSR_MTRR_PHYSMASK3 0x0207
#define IA32_MSR_MTRR_PHYSBASE4 0x0208
#define IA32_MSR_MTRR_PHYSMASK4 0x0209
#define IA32_MSR_MTRR_PHYSBASE5 0x020A
#define IA32_MSR_MTRR_PHYSMASK5 0x020B
#define IA32_MSR_MTRR_PHYSBASE6 0x020C
#define IA32_MSR_MTRR_PHYSMASK6 0x020D
#define IA32_MSR_MTRR_PHYSBASE7 0x020E
#define IA32_MSR_MTRR_PHYSMASK7 0x020F

#define IA32_MSR_MTRR_FIX64K_00000 0x0250
#define IA32_MSR_MTRR_FIX16K_80000 0x0258
#define IA32_MSR_MTRR_FIX16K_A0000 0x0259
#define IA32_MSR_MTRR_FIX4K_C0000 0x0268
#define IA32_MSR_MTRR_FIX4K_C8000 0x0269
#define IA32_MSR_MTRR_FIX4K_D0000 0x026A
#define IA32_MSR_MTRR_FIX4K_D8000 0x026B
#define IA32_MSR_MTRR_FIX4K_E0000 0x026C
#define IA32_MSR_MTRR_FIX4K_E8000 0x026D
#define IA32_MSR_MTRR_FIX4K_F0000 0x026E
#define IA32_MSR_MTRR_FIX4K_F8000 0x026F

#define IA32_MSR_TSC_AUX 		  0xC0000103
#define IA32_MSR_BNDCFGS 		  0x00000d90
#define IA32_MSR_DEBUG_CTL 		  0x1D9
#define IA32_MSR_SPEC_CTRL        0x00000048
#define IA32_MSR_TSC_ADJUST 	  0x0000003b

#define IA32_MSR_MISC_ENABLE 0x000001a0

#endif


