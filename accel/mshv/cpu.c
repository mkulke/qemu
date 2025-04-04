#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/error-report.h"
#include "qemu/memalign.h"
#include "system/mshv.h"
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "emulate/x86_decode.h"
#include "emulate/x86_emu.h"
#include "qemu/atomic.h"
#include "trace-accel_mshv.h"
#include "trace.h"

static QemuMutex *cpu_guards_lock;
static GHashTable *cpu_guards;

/* MTRR constants */
/* IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11 */
static u_int64_t MTRR_ENABLE = 0x800;
static u_int64_t MTRR_MEM_TYPE_WB = 0x6;

/* Defines poached from apicdef.h kernel header. */
static u_int32_t APIC_MODE_NMI = 0x4;
static u_int32_t APIC_MODE_EXTINT = 0x7;

static enum hv_register_name STANDARD_REGISTER_NAMES[18] = {
	HV_X64_REGISTER_RAX,
	HV_X64_REGISTER_RBX,
	HV_X64_REGISTER_RCX,
	HV_X64_REGISTER_RDX,
	HV_X64_REGISTER_RSI,
	HV_X64_REGISTER_RDI,
	HV_X64_REGISTER_RSP,
	HV_X64_REGISTER_RBP,
	HV_X64_REGISTER_R8,
	HV_X64_REGISTER_R9,
	HV_X64_REGISTER_R10,
	HV_X64_REGISTER_R11,
	HV_X64_REGISTER_R12,
	HV_X64_REGISTER_R13,
	HV_X64_REGISTER_R14,
	HV_X64_REGISTER_R15,
	HV_X64_REGISTER_RIP,
	HV_X64_REGISTER_RFLAGS,
};

static enum hv_register_name SPECIAL_REGISTER_NAMES[18] = {
	HV_X64_REGISTER_CS,
	HV_X64_REGISTER_DS,
	HV_X64_REGISTER_ES,
	HV_X64_REGISTER_FS,
	HV_X64_REGISTER_GS,
	HV_X64_REGISTER_SS,
	HV_X64_REGISTER_TR,
	HV_X64_REGISTER_LDTR,
	HV_X64_REGISTER_GDTR,
	HV_X64_REGISTER_IDTR,
	HV_X64_REGISTER_CR0,
	HV_X64_REGISTER_CR2,
	HV_X64_REGISTER_CR3,
	HV_X64_REGISTER_CR4,
	HV_X64_REGISTER_CR8,
	HV_X64_REGISTER_EFER,
	HV_X64_REGISTER_APIC_BASE,
	HV_REGISTER_PENDING_INTERRUPTION,
};

static enum hv_register_name FPU_REGISTER_NAMES[26] = {
	HV_X64_REGISTER_XMM0,
	HV_X64_REGISTER_XMM1,
	HV_X64_REGISTER_XMM2,
	HV_X64_REGISTER_XMM3,
	HV_X64_REGISTER_XMM4,
	HV_X64_REGISTER_XMM5,
	HV_X64_REGISTER_XMM6,
	HV_X64_REGISTER_XMM7,
	HV_X64_REGISTER_XMM8,
	HV_X64_REGISTER_XMM9,
	HV_X64_REGISTER_XMM10,
	HV_X64_REGISTER_XMM11,
	HV_X64_REGISTER_XMM12,
	HV_X64_REGISTER_XMM13,
	HV_X64_REGISTER_XMM14,
	HV_X64_REGISTER_XMM15,
	HV_X64_REGISTER_FP_MMX0,
	HV_X64_REGISTER_FP_MMX1,
	HV_X64_REGISTER_FP_MMX2,
	HV_X64_REGISTER_FP_MMX3,
	HV_X64_REGISTER_FP_MMX4,
	HV_X64_REGISTER_FP_MMX5,
	HV_X64_REGISTER_FP_MMX6,
	HV_X64_REGISTER_FP_MMX7,
	HV_X64_REGISTER_FP_CONTROL_STATUS,
	HV_X64_REGISTER_XMM_CONTROL_STATUS,
};

static int guest_mem_read_with_gva(CPUState *cpu, uint64_t gva, uint8_t *data,
								   uintptr_t size, bool fetch_instruction)
{
	int ret;
	uint64_t gpa, flags;
	int cpu_fd = mshv_vcpufd(cpu);

	flags = HV_TRANSLATE_GVA_VALIDATE_READ;
	ret = translate_gva(cpu_fd, gva, &gpa, flags);
	if (ret < 0) {
		perror("failed to translate gva to gpa");
		return -1;
	}
	ret = guest_mem_read_fn(gpa, data, size, false, fetch_instruction);
	if (ret < 0) {
		perror("failed to read guest memory");
		return -1;
	}
	return 0;
}

static int guest_mem_write_with_gva(CPUState *cpu, uint64_t gva, const uint8_t *data,
									uintptr_t size)
{
	int ret;
	uint64_t gpa, flags;
	int cpu_fd = mshv_vcpufd(cpu);

	flags = HV_TRANSLATE_GVA_VALIDATE_WRITE;
	ret = translate_gva(cpu_fd, gva, &gpa, flags);
	if (ret < 0) {
		perror("failed to translate gva to gpa");
		return -1;
	}
	ret = guest_mem_write_fn(gpa, data, size, false);
	if (ret < 0) {
		perror("failed to write to guest memory");
		return -1;
	}
	return 0;
}


static void write_mem_emu(CPUState *cpu, void *data, target_ulong addr, int bytes)
{
	if (guest_mem_write_with_gva(cpu, addr, data, bytes) < 0) {
		error_report("failed to write memory");
		abort();
	}
}

static void read_mem_emu(CPUState *cpu, void *data, target_ulong addr, int bytes)
{
	if (guest_mem_read_with_gva(cpu, addr, data, bytes, false) < 0) {
		error_report("failed to read memory");
		abort();
	}
}

static void fetch_instruction_emu(CPUState *cpu, void *data, target_ulong addr,
	                           int bytes)
{
	if (guest_mem_read_with_gva(cpu, addr, data, bytes, true) < 0) {
		error_report("failed to fetch instruction");
		abort();
	}
}

static void read_segment_descriptor_emu(CPUState *cpu,
		                                struct x86_segment_descriptor *desc,
										enum X86Seg seg_idx)
{
	bool ret;
	X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;
	SegmentCache *seg = &env->segs[seg_idx];
	x86_segment_selector sel = { .sel = seg->selector & 0xFFFF };

	ret = x86_read_segment_descriptor(cpu, desc, sel);
	if (ret == false) {
		error_report("failed to read segment descriptor");
		abort();
	}
}

static void handle_io_emu(CPUState *cpu, uint16_t port, void *data, int direction,
                          int size, int count)
{
	error_report("handle_io_emu not implemented");
	abort();
}

static void simulate_rdmsr_emu(CPUState *cpu)
{
	error_report("simulate_rdmsr_emu not implemented");
	abort();
}

static void simulate_wrmsr_emu(CPUState *cpu)
{
	error_report("simulate_wrmsr_emu not implemented");
	abort();
}

static const struct x86_emul_ops mshv_x86_emul_ops = {
	.fetch_instruction = fetch_instruction_emu,
	.read_mem = read_mem_emu,
	.write_mem = write_mem_emu,
	.read_segment_descriptor = read_segment_descriptor_emu,
	.handle_io = handle_io_emu,
	.simulate_rdmsr = simulate_rdmsr_emu,
	.simulate_wrmsr = simulate_wrmsr_emu,
};

void mshv_init_cpu_logic(void)
{
	cpu_guards_lock = g_new0(QemuMutex, 1);
	qemu_mutex_init(cpu_guards_lock);
	cpu_guards = g_hash_table_new(g_direct_hash, g_direct_equal);

	init_decoder();
	init_emu(&mshv_x86_emul_ops);
}

static void add_cpu_guard(int cpu_fd)
{
	QemuMutex *guard;

	WITH_QEMU_LOCK_GUARD(cpu_guards_lock) {
		guard = g_new0(QemuMutex, 1);
		qemu_mutex_init(guard);
		g_hash_table_insert(cpu_guards, GUINT_TO_POINTER(cpu_fd), guard);
	}
}

static void remove_cpu_guard(int cpu_fd)
{
	QemuMutex *guard;

	WITH_QEMU_LOCK_GUARD(cpu_guards_lock) {
		guard = g_hash_table_lookup(cpu_guards, GUINT_TO_POINTER(cpu_fd));
		if (guard) {
			qemu_mutex_destroy(guard);
			g_free(guard);
			g_hash_table_remove(cpu_guards, GUINT_TO_POINTER(cpu_fd));
		}
	}
}

int mshv_create_vcpu(int vm_fd, uint8_t vp_index, int *cpu_fd)
{
	int ret;
	struct mshv_create_vp vp_arg = {
		.vp_index = vp_index,
	};
	ret = ioctl(vm_fd, MSHV_CREATE_VP, &vp_arg);
	if (ret < 0) {
		perror("failed to create mshv vcpu");
		return -errno;
	}

	add_cpu_guard(ret);
	*cpu_fd = ret;

	printf("[mgns-qemu] created vcpu %d\n", vp_index);

	return 0;
}

void mshv_remove_vcpu(int vm_fd, int cpu_fd)
{
	remove_cpu_guard(cpu_fd);
	/* TODO: don't we have to perform an ioctl to remove the vcpu?
	 * there is WHvDeleteVirtualProcessor in the WHV api
	 * */
}

static int get_generic_regs_mgns(int cpu_fd,
						         struct hv_register_assoc *assocs,
						         size_t n_regs)
{
	struct mshv_vp_registers input = {
		.count = n_regs,
		.regs = assocs,
	};

	return ioctl(cpu_fd, MSHV_GET_VP_REGISTERS, &input);
}

inline static int set_generic_regs_mgns(int cpu_fd,
										struct hv_register_assoc *assocs,
										size_t n_regs)
{
	struct mshv_vp_registers input = {
		.count = n_regs,
		.regs = assocs,
	};

	return ioctl(cpu_fd, MSHV_SET_VP_REGISTERS, &input);
}

inline static void populate_standard_regs_mgns(const struct hv_register_assoc *assocs,
										       struct StandardRegisters *regs)
{
	regs->rax =	assocs[0].value.reg64;
	regs->rbx =	assocs[1].value.reg64;
	regs->rcx =	assocs[2].value.reg64;
	regs->rdx =	assocs[3].value.reg64;
	regs->rsi =	assocs[4].value.reg64;
	regs->rdi =	assocs[5].value.reg64;
	regs->rsp =	assocs[6].value.reg64;
	regs->rbp =	assocs[7].value.reg64;
	regs->r8  =	assocs[8].value.reg64;
	regs->r9  =	assocs[9].value.reg64;
	regs->r10 =	assocs[10].value.reg64;
	regs->r11 =	assocs[11].value.reg64;
	regs->r12 =	assocs[12].value.reg64;
	regs->r13 =	assocs[13].value.reg64;
	regs->r14 =	assocs[14].value.reg64;
	regs->r15 =	assocs[15].value.reg64;
	regs->rip =	assocs[16].value.reg64;

	regs->rflags = assocs[17].value.reg64;
}

inline static void populate_segment_reg_mgns(const struct hv_x64_segment_register *hv_seg,
							                 struct SegmentRegister *seg)
{
	memset(seg, 0, sizeof(struct SegmentRegister));

	seg->base = hv_seg->base;
	seg->limit = hv_seg->limit;
	seg->selector = hv_seg->selector;
	seg->unusable = 0;
	seg->padding = 0;

	seg->type_ = hv_seg->segment_type;
	seg->present = hv_seg->present;
	seg->dpl = hv_seg->descriptor_privilege_level;
	seg->db = hv_seg->_default;
	seg->s = hv_seg->non_system_segment;
	seg->l = hv_seg->_long;
	seg->g = hv_seg->granularity;
	seg->avl = hv_seg->available;

}

inline static void populate_table_reg_mgns(const struct hv_x64_table_register *hv_seg,
										   struct TableRegister *reg)
{
	memset(reg, 0, sizeof(TableRegister));

	reg->base = hv_seg->base;
	reg->limit = hv_seg->limit;
}

static void populate_interrupt_bitmap_mgns(uint64_t pending_reg,
		                                   uint64_t *bitmap)
{
	uint64_t interrupt_nr;
	/* TODO: early exit */
	/* Check if the least significant bit is 1 (interruption pending) */
	/* and that the trailing zero count (after shifting right by 1) is >= 3. */
	if (((pending_reg & 0x01ULL) == 1ULL)
		&& (__builtin_ctzll(pending_reg >> 1) >= 3)) {
		/* Extract the interrupt number from bits 16 and above. */
        interrupt_nr = pending_reg >> 16;
        if (interrupt_nr > 255) {
			perror("invalid interrupt vector number > 255");
            abort();
        }

        /* Compute the bit offset (lower 6 bits, i.e. 0-63) */
        uint64_t bit_offset = pending_reg & 0x3FULL;
        /* The index is stored in the remaining higher bits (shift right by 6) */
        uint64_t index = pending_reg >> 6;

        /* Set the corresponding bit in the interrupt bitmap. */
        /* (63 - bit_offset) shifts from the left. */
        bitmap[index] = 1ULL << (63 - bit_offset);
	}
}

static void populate_special_regs_mgns(const struct hv_register_assoc *assocs,
									   struct SpecialRegisters *regs)
{
	uint64_t pending_reg;

	populate_segment_reg_mgns(&assocs[0].value.segment, &regs->cs);
	populate_segment_reg_mgns(&assocs[1].value.segment, &regs->ds);
	populate_segment_reg_mgns(&assocs[2].value.segment, &regs->es);
	populate_segment_reg_mgns(&assocs[3].value.segment, &regs->fs);
	populate_segment_reg_mgns(&assocs[4].value.segment, &regs->gs);
	populate_segment_reg_mgns(&assocs[5].value.segment, &regs->ss);
	populate_segment_reg_mgns(&assocs[6].value.segment, &regs->tr);
	populate_segment_reg_mgns(&assocs[7].value.segment, &regs->ldt);

	populate_table_reg_mgns(&assocs[8].value.table, &regs->gdt);
	populate_table_reg_mgns(&assocs[9].value.table, &regs->idt);

	regs->cr0	  	= assocs[10].value.reg64;
	regs->cr2	  	= assocs[11].value.reg64;
	regs->cr3	  	= assocs[12].value.reg64;
	regs->cr4	  	= assocs[13].value.reg64;
	regs->cr8	  	= assocs[14].value.reg64;
	regs->efer 		= assocs[15].value.reg64;
	regs->apic_base = assocs[16].value.reg64;

	pending_reg = assocs[17].value.pending_interruption.as_uint64;
	populate_interrupt_bitmap_mgns(pending_reg, regs->interrupt_bitmap);
}

int mshv_get_standard_regs(int cpu_fd, struct StandardRegisters *regs)
{
	size_t n_regs = sizeof(STANDARD_REGISTER_NAMES) / sizeof(enum hv_register_name);
	struct hv_register_assoc *assocs;
	int ret;

	// TODO: maybe make this global?
	assocs = g_new0(struct hv_register_assoc, n_regs);
	for (size_t i = 0; i < n_regs; i++) {
		assocs[i].name = STANDARD_REGISTER_NAMES[i];
	}
	ret = get_generic_regs_mgns(cpu_fd, assocs, n_regs);
	if (ret < 0) {
		perror("failed to get standard registers");
		g_free(assocs);
		return -errno;
	}

	populate_standard_regs_mgns(assocs, regs);

	g_free(assocs);
	return 0;
}

int set_standard_regs_mgns(int cpu_fd, const struct StandardRegisters *regs)
{
	struct hv_register_assoc *assocs;
	size_t n_regs = sizeof(STANDARD_REGISTER_NAMES) / sizeof(enum hv_register_name);
	int ret;

	assocs = g_new0(struct hv_register_assoc, n_regs);

	/* set names */
	for (size_t i = 0; i < n_regs; i++) {
		assocs[i].name = STANDARD_REGISTER_NAMES[i];
	}
	assocs[0].value.reg64 = regs->rax;
	assocs[1].value.reg64 = regs->rbx;
	assocs[2].value.reg64 = regs->rcx;
	assocs[3].value.reg64 = regs->rdx;
	assocs[4].value.reg64 = regs->rsi;
	assocs[5].value.reg64 = regs->rdi;
	assocs[6].value.reg64 = regs->rsp;
	assocs[7].value.reg64 = regs->rbp;
	assocs[8].value.reg64 = regs->r8;
	assocs[9].value.reg64 = regs->r9;
	assocs[10].value.reg64 = regs->r10;
	assocs[11].value.reg64 = regs->r11;
	assocs[12].value.reg64 = regs->r12;
	assocs[13].value.reg64 = regs->r13;
	assocs[14].value.reg64 = regs->r14;
	assocs[15].value.reg64 = regs->r15;
	assocs[16].value.reg64 = regs->rip;
	assocs[17].value.reg64 = regs->rflags;

	ret = set_generic_regs_mgns(cpu_fd, assocs, n_regs);
	g_free(assocs);
	if (ret < 0) {
		perror("failed to set standard registers");
		return -errno;
	}
	return 0;
}

int mshv_get_special_regs(int cpu_fd, struct SpecialRegisters *regs)
{
	size_t n_regs = sizeof(SPECIAL_REGISTER_NAMES) / sizeof(enum hv_register_name);
	struct hv_register_assoc *assocs;
	int ret;

	assocs = g_new0(struct hv_register_assoc, n_regs);
	for (size_t i = 0; i < n_regs; i++) {
		assocs[i].name = SPECIAL_REGISTER_NAMES[i];
	}
	ret = get_generic_regs_mgns(cpu_fd, assocs, n_regs);
	if (ret < 0) {
		perror("failed to get special registers");
		g_free(assocs);
		return -errno;
	}

	populate_special_regs_mgns(assocs, regs);

	g_free(assocs);
	return 0;
}

static void populate_hv_segment_reg_mgns(const struct SegmentRegister *reg,
								   	     struct hv_x64_segment_register *hv_reg)
{
	hv_reg->base = reg->base;
	hv_reg->limit = reg->limit;
	hv_reg->selector = reg->selector;

	hv_reg->segment_type = reg->type_ & 0xF;
	hv_reg->non_system_segment = reg->s & 0x1;
	hv_reg->descriptor_privilege_level = reg->dpl & 0x3;
	hv_reg->present = reg->present & 0x1;
	hv_reg->reserved = 0;
	hv_reg->available = reg->avl & 0x1;
	hv_reg->_long = reg->l & 0x1;
	hv_reg->_default = reg->db & 0x1;
	hv_reg->granularity = reg->g & 0x1;
}

static void populate_hv_table_reg_mgns(const struct TableRegister *reg,
 							   	       struct hv_x64_table_register *hv_reg)
{
	hv_reg->base = reg->base;
	hv_reg->limit = reg->limit;
	memset(hv_reg->pad, 0, sizeof(hv_reg->pad));
}

static int set_special_regs_mgns(int cpu_fd, const struct SpecialRegisters *regs)
{
	struct hv_register_assoc *assocs;
	uint64_t bits;
	size_t n_regs = sizeof(SPECIAL_REGISTER_NAMES) / sizeof(enum hv_register_name);
	int ret;

	assocs = g_new0(struct hv_register_assoc, n_regs);

	/* set names */
	for (size_t i = 0; i < n_regs; i++) {
		assocs[i].name = SPECIAL_REGISTER_NAMES[i];
	}
	populate_hv_segment_reg_mgns(&regs->cs, &assocs[0].value.segment);
	populate_hv_segment_reg_mgns(&regs->ds, &assocs[1].value.segment);
	populate_hv_segment_reg_mgns(&regs->es, &assocs[2].value.segment);
	populate_hv_segment_reg_mgns(&regs->fs, &assocs[3].value.segment);
	populate_hv_segment_reg_mgns(&regs->gs, &assocs[4].value.segment);
	populate_hv_segment_reg_mgns(&regs->ss, &assocs[5].value.segment);
	populate_hv_segment_reg_mgns(&regs->tr, &assocs[6].value.segment);
	populate_hv_segment_reg_mgns(&regs->ldt, &assocs[7].value.segment);

	populate_hv_table_reg_mgns(&regs->gdt, &assocs[8].value.table);
	populate_hv_table_reg_mgns(&regs->idt, &assocs[9].value.table);

	assocs[10].value.reg64 = regs->cr0;
	assocs[11].value.reg64 = regs->cr2;
	assocs[12].value.reg64 = regs->cr3;
	assocs[13].value.reg64 = regs->cr4;
	assocs[14].value.reg64 = regs->cr8;
	assocs[15].value.reg64 = regs->efer;
	assocs[16].value.reg64 = regs->apic_base;

	/* TODO: support asserting an interrupt using interrup_bitmap
	 * it should be possible if we use the vm_fd
	 */
	for (size_t i = 0; i < 4; i++) {
		bits = regs->interrupt_bitmap[i];
		if (bits) {
			perror("asserting an interrupt is not supported");
			return -EINVAL;
		}
	}

	ret = set_generic_regs_mgns(cpu_fd, assocs, n_regs);
	g_free(assocs);
	if (ret < 0) {
		perror("failed to set special registers");
		return -errno;
	}
	return 0;
}

inline static void populate_fpu_regs_mgns(struct hv_register_assoc *assocs,
										  struct FloatingPointUnit *fpu)
{
	union hv_x64_fp_control_status_register fp_control_status;
	union hv_x64_xmm_control_status_register xmm_control_status;
	struct hv_register_assoc *assoc;
	uint8_t (*xmm)[16];
	size_t fp_i;
	uint8_t (*fpr)[16];

	fp_control_status = assocs[24].value.fp_control_status;
	xmm_control_status = assocs[25].value.xmm_control_status;

	memset(fpu->fpr, 0, sizeof(fpu->fpr));
	fpu->fcw = fp_control_status.fp_control;
	fpu->fsw = fp_control_status.fp_status;
	fpu->ftwx = fp_control_status.fp_tag;
	fpu->pad1 = 0;
	fpu->last_opcode = fp_control_status.last_fp_op;
	fpu->last_ip = fp_control_status.last_fp_rip;
	fpu->last_dp = xmm_control_status.last_fp_rdp;
	memset(fpu->xmm, 0, sizeof(fpu->xmm));
	fpu->mxcsr = xmm_control_status.xmm_status_control;
	fpu->pad2 = 0;

	/* First 16 registers are xmm0-xmm15 */
	for (size_t i = 0; i < 16; i++) {
		assoc = &assocs[i];
		/* Copy 16 bytes from assoc to xmm[i] */
		xmm = &fpu->xmm[i];
		memcpy(xmm, &assoc->value.reg128, 16);
	}

	/* Next 8 registers are fp_mmx0-fp_mmx7 */
	for (size_t i = 16; i < 24; i++) {
		assoc = &assocs[i];
		fp_i = (i - 16);
		/* Copy 16 bytes from assoc to fpr[fp_i] */
		fpr = &fpu->fpr[fp_i];
		memcpy(fpr, &assoc->value.reg128, 16);
	}
}

static int set_fpu_regs_mgns(int cpu_fd, const struct FloatingPointUnit *regs)
{
	struct hv_register_assoc *assocs;
	union hv_register_value *value;
	size_t n_regs = sizeof(FPU_REGISTER_NAMES) / sizeof(enum hv_register_name);
	size_t fp_i;
	union hv_x64_fp_control_status_register *ctrl_status;
	union hv_x64_xmm_control_status_register *xmm_ctrl_status;
	int ret;

	assocs = g_new0(struct hv_register_assoc, n_regs);

	/* first 16 registers are xmm0-xmm15 */
	for (size_t i = 0; i < 16; i++) {
		assocs[i].name = FPU_REGISTER_NAMES[i];
		value = &assocs[i].value;
		memcpy(&value->reg128, &regs->xmm[i], 16);
	}

	/* next 8 registers are fp_mmx0-fp_mmx7 */
	for (size_t i = 16; i < 24; i++) {
		assocs[i].name = FPU_REGISTER_NAMES[i];
		fp_i = (i - 16);
		value = &assocs[i].value;
		memcpy(&value->reg128, &regs->fpr[fp_i], 16);
	}

	/* last two registers are fp_control_status and xmm_control_status */
	assocs[24].name = FPU_REGISTER_NAMES[24];
	value = &assocs[24].value;
	ctrl_status = &value->fp_control_status;
	ctrl_status->fp_control = regs->fcw;
	ctrl_status->fp_status = regs->fsw;
	ctrl_status->fp_tag = regs->ftwx;
	ctrl_status->reserved = 0;
	ctrl_status->last_fp_op = regs->last_opcode;
	ctrl_status->last_fp_rip = regs->last_ip;

	assocs[25].name = FPU_REGISTER_NAMES[25];
	value = &assocs[25].value;
	xmm_ctrl_status = &value->xmm_control_status;
	xmm_ctrl_status->xmm_status_control = regs->mxcsr;
	xmm_ctrl_status->xmm_status_control_mask = 0;
	xmm_ctrl_status->last_fp_rdp = regs->last_dp;

	ret = set_generic_regs_mgns(cpu_fd, assocs, n_regs);
	g_free(assocs);
	if (ret < 0) {
		perror("failed to set fpu registers");
		return -errno;
	}
	return 0;
}

static int set_xc_reg_mgns(int cpu_fd, uint64_t xcr0)
{
	int ret;
	struct hv_register_assoc assoc = {
		.name = HV_X64_REGISTER_XFEM,
		.value.reg64 = xcr0,
	};

	ret = set_generic_regs_mgns(cpu_fd, &assoc, 1);
	if (ret < 0) {
		perror("failed to set xcr");
		return -errno;
	}
	return 0;
}

static int set_cpu_state(int cpu_fd,
						 const struct StandardRegisters *standard_regs,
						 const struct SpecialRegisters *special_regs,
						 const struct FloatingPointUnit *fpu_regs,
						 uint64_t xcr0)
{
	int ret;

	ret = set_standard_regs_mgns(cpu_fd, standard_regs);
	if (ret < 0) {
		return ret;
	}
	ret = set_special_regs_mgns(cpu_fd, special_regs);
	if (ret < 0) {
		return ret;
	}
	ret = set_fpu_regs_mgns(cpu_fd, fpu_regs);
	if (ret < 0) {
		return ret;
	}
	ret = set_xc_reg_mgns(cpu_fd, xcr0);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

static int register_intercept_result_cpuid_entry(int cpu_fd,
												 uint8_t subleaf_specific,
												 uint8_t always_override,
												 struct hv_cpuid_entry *entry)
{
	struct hv_register_x64_cpuid_result_parameters cpuid_params = {
		.input.eax = entry->function,
		.input.ecx = entry->index,
		.input.subleaf_specific = subleaf_specific,
		.input.always_override = always_override,
		.input.padding = 0,
		/* With regard to masks - these are to specify bits to be overwritten. */
		/* The current CpuidEntry structure wouldn't allow to carry the masks */
		/* in addition to the actual register values. For this reason, the */
		/* masks are set to the exact values of the corresponding register bits */
		/* to be registered for an overwrite. To view resulting values the */
		/* hypervisor would return, HvCallGetVpCpuidValues hypercall can be used. */
		.result.eax = entry->eax,
		.result.eax_mask = entry->eax,
		.result.ebx = entry->ebx,
		.result.ebx_mask = entry->ebx,
		.result.ecx = entry->ecx,
		.result.ecx_mask = entry->ecx,
		.result.edx = entry->edx,
		.result.edx_mask = entry->edx,
	};
 	union hv_register_intercept_result_parameters parameters = {
		.cpuid = cpuid_params,
	};
	struct mshv_register_intercept_result args = {
		.intercept_type = HV_INTERCEPT_TYPE_X64_CPUID,
		.parameters = parameters,
	};
	int ret;

	ret = ioctl(cpu_fd, MSHV_VP_REGISTER_INTERCEPT_RESULT, &args);
	if (ret < 0) {
		perror("failed to register intercept result for cpuid");
		return -errno;
	}

	return 0;
}

static int register_intercept_result_cpuid(int cpu_fd, struct hv_cpuid *cpuid)
{
	int ret = 0, entry_ret;
	struct hv_cpuid_entry *entry;
	uint8_t subleaf_specific, always_override;

	for (size_t i = 0; i < cpuid->nent; i++) {
		entry = &cpuid->entries[i];

		/* set defaults */
		subleaf_specific = 0;
		always_override = 1;

		/* Intel */
		/* 0xb - Extended Topology Enumeration Leaf */
		/* 0x1f - V2 Extended Topology Enumeration Leaf */
		/* AMD */
		/* 0x8000_001e - Processor Topology Information */
		/* 0x8000_0026 - Extended CPU Topology */
		if (entry->function == 0xb
			|| entry->function == 0x1f
			|| entry->function == 0x8000001e
			|| entry->function == 0x80000026) {
			subleaf_specific = 1;
			always_override = 1;
		}
		else if (entry->function == 0x00000001
		    || entry->function == 0x80000000
		    || entry->function == 0x80000001
		    || entry->function == 0x80000008) {
			subleaf_specific = 0;
			always_override = 1;
		}

		entry_ret = register_intercept_result_cpuid_entry(cpu_fd,
														  subleaf_specific,
														  always_override,
														  entry);
		if ((entry_ret < 0) && (ret == 0)) {
			ret = entry_ret;
		}
	}

	return ret;
}
static void add_cpuid_entry(GList *cpuid_entries,
							uint32_t function, uint32_t index,
							uint32_t eax, uint32_t ebx,
							uint32_t ecx, uint32_t edx)
{
	struct hv_cpuid_entry *entry;

	entry = g_malloc0(sizeof(struct hv_cpuid_entry));
	entry->function = function;
	entry->index = index;
	entry->eax = eax;
	entry->ebx = ebx;
	entry->ecx = ecx;
	entry->edx = edx;

	cpuid_entries = g_list_append(cpuid_entries, entry);
}

static void collect_cpuid_entries(CPUState *cpu, GList *cpuid_entries)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    uint32_t eax, ebx, ecx, edx;
    uint32_t leaf, subleaf;
	const size_t max_leaf = 0x1F;
	const size_t max_subleaf = 0x20;

    // Example leaves to iterate through
    const uint32_t leaves_with_subleaves[] = {0x4, 0x7, 0xD, 0xF, 0x10};
    const int num_subleaf_leaves = sizeof(leaves_with_subleaves)/sizeof(leaves_with_subleaves[0]);

    // Regular leaves without subleaves
    for (leaf = 0; leaf <= max_leaf; leaf++) {
        bool has_subleaves = false;
        for (int i = 0; i < num_subleaf_leaves; i++) {
            if (leaf == leaves_with_subleaves[i]) {
                has_subleaves = true;
                break;
            }
        }

        if (!has_subleaves) {
            cpu_x86_cpuid(env, leaf, 0, &eax, &ebx, &ecx, &edx);
            if (eax == 0 && ebx == 0 && ecx == 0 && edx == 0) {
				/* all zeroes indicates no more leaves */
                continue;
			}

			add_cpuid_entry(cpuid_entries, leaf, 0, eax, ebx, ecx, edx);
            continue;
        }

        subleaf = 0;
        while (subleaf < max_subleaf) {
            cpu_x86_cpuid(env, leaf, subleaf, &eax, &ebx, &ecx, &edx);

            if (eax == 0 && ebx == 0 && ecx == 0 && edx == 0) {
				/* all zeroes indicates no more leaves */
                break;
			}
			add_cpuid_entry(cpuid_entries, leaf, 0, eax, ebx, ecx, edx);
        }
    }
}

/* cstatic int set_cpuid2(int cpu_fd, struct hv_cpuid *cpuid) */
static int set_cpuid2(CPUState *cpu)
{
	int ret;
	size_t n_entries, cpuid_size;
	struct hv_cpuid *cpuid;
	struct hv_cpuid_entry *entry;
	GList *entries = NULL;
	int cpu_fd = mshv_vcpufd(cpu);

	collect_cpuid_entries(cpu, entries);
	n_entries = g_list_length(entries);

    cpuid_size = sizeof(struct hv_cpuid)
		+ n_entries * sizeof(struct hv_cpuid_entry);

	cpuid = g_malloc0(cpuid_size);
	cpuid->nent = n_entries;
	cpuid->padding = 0;

	for (size_t i = 0; i < n_entries; i++) {
		entry = g_list_nth_data(entries, i);
		cpuid->entries[i] = *entry;
		g_free(entry);
	}
	g_list_free(entries);

	ret = register_intercept_result_cpuid(cpu_fd, cpuid);
	g_free(cpuid);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int set_msrs_mgns(int cpu_fd, GList *msrs)
{
	size_t n_msrs;
	GList *entries;
	msr_entry *entry;
	enum hv_register_name name;
	struct hv_register_assoc *assoc;
	int ret;
	size_t i = 0;

	n_msrs = g_list_length(msrs);
	struct hv_register_assoc *assocs = g_new0(struct hv_register_assoc, n_msrs);

	entries = msrs;
	for(GList* elem = entries; elem != NULL; elem = elem->next) {
		entry = elem->data;
		ret = msr_to_hv_reg_name_mgns(entry->index, &name);
		if (ret < 0) {
			g_free(assocs);
			return ret;
		}
		assoc = &assocs[i];
		assoc->name = name;
		/* the union has be initialized to 0 */
		assoc->value.reg64 = entry->data;
		i++;
	}
	ret = set_generic_regs_mgns(cpu_fd, assocs, n_msrs);
	g_free(assocs);
	if (ret < 0) {
		perror("failed to set msrs");
		return -errno;
	}
	return 0;
}

int configure_msr_mgns(int cpu_fd, msr_entry *msrs, size_t n_msrs)
{
	GList *valid_msrs = NULL;
	uint32_t msr_index;
	int ret;

	for (size_t i = 0; i < n_msrs; i++) {
		msr_index = msrs[i].index;
		/* check whether index of msrs is in SUPPORTED_MSRS */
		if (is_supported_msr_mgns(msr_index)) {
			valid_msrs = g_list_append(valid_msrs, &msrs[i]);
		}
	}

	ret = set_msrs_mgns(cpu_fd, valid_msrs);
	g_list_free(valid_msrs);
	return ret;
}

static int setup_msrs_mgns(int cpu_fd)
{
	int ret;
	uint64_t default_type = MTRR_ENABLE | MTRR_MEM_TYPE_WB;

	/* boot msr entries */
    struct msr_entry msrs[9] = {
		{ .index = IA32_MSR_SYSENTER_CS, .data = 0x0, },
		{ .index = IA32_MSR_SYSENTER_ESP, .data = 0x0, },
		{ .index = IA32_MSR_SYSENTER_EIP, .data = 0x0, },
		{ .index = IA32_MSR_STAR, .data = 0x0, },
		{ .index = IA32_MSR_CSTAR, .data = 0x0, },
		{ .index = IA32_MSR_LSTAR, .data = 0x0, },
		{ .index = IA32_MSR_KERNEL_GS_BASE, .data = 0x0, },
		{ .index = IA32_MSR_SFMASK, .data = 0x0, },
		{ .index = IA32_MSR_MTRR_DEF_TYPE, .data = default_type, },
	};

	ret = configure_msr_mgns(cpu_fd, msrs, 9);
	if (ret < 0) {
		perror("failed to setup msrs");
		return ret;
	}

	printf("[mgns-qemu] setup_msrs_mgns() done\n");

	return 0;
}

static int get_vp_state_mgns(int cpu_fd,
		                     struct mshv_get_set_vp_state *state)
{
	int ret;

	ret = ioctl(cpu_fd, MSHV_GET_VP_STATE, state);
	if (ret < 0) {
		perror("failed to get vp state");
		return -errno;
	}

	return 0;
}

static int set_vp_state_mgns(int cpu_fd,
		                     struct mshv_get_set_vp_state *state)
{
	int ret;

	ret = ioctl(cpu_fd, MSHV_SET_VP_STATE, state);
	if (ret < 0) {
		perror("failed to set vp state");
		return -errno;
	}

	return 0;
}

static int get_lapic(int cpu_fd, struct hv_local_interrupt_controller_state *lapic_state)
{
	int ret;
	size_t size = 4096;
	/* buffer aligned to 4k, as *state requires that */
	void *buffer = qemu_memalign(size, size);
	struct mshv_get_set_vp_state state = { 0 };

	state.buf_ptr = (uint64_t) buffer;
	state.buf_sz = size;
	state.type = MSHV_VP_STATE_LAPIC;

	ret = get_vp_state_mgns(cpu_fd, &state);
	if (ret == 0) {
		memcpy(lapic_state, buffer, sizeof(*lapic_state));
	}
	qemu_vfree(buffer);
	if (ret < 0) {
		perror("failed to get lapic");
		return ret;
	}

	return 0;
}

static int set_lapic(int cpu_fd, struct hv_local_interrupt_controller_state *lapic_state)
{

	int ret;
	size_t size = 4096;
	/* buffer aligned to 4k, as *state requires that */
	void *buffer = qemu_memalign(size, size);
	struct mshv_get_set_vp_state state = { 0 };

	assert(lapic_state);
	memcpy(lapic_state, buffer, sizeof(*lapic_state));

	state.buf_ptr = (uint64_t) buffer;
	state.buf_sz = size;
	state.type = MSHV_VP_STATE_LAPIC;

	ret = set_vp_state_mgns(cpu_fd, &state);
	qemu_vfree(buffer);
	if (ret < 0) {
		perror("failed to set lapic");
		return ret;
	}

	return 0;
}

static uint32_t set_apic_delivery_mode(uint32_t reg, uint32_t mode)
{
	return ((reg) & ~0x700) | ((mode) << 8);
}

static int set_lint_mgns(int cpu_fd)
{
	int ret;
	uint32_t *lvt_lint0, *lvt_lint1;

	struct hv_local_interrupt_controller_state lapic_state = { 0 };
	ret = get_lapic(cpu_fd, &lapic_state);
	if (ret < 0) {
		return ret;
	}


	lvt_lint0 = &lapic_state.apic_lvt_lint0;
	printf("[mgns-qemu] set_lint() lapic.APIC_LVT0 before: %x\n", *lvt_lint0);
	*lvt_lint0 = set_apic_delivery_mode(*lvt_lint0, APIC_MODE_EXTINT);
	printf("                                       after:  %x\n", *lvt_lint0);

	lvt_lint1 = &lapic_state.apic_lvt_lint1;
	printf("[mgns-qemu] set_lint() lapic.APIC_LVT1 before: %x\n", *lvt_lint1);
	*lvt_lint1 = set_apic_delivery_mode(*lvt_lint1, APIC_MODE_NMI);
	printf("                                       after:  %x\n", *lvt_lint1);

	/* TODO: should we skip setting lapic if the values are the same? */

	ret = set_lapic(cpu_fd, &lapic_state);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* TODO: consolidate arguments */
/* TODO: populate topology info */
int mshv_configure_vcpu(CPUState *cpu,
						int cpu_fd,
						uint8_t id,
						uint8_t ndies,
						uint8_t ncores_per_die,
						uint8_t nthreads_per_core,
						struct StandardRegisters *standard_regs,
						struct SpecialRegisters *special_regs,
						uint64_t xcr0,
						struct FloatingPointUnit *fpu_regs)
{
	int ret;

	ret = set_cpuid2(cpu);
	if (ret < 0) {
		perror("failed to set cpuid");
		return ret;
	}

	ret = setup_msrs_mgns(cpu_fd);
	if (ret < 0) {
		perror("failed to setup msrs");
		return ret;
	}

	/* TODO: mshv-c is setting lint twice, after setting msrs
	 * should we do the same? */

	ret = set_cpu_state(cpu_fd,
						standard_regs,
						special_regs,
						fpu_regs,
						xcr0);
	if (ret < 0) {
		perror("failed to set vcpu registers");
		return ret;
	}

	ret = set_lint_mgns(cpu_fd);
	if (ret < 0) {
		perror("failed to set lpic int");
		return ret;
	}

	return 0;
}

int set_x64_registers_mgns(int cpu_fd, const struct X64Registers *regs)
{
	size_t n_regs = regs->count;
	struct hv_register_assoc *assocs;

	assocs = g_new0(struct hv_register_assoc, n_regs);
	for (size_t i = 0; i < n_regs; i++) {
		assocs[i].name = regs->names[i];
		assocs[i].value.reg64 = regs->values[i];
	}
	int ret;

	ret = set_generic_regs_mgns(cpu_fd, assocs, n_regs);
	g_free(assocs);
	if (ret < 0) {
		perror("failed to set X64 registers");
		return -errno;
	}
	return 0;
}

static int set_memory_info(const struct hyperv_message *msg,
		                   struct hv_x64_memory_intercept_message *info)
{
	if (msg->header.message_type != HVMSG_GPA_INTERCEPT
			&& msg->header.message_type != HVMSG_UNMAPPED_GPA
			&& msg->header.message_type != HVMSG_UNACCEPTED_GPA) {
		perror("invalid message type");
		return -1;
	}
	// copy the content of the message to info
	memcpy(info, msg->payload, sizeof(*info));
	return 0;
}

static int read_memory_mgns(int cpu_fd,
							uint64_t initial_gva,
							uint64_t initial_gpa,
		                    uint64_t gva,
		                    uint8_t *data,
		                    size_t len)
{
	int ret;
	uint64_t gpa, flags;

	if (gva == initial_gva) {
		gpa = initial_gpa;
	} else {
	    flags = HV_TRANSLATE_GVA_VALIDATE_READ;
		ret = translate_gva(cpu_fd, gva, &gpa, flags);
		if (ret < 0) {
			perror("failed to translate gva to gpa");
			return -1;
		}

		/* TODO: it's unfortunate that this fn doesn't fail
		 * the rust code has a code path for failed reads at this point,
		 * but it's dead code */
		guest_mem_read_fn(gpa, data, len, false, false);
	}

	return 0;
}

int translate_gva(int cpu_fd, uint64_t gva, uint64_t *gpa, uint64_t flags)
{
	int ret;
	union hv_translate_gva_result result = { 0 };

	*gpa = 0;
	struct mshv_translate_gva args = {
		.gva = gva,
		.flags = flags,
		.gpa = (__u64 *)gpa,
		.result = &result,
	};

	ret = ioctl(cpu_fd, MSHV_TRANSLATE_GVA, &args);
	if (ret < 0) {
		perror("failed to invoke gva translation");
		return -errno;
	}
	if (result.result_code != HV_TRANSLATE_GVA_SUCCESS) {
		error_report("failed to translate gva (" TARGET_FMT_lx ") to gpa", gva);
		return -1;

	}

	return 0;
}

static int write_memory_mgns(int cpu_fd,
							 uint64_t initial_gva,
							 uint64_t initial_gpa,
							 uint64_t gva,
							 const uint8_t *data,
							 size_t len)
{
	int ret;
	uint64_t gpa, flags;

	if (gva == initial_gva) {
		gpa = initial_gpa;
	} else {
	    flags = HV_TRANSLATE_GVA_VALIDATE_WRITE;
		ret = translate_gva(cpu_fd, gva, &gpa, flags);
		if (ret < 0) {
			perror("failed to translate gva to gpa");
			return -1;
		}
	}
	ret = guest_mem_write_fn(gpa, data, len, false);
	if (ret != MEMTX_OK) {
		perror("failed to write to mmio");
		return -1;
	}

	return 0;
}

static int emulate_insn(CPUState *cpu,
						uint8_t *insn_bytes, size_t insn_len,
						uint64_t gva, uint64_t gpa)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	struct x86_decode decode = { 0 };
	int ret;
	int cpu_fd = mshv_vcpufd(cpu);
	QemuMutex *guard;

	/* TODO: use initial gva and gpa */
	/* TODO: use instruction_bytes for emu */

	guard = g_hash_table_lookup(cpu_guards, GUINT_TO_POINTER(cpu_fd));
	if (!guard) {
		error_report("failed to get cpu guard");
		return -1;
	}

	WITH_QEMU_LOCK_GUARD(guard) {
		ret = mshv_load_regs(cpu_fd, cpu);
		if (ret < 0) {
			error_report("failed to load registers");
			return -1;
		}

		decode_instruction(env, &decode);
		exec_instruction(env, &decode);

		ret = mshv_store_regs(cpu_fd, cpu);
		if (ret < 0) {
			error_report("failed to store registers");
			return -1;
		}
	}

	return 0;
}

static int handle_mmio(CPUState *cpu, const struct hyperv_message *msg,
					   enum VmExitMgns *exit_reason)
{
	struct hv_x64_memory_intercept_message info = { 0 };
	size_t insn_len;
	uint8_t access_type;
	uint8_t *instruction_bytes;
	int ret;

	ret = set_memory_info(msg, &info);
	if (ret < 0) {
		perror("failed to convert message to memory info");
		/* TODO: rather return? */
		abort();
	}
	insn_len = info.instruction_byte_count;
	access_type = info.header.intercept_access_type;

	if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE) {
		perror("invalid intercept access type: execute");
		abort();
	}

	if (insn_len <= 0 || insn_len > 16) {
		perror("invalid instruction length");
		abort();
	}

	/* TODO: insn_len != 16 is x-page access, do we handle it properly? */

	instruction_bytes = info.instruction_bytes;

	ret = emulate_insn(cpu,
					   instruction_bytes, insn_len,
					   info.guest_virtual_address, info.guest_physical_address);
	if (ret < 0) {
		error_report("failed to emulate mmio");
		return -1;
	}

	*exit_reason = VmExitIgnore;

	return 0;
}

static int handle_unmapped_mem(int vm_fd, CPUState *cpu,
							   const struct hyperv_message *msg,
							   enum VmExitMgns *exit_reason)
{
	struct hv_x64_memory_intercept_message info = { 0 };
	uint64_t gpa;
	int ret;
	bool found;

	ret = set_memory_info(msg, &info);
	if (ret < 0) {
		perror("failed to convert message to memory info");
		return -1;
	}
	gpa = info.guest_physical_address;

    found = find_entry_idx_by_gpa_mgns(gpa, NULL);
	if (!found) {
		return handle_mmio(cpu, msg, exit_reason);
	}

	ret = map_overlapped_region_mgns(vm_fd, gpa);
	if (ret < 0) {
		*exit_reason = VmExitSpecial;
	} else {
		*exit_reason = VmExitIgnore;
	}

	return 0;
}

static int handle_pio_str(CPUState *cpu,
						  struct hv_x64_io_port_intercept_message *info) {
	size_t len = info->access_info.access_size;
	uint8_t access_type = info->header.intercept_access_type;
	uint16_t port = info->port_number;
	bool repop = info->access_info.rep_prefix == 1;
	size_t repeat = repop ? info->rcx : 1;
	size_t insn_len = info->header.instruction_length;
	uint8_t data[4] = { 0 };
	struct StandardRegisters standard_regs = { 0 };
	struct SpecialRegisters special_regs = { 0 };
	bool direction_flag;
	uint32_t reg_names[3];
	uint64_t reg_values[3];
	int ret;
	uint64_t src, dst, rip, rax, rsi, rdi;
	struct X64Registers x64_regs = { 0 };
	int cpu_fd = mshv_vcpufd(cpu);

	ret = mshv_get_standard_regs(cpu_fd, &standard_regs);
	if (ret < 0) {
		error_report("failed to get standard registers");
		return -1;
	}
	ret = mshv_get_special_regs(cpu_fd, &special_regs);
	if (ret < 0) {
		error_report("failed to get special registers");
		return ret;
	}

	direction_flag = (standard_regs.rflags & DF) != 0;

	if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_WRITE) {
		src = linear_addr(cpu, info->rsi, R_DS);

		for (size_t i = 0; i < repeat; i++) {
			ret = read_memory_mgns(cpu_fd, 0, 0, src, data, len);
			if (ret < 0) {
				perror("failed to read memory");
				return -1;
			}
			ret = pio_write_fn(port, data, len, false);
			if (ret < 0) {
				perror("failed to write to io port");
				return -1;
			}
			if (direction_flag) {
				src -= (uint64_t)len;
				info->rsi -= (uint64_t)len;
			} else {
				src += (uint64_t)len;
				info->rsi += (uint64_t)len;
			}
		}
		rip = info->header.rip + insn_len;
		rax = info->rax;
		rsi = info->rsi;
		reg_names[0] = HV_X64_REGISTER_RIP;
		reg_values[0] = rip;
		reg_names[1] = HV_X64_REGISTER_RAX;
		reg_values[1] = rax;
		reg_names[2] = HV_X64_REGISTER_RSI;
		reg_values[2] = rsi;
	} else {
		dst = linear_addr(cpu, info->rdi, R_ES);

		for (size_t i = 0; i < repeat; i++) {
			pio_read_fn(port, data, len, false);

			ret = write_memory_mgns(cpu_fd, 0, 0, dst, data, len);
			if (ret < 0) {
				perror("failed to write memory");
				return -1;
			}
			if (direction_flag) {
				dst -= (uint64_t)len;
				info->rdi -= (uint64_t)len;
			} else {
				dst += (uint64_t)len;
				info->rdi += (uint64_t)len;
			}
		}
		rip = info->header.rip + insn_len;
		rax = info->rax;
		rdi = info->rdi;
		reg_names[0] = HV_X64_REGISTER_RIP;
		reg_values[0] = rip;
		reg_names[1] = HV_X64_REGISTER_RAX;
		reg_values[1] = rax;
		reg_names[2] = HV_X64_REGISTER_RDI;
		reg_values[2] = rdi;
	}

	x64_regs.names = reg_names;
	x64_regs.values = reg_values;
	x64_regs.count = 2;

	ret = set_x64_registers_mgns(cpu_fd, &x64_regs);
	if (ret < 0) {
		perror("failed to set x64 registers");
		return -1;
	}

	return 0;
}

static int handle_pio_non_str(CPUState *cpu,
                              struct hv_x64_io_port_intercept_message *info) {
	size_t len = info->access_info.access_size;
	uint8_t access_type = info->header.intercept_access_type;
	int ret;
	uint32_t val, eax;
	const uint32_t eax_mask =  0xffffffffu >> (32 - len * 8);
	size_t insn_len;
	uint64_t rip, rax;
	uint32_t reg_names[2];
	uint64_t reg_values[2];
	struct X64Registers x64_regs = { 0 };
	uint16_t port = info->port_number;
	int cpu_fd = mshv_vcpufd(cpu);

	if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_WRITE) {
		union {
			uint32_t u32;
			uint8_t bytes[4];
		} conv;

		/* convert the first 4 bytes of rax to bytes */
		conv.u32 = (uint32_t)info->rax;
		/* secure mode is set to false */
		ret = pio_write_fn(port, conv.bytes, len, false);
		if (ret < 0) {
			perror("failed to write to io port");
			return -1;
		}
	} else {
		uint8_t data[4] = { 0 };
		/* secure mode is set to false */
		pio_read_fn(info->port_number, data, len, false);

		/* Preserve high bits in EAX, but clear out high bits in RAX */
		val = *(uint32_t *)data;
		eax = (((uint32_t)info->rax) & ~eax_mask) | (val & eax_mask);
		info->rax = (uint64_t)eax;
	}

	insn_len = info->header.instruction_length;

	/* Advance RIP and update RAX */
	rip = info->header.rip + insn_len;
	rax = info->rax;

	reg_names[0] = HV_X64_REGISTER_RIP;
	reg_values[0] = rip;
	reg_names[1] = HV_X64_REGISTER_RAX;
	reg_values[1] = rax;

	x64_regs.names = reg_names;
	x64_regs.values = reg_values;
	x64_regs.count = 2;

	ret = set_x64_registers_mgns(cpu_fd, &x64_regs);
	if (ret < 0) {
		perror("failed to set x64 registers");
		return -1;
	}

	return 0;
}

static int set_ioport_info(const struct hyperv_message *msg,
		                   struct hv_x64_io_port_intercept_message *info)
{
	if (msg->header.message_type != HVMSG_X64_IO_PORT_INTERCEPT) {
		perror("invalid message type");
		return -1;
	}
	// copy the content of the message to info
	memcpy(info, msg->payload, sizeof(*info));
	return 0;
}

static int handle_pio(CPUState *cpu, const struct hyperv_message *msg)
{
	struct hv_x64_io_port_intercept_message info = { 0 };
	int ret;

	ret = set_ioport_info(msg, &info);
	if (ret < 0) {
		perror("failed to convert message to ioport info");
		return -1;
	}

	if (info.access_info.string_op) {
		return handle_pio_str(cpu, &info);
	}

	return handle_pio_non_str(cpu, &info);
}

enum VmExitMgns run_vcpu(int vm_fd, CPUState *cpu, hv_message *msg)
{
	int ret;
	hv_message exit_msg = { 0 };
	enum VmExitMgns exit_reason;
	int cpu_fd = mshv_vcpufd(cpu);

	ret = ioctl(cpu_fd, MSHV_RUN_VP, &exit_msg);
	if (ret < 0) {
		perror("failed to run vcpu");
		return VmExitShutdown;
	}

	switch(exit_msg.header.message_type) {
		case HVMSG_UNRECOVERABLE_EXCEPTION:
			*msg = exit_msg;
			return VmExitShutdown;
		case HVMSG_UNMAPPED_GPA:
			ret = handle_unmapped_mem(vm_fd, cpu, &exit_msg, &exit_reason);
			if (ret < 0) {
				perror("failed to handle unmapped memory");
				abort();
			}
			return exit_reason;
		case HVMSG_GPA_INTERCEPT:
			ret = handle_mmio(cpu, &exit_msg, &exit_reason);
			if (ret < 0) {
				perror("failed to handle mmio");
				abort();
			}
			return exit_reason;
		case HVMSG_X64_IO_PORT_INTERCEPT:
			ret = handle_pio(cpu, &exit_msg);
			if (ret < 0) {
				return VmExitSpecial;
			}
			return VmExitIgnore;
		default:
			msg = &exit_msg;
	}

	return 0;
}
