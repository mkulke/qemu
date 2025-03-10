#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/memalign.h"
#include "sysemu/mshv.h"
#include <qemu-mshv.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

static GHashTable *cpu_db_mgns;
static QemuMutex cpu_db_mutex_mgns;

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
void init_cpu_db_mgns(void)
{
	cpu_db_mgns = g_hash_table_new(g_direct_hash, g_direct_equal);
	qemu_mutex_init(&cpu_db_mutex_mgns);
}

int create_vcpu_mgns(int vm_fd, uint8_t vp_index)
{
	int ret;
	struct mshv_create_vp vp_arg = {
		.vp_index = vp_index,
	};
	ret = ioctl(vm_fd, MSHV_CREATE_VP, &vp_arg);
	if (ret < 0) {
		perror("failed to create vcpu");
		return -errno;
	}

	printf("[mgns-qemu] created vcpu %d\n", vp_index);

	return ret;
	/* printf("[mgns-qemu] skipped create_vcpu_mgns %d\n", vp_index); */
	/* return 0; */
}

void remove_vcpu_mgns(int vcpu_fd)
{
	/* TODO: don't we have to perform an ioctl to remove the vcpu?
	 * there is WHvDeleteVirtualProcessor in the WHV api
	 * */

	WITH_QEMU_LOCK_GUARD(&cpu_db_mutex_mgns) {
		g_hash_table_remove(cpu_db_mgns, GUINT_TO_POINTER(vcpu_fd));
	}
}

int new_vcpu_mgns(int mshv_fd, uint8_t vp_index, MshvOps *ops)
{
	int ret, vcpu_fd;

	ret = create_vcpu_mgns(mshv_fd, vp_index);
	if (ret < 0) {
		return ret;
	}
	vcpu_fd = ret;

	PerCpuInfoMgns *info = g_new0(PerCpuInfoMgns, 1);
	info->vp_index = vp_index;
	info->ops = ops;
	info->vp_fd = vcpu_fd;

	WITH_QEMU_LOCK_GUARD(&cpu_db_mutex_mgns) {
		g_hash_table_insert(cpu_db_mgns, GUINT_TO_POINTER(vcpu_fd), info);
	}

	return 0;
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

inline static void populate_standard_regs_mgns(struct hv_register_assoc *assocs,
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

int get_standard_regs_mgns(int cpu_fd, struct StandardRegisters *regs)
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

static int set_standard_regs_mgns(int cpu_fd, const struct StandardRegisters *regs)
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

static int get_special_regs_mgns(int cpu_fd, struct SpecialRegisters *regs)
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

	/* size_t size = sizeof(struct hv_register_assoc) * n_regs; */
	/* printf("[mgns-qemu] hv_register_assoc w/ size %zu", size); */
	/* for (size_t i = 0; i < size; i++) { */
	/* 	if (i % 16 == 0) { */
	/* 		printf("\n"); */
	/* 	} */
	/* 	printf("%02x ", ((uint8_t *)assocs)[i]); */
	/* } */
	/* printf("\n"); */

	populate_special_regs_mgns(assocs, regs);

	/* size = sizeof(struct SpecialRegisters); */
	/* printf("[mgns-qemu] regs w/ size %zu", size); */
	/* // print 16 bytes in hex every line */
	/* for (size_t i = 0; i < size; i++) { */
	/* 	if (i % 16 == 0) { */
	/* 		printf("\n"); */
	/* 	} */
	/* 	printf("%02x ", ((uint8_t *)assocs)[i]); */
	/* } */
	/* printf("\n"); */

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

static int get_fpu_regs_mgns(int cpu_fd, struct FloatingPointUnit *regs)
{
	size_t n_regs = sizeof(FPU_REGISTER_NAMES) / sizeof(enum hv_register_name);
	struct hv_register_assoc *assocs;
	int ret;

	assocs = g_new0(struct hv_register_assoc, n_regs);
	for (size_t i = 0; i < n_regs; i++) {
		assocs[i].name = FPU_REGISTER_NAMES[i];
	}
	ret = get_generic_regs_mgns(cpu_fd, assocs, n_regs);
	if (ret < 0) {
		perror("failed to get fpu registers");
		g_free(assocs);
		return -errno;
	}
	populate_fpu_regs_mgns(assocs, regs);
	g_free(assocs);
	return 0;
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

int set_vcpu_mgns(int cpu_fd,
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
	printf("[mgns-qemu] set_vcpu_mgns() done\n");
	return 0;
}

int get_vcpu_mgns(int cpu_fd,
                  struct StandardRegisters *standard_regs,
                  struct SpecialRegisters *special_regs,
                  struct FloatingPointUnit *fpu_regs)
{
	int ret;

	ret = get_standard_regs_mgns(cpu_fd, standard_regs);
	if (ret < 0) {
		return ret;
	}
	ret = get_special_regs_mgns(cpu_fd, special_regs);
	if (ret < 0) {
		return ret;
	}
	ret = get_fpu_regs_mgns(cpu_fd, fpu_regs);
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

static int set_cpuid2(int cpu_fd, struct hv_cpuid *cpuid)
{
	int ret;

	ret = register_intercept_result_cpuid(cpu_fd, cpuid);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* TODO: Note this function is still using the cpuid impl from mshv-c */
static int set_cpuid2_mgns(int cpu_fd, struct CpuIdMgns *cpuid_mgns)
{
	int ret;
	size_t n_entries = cpuid_mgns->len;
    size_t cpuid_size = sizeof(struct hv_cpuid)
		+ n_entries * sizeof(struct hv_cpuid_entry);
	struct hv_cpuid *cpuid;
	struct hv_cpuid_entry *entry;
	struct CpuIdEntryMgns *mgns_entry;

	cpuid = g_malloc0(cpuid_size);
	cpuid->nent = n_entries;
	cpuid->padding = 0;
	for (size_t i = 0; i < n_entries; i++) {
		mgns_entry = &cpuid_mgns->entries[i];
		entry = &cpuid->entries[i];
		entry->function = mgns_entry->function;
		entry->index = mgns_entry->index;
		entry->flags = mgns_entry->flags;
		entry->eax = mgns_entry->eax;
		entry->ebx = mgns_entry->ebx;
		entry->ecx = mgns_entry->ecx;
		entry->edx = mgns_entry->edx;
		/* padding is covered, due to 0ing  */
	}

	ret = set_cpuid2(cpu_fd, cpuid);
	g_free(cpuid);
	if (ret < 0) {
		return ret;
	}

	printf("[mgns-qemu] set_cpuid2_mgns2() done\n");

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

int configure_vcpu_mgns(int cpu_fd,
						uint8_t id,
						enum MshvCpuVendor cpu_vendor,
						uint8_t ndies,
						uint8_t ncores_per_die,
						uint8_t nthreads_per_core,
						struct StandardRegisters *standard_regs,
						struct SpecialRegisters *special_regs,
						uint64_t xcr0,
						struct FloatingPointUnit *fpu_regs)
{
	int ret;
	struct CpuIdMgns *cpuid_mshvc;

	/* TODO: we create the cpuid data in mshv-c for the time being
	 * we need to port it or consolidate with existing qemu facilities */
	cpuid_mshvc = create_cpuid_mgns(id,
								    cpu_vendor,
								    ndies,
								    ncores_per_die / ndies,
								    nthreads_per_core);
	ret = set_cpuid2_mgns(cpu_fd, cpuid_mshvc);
	mshv_free_cpuid_mgns(cpuid_mshvc);
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

	ret = set_vcpu_mgns(cpu_fd,
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

int set_cpu_state_mgns(int cpu_fd,
		 	           const StandardRegisters *standard_regs,
					   const SpecialRegisters *special_regs)
{
	int ret;

	ret = set_standard_regs_mgns(cpu_fd, standard_regs);
	if (ret < 0) {
		perror("failed to set standard registers");
		return ret;
	}

	ret = set_special_regs_mgns(cpu_fd, special_regs);
	if (ret < 0) {
		perror("failed to set special registers");
		return ret;
	}

	return 0;
}

int get_cpu_state_mgns(int cpu_fd,
					   StandardRegisters *standard_regs,
					   SpecialRegisters *special_regs)
{

	int ret;

	ret = get_standard_regs_mgns(cpu_fd, standard_regs);
	if (ret < 0) {
		perror("failed to get cpu state");
		return ret;
	}

	ret = get_special_regs_mgns(cpu_fd, special_regs);
	if (ret < 0) {
		perror("failed to get cpu state");
		return ret;
	}
return 0;
}

int translate_gva_mgns(int cpu_fd, uint64_t gva, uint64_t *gpa,
					   uint64_t flags)
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
		perror("failed to translate gva to gpa");
		return -1;
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

int run_vcpu_mgns(int cpu_fd, struct hyperv_message *msg)
{
	int ret;

	ret = ioctl(cpu_fd, MSHV_RUN_VP, msg);
	if (ret < 0) {
		perror("failed to run vcpu");
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

static MshvOps mshv_ops = {
	.guest_mem_write_fn = guest_mem_write_fn,
	.guest_mem_read_fn = guest_mem_read_fn,
	.mmio_read_fn = mmio_read_fn,
	.mmio_write_fn = mmio_write_fn,
	.pio_read_fn = pio_read_fn,
	.pio_write_fn = pio_write_fn,
	/* fn's for the plaform in the emulator */
	.set_cpu_state = set_cpu_state_mgns,
	.get_cpu_state = get_cpu_state_mgns,
	.set_x64_registers = set_x64_registers_mgns,
	.translate_gva = translate_gva_mgns,
	.run = run_vcpu_mgns,
	/* memory fn */
	.find_by_gpa = find_entry_idx_by_gpa_mgns,
	.map_overlapped_region = map_overlapped_region_mgns,
};

static int emulate_ch(int cpu_fd,
					  uint64_t gva,
					  uint64_t gpa,
					  uint8_t (*instructions)[16])
{
	emulate_ch_exported(cpu_fd,
			           gva, gpa,
					   (uint8_t*)instructions, 16,
					   &mshv_ops);
	return 0;
}

static int linearize_ds_ch(struct EmulatorWrapperMgns *emu,
		                   uint64_t logical_addr)
{
	return linearize_exported(emu->cpu_fd,
					   DSRegister,
					   logical_addr,
					   emu->initial_gva,
					   emu->initial_gpa,
					   &mshv_ops);
}

static int linearize_es_ch(struct EmulatorWrapperMgns *emu,
		                   uint64_t logical_addr)
{
	return linearize_exported(emu->cpu_fd,
					   ESRegister,
					   logical_addr,
					   emu->initial_gva,
					   emu->initial_gpa,
					   &mshv_ops);
}

static int handle_mmio_mgns(int cpu_fd,
					        const struct hyperv_message *msg,
					        enum VmExitMgns *exit_reason)
{
	struct hv_x64_memory_intercept_message info = { 0 };
	size_t insn_len;
	uint8_t access_type;
	uint64_t gva, gpa;
	int ret;

	ret = set_memory_info(msg, &info);
	if (ret < 0) {
		perror("failed to convert message to memory info");
		/* TODO: rather return? */
		abort();
	}
	insn_len = info.instruction_byte_count;
	access_type = info.header.intercept_access_type;
	gva = info.guest_virtual_address;
	gpa = info.guest_physical_address;

	if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE) {
		perror("invalid intercept access type: execute");
		abort();
	}

	if (insn_len <= 0 || insn_len > 16) {
		perror("invalid instruction length");
		abort();
	}

	ret = emulate_ch(cpu_fd, gva, gpa, &info.instruction_bytes);
	if (ret < 0) {
		perror("failed to emulate mmio");
		abort();
	}

	*exit_reason = VmExitIgnore;

	return 0;
}

int handle_unmapped_mem_mgns(int vm_fd,
							 int vcpu_fd,
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
		return handle_mmio_mgns(vcpu_fd, msg, exit_reason);
	}

	ret = map_overlapped_region_mgns(vm_fd, gpa);
	if (ret < 0) {
		*exit_reason = VmExitSpecial;
	} else {
		*exit_reason = VmExitIgnore;
	}

	return 0;
}

static int read_memory_mgns(struct EmulatorWrapperMgns *emu,
		                    uint64_t gva,
		                    uint8_t *data,
		                    size_t len)
{
	int ret;
	uint64_t gpa, flags;

	if (gva == emu->initial_gva) {
		gpa = emu->initial_gpa;
	} else {
	    flags = HV_TRANSLATE_GVA_VALIDATE_READ;
		ret = translate_gva_mgns(emu->cpu_fd, gva, &gpa, flags);
		if (ret < 0) {
			perror("failed to translate gva to gpa");
			return -1;
		}
		/* TODO: it's unfortunate that this fn doesn't fail
		 * the rust code has a code path for failed reads at this point,
		 * but it's dead code */
		guest_mem_read_fn(gpa, data, len, false);
	}

	return 0;
}

static int write_memory_mgns(struct EmulatorWrapperMgns *emu,
							 uint64_t gva,
							 const uint8_t *data,
							 size_t len)
{
	int ret;
	uint64_t gpa, flags;

	if (gva == emu->initial_gva) {
		gpa = emu->initial_gpa;
	} else {
	    flags = HV_TRANSLATE_GVA_VALIDATE_WRITE;
		ret = translate_gva_mgns(emu->cpu_fd, gva, &gpa, flags);
		if (ret < 0) {
			perror("failed to translate gva to gpa");
			return -1;
		}
	}
	ret = guest_mem_write_fn(gpa, data, len, false);
	if (ret == MEMTX_OK) {
		return 0;
	}

	ret = mmio_write_fn(gpa, data, len, false);
	if (ret < 0) {
		perror("failed to write to mmio");
		return -1;
	}

	return 0;
}

static int handle_pio_str_mgns(int cpu_fd,
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
	struct EmulatorWrapperMgns emu = { 0 };

	ret = get_cpu_state_mgns(cpu_fd, &standard_regs, &special_regs);
	if (ret < 0) {
		perror("failed to get cpu state");
		return -1;
	}

	emu.cpu_fd = cpu_fd;
	emu.initial_gpa = 0;
	emu.initial_gva = 0;

	direction_flag = (standard_regs.rflags & DF) != 0;

	if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_WRITE) {
		src = linearize_ds_ch(&emu, info->rsi);

		for (size_t i = 0; i < repeat; i++) {
			ret = read_memory_mgns(&emu, src, data, len);
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
		dst = linearize_es_ch(&emu, info->rdi);
		for (size_t i = 0; i < repeat; i++) {
			pio_read_fn(port, data, len, false);

			ret = write_memory_mgns(&emu, dst, data, len);
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

static int handle_pio_non_str_mgns(int cpu_fd,
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

int handle_pio_mgns(int cpu_fd, const struct hyperv_message *msg)
{
	struct hv_x64_io_port_intercept_message info = { 0 };
	int ret;

	ret = set_ioport_info(msg, &info);
	if (ret < 0) {
		perror("failed to convert message to ioport info");
		return -1;
	}

	if (info.access_info.string_op) {
		return handle_pio_str_mgns(cpu_fd, &info);
	}

	return handle_pio_non_str_mgns(cpu_fd, &info);
}

enum VmExitMgns run_vcpu_mgns2(int vm_fd,
							   int cpu_fd,
							   hv_message *msg)
{
	int ret;
	hv_message exit_msg = { 0 };
	enum VmExitMgns exit_reason;

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
			ret = handle_unmapped_mem_mgns(vm_fd, cpu_fd, &exit_msg, &exit_reason);
			if (ret < 0) {
				perror("failed to handle unmapped memory");
				abort();
			}
			return exit_reason;
		case HVMSG_GPA_INTERCEPT:
			ret = handle_mmio_mgns(cpu_fd, &exit_msg, &exit_reason);
			if (ret < 0) {
				perror("failed to handle mmio");
				abort();
			}
			return exit_reason;
		case HVMSG_X64_IO_PORT_INTERCEPT:
			ret = handle_pio_mgns(cpu_fd, &exit_msg);
			if (ret < 0) {
				return VmExitSpecial;
			}
			return VmExitIgnore;
		default:
			msg = &exit_msg;
	}

	return 0;
}
