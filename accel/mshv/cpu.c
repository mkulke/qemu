#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "sysemu/mshv.h"
#include <qemu-mshv.h>
#include <stdint.h>
#include <sys/ioctl.h>

static GHashTable *cpu_db_mgns;
static QemuMutex cpu_db_mutex_mgns;

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

static int create_vcpu_mgns(int vm_fd, uint8_t vp_index)
{
	/* int ret; */
	/* struct mshv_create_vp vp_arg = { */
	/* 	.vp_index = vp_index, */
	/* }; */
	/* ret = ioctl(vm_fd, MSHV_CREATE_VP, &vp_arg); */
	/* if (ret < 0) { */
	/* 	perror("failed to create vcpu"); */
	/* 	return -errno; */
	/* } */

	/* return ret; */
	printf("[mgns-qemu] skipped create_vcpu_mgns %d\n", vp_index);
	return 0;
}

void remove_vcpu_mgns(int vcpu_fd)
{
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

inline static int get_generic_regs_mgns(int cpu_fd,
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

inline static void populate_segment_reg_mgns(struct hv_x64_segment_register *hv_seg,
											 struct SegmentRegister *seg)
{
	*seg = (struct SegmentRegister){0};

	seg->base = hv_seg->base;
	seg->limit = hv_seg->limit;
	seg->selector = hv_seg->selector;
	seg->unusable = 0;
	seg->padding = 0;
}

inline static void populate_table_reg_mgns(struct hv_x64_segment_register *hv_seg,
										   struct TableRegister *seg)
{
	*seg = (struct TableRegister){0};

	seg->base = hv_seg->base;
	seg->limit = hv_seg->limit;
}

inline static void populate_interrupt_bitmap_mgns(uint64_t pending_reg, uint64_t *bitmap)
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

inline static void populate_special_regs_mgns(struct hv_register_assoc *assocs,
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

	populate_table_reg_mgns(&assocs[8].value.segment, &regs->gdt);
	populate_table_reg_mgns(&assocs[9].value.segment, &regs->idt);

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

static int get_standard_regs_mgns(int cpu_fd, struct StandardRegisters *regs)
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
	populate_special_regs_mgns(assocs, regs);
	g_free(assocs);
	return 0;
}

static int set_special_regs_mgns(int cpu_fd, struct SpecialRegisters *regs)
{
	return 0;
	/* struct hv_register_assoc *assocs; */
	/* union hv_register_value *value; */
	/* size_t n_regs = sizeof(SPECIAL_REGISTER_NAMES) / sizeof(enum hv_register_name); */
	/* size_t fp_i; */
	/* union hv_x64_fp_control_status_register *ctrl_status; */
	/* union hv_x64_xmm_control_status_register *xmm_ctrl_status; */
	/* int ret; */

	/* assocs = g_new0(struct hv_register_assoc, n_regs); */

	/* /1* first 16 registers are xmm0-xmm15 *1/ */
	/* for (size_t i = 0; i < 16; i++) { */
	/* 	assocs[i].name = FPU_REGISTER_NAMES[i]; */
	/* 	value = &assocs[i].value; */
	/* 	memcpy(&value->reg128, &regs->xmm[i], 16); */
	/* } */

	/* /1* next 8 registers are fp_mmx0-fp_mmx7 *1/ */
	/* for (size_t i = 16; i < 24; i++) { */
	/* 	assocs[i].name = FPU_REGISTER_NAMES[i]; */
	/* 	fp_i = (i - 16); */
	/* 	value = &assocs[i].value; */
	/* 	memcpy(&value->reg128, &regs->fpr[fp_i], 16); */
	/* } */	

	/* /1* last two registers are fp_control_status and xmm_control_status *1/ */
	/* assocs[24].name = FPU_REGISTER_NAMES[24]; */
	/* value = &assocs[24].value; */
	/* ctrl_status = &value->fp_control_status; */
	/* ctrl_status->fp_control = regs->fcw; */
	/* ctrl_status->fp_status = regs->fsw; */
	/* ctrl_status->fp_tag = regs->ftwx; */
	/* ctrl_status->reserved = 0; */
	/* ctrl_status->last_fp_op = regs->last_opcode; */
	/* ctrl_status->last_fp_rip = regs->last_ip; */

	/* assocs[25].name = FPU_REGISTER_NAMES[25]; */
	/* value = &assocs[25].value; */
	/* xmm_ctrl_status = &value->xmm_control_status; */
	/* xmm_ctrl_status->xmm_status_control = regs->mxcsr; */
	/* xmm_ctrl_status->xmm_status_control_mask = 0; */
	/* xmm_ctrl_status->last_fp_rdp = regs->last_dp; */

	/* ret = set_generic_regs_mgns(cpu_fd, assocs, n_regs); */
	/* g_free(assocs); */
	/* if (ret < 0) { */
	/* 	perror("failed to set fpu registers"); */
	/* 	return -errno; */
	/* } */
	/* g_free(assocs); */
	/* return 0; */
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

static int set_fpu_regs_mgns(int cpu_fd, struct FloatingPointUnit *regs)
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
	g_free(assocs);
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
				  struct StandardRegisters *standard_regs,
				  struct SpecialRegisters *special_regs,
				  struct FloatingPointUnit *fpu_regs,
				  uint64_t xcr0)
{
	int ret;

	ret = set_special_regs_mgns(cpu_fd, special_regs);
	if (ret < 0) {
		return ret;
	}

	ret = set_fpu_regs_mgns(cpu_fd, fpu_regs);
	if (ret < 0) {
		return ret;
	}
	return set_xc_reg_mgns(cpu_fd, xcr0);
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

static int set_msrs(int cpu_fd, GList *msrs)
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

	ret = set_msrs(cpu_fd, valid_msrs);
	g_list_free(valid_msrs);
	return ret;
}
