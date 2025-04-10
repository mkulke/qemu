#include "qemu/osdep.h"
#include "cpu.h"
#include "system/mshv.h"
#include "emulate/x86_flags.h"
#include "qemu/error-report.h"

static void set_seg(struct SegmentRegister *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type_ = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = !lhs->present;
    lhs->padding = 0;
}

static void mshv_set_seg(struct SegmentRegister *mshv_seg, SegmentCache *qemu_s)
{
    set_seg(mshv_seg, (const struct SegmentCache *)qemu_s);
}

static void mshv_put_reg(uint64_t *mshv_reg, target_ulong *qemu_reg)
{
    *mshv_reg = *qemu_reg;
}

int mshv_store_regs(int cpu_fd, const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    StandardRegisters regs = {0};
	int ret;

	regs.rax = env->regs[R_EAX];
	regs.rbx = env->regs[R_EBX];
	regs.rcx = env->regs[R_ECX];
	regs.rdx = env->regs[R_EDX];
	regs.rsi = env->regs[R_ESI];
	regs.rdi = env->regs[R_EDI];
	regs.rsp = env->regs[R_ESP];
	regs.rbp = env->regs[R_EBP];
	regs.r8  = env->regs[R_R8];
	regs.r9  = env->regs[R_R9];
	regs.r10 = env->regs[R_R10];
	regs.r11 = env->regs[R_R11];
	regs.r12 = env->regs[R_R12];
	regs.r13 = env->regs[R_R13];
	regs.r14 = env->regs[R_R14];
	regs.r15 = env->regs[R_R15];
    lflags_to_rflags(env);
	regs.rflags = env->eflags;
	regs.rip = env->eip;

	ret = mshv_set_standard_regs(cpu_fd, &regs);
	if (ret < 0) {
		perror("Failed to store standard registers");
		return -1;
	}

	return 0;
}

int mshv_load_regs(CPUState *cpu)
{
	int ret;

	ret = mshv_get_standard_regs(cpu);
	if (ret < 0) {
		perror("Failed to load standard registers");
		return -1;
	}
	ret = mshv_get_special_regs(cpu);
	if (ret < 0) {
		perror("Failed to load special registers");
		return -1;
	}

	return 0;
}

static int mshv_put_regs(MshvState *mshv_state, CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    StandardRegisters regs = {0};
    SpecialRegisters sregs = {0};
    FloatingPointUnit fpu = {0};
    MshvCpuState cpu_state = { .regs = &regs, .sregs = &sregs, .fpu = &fpu };
    int ret = 0;

    mshv_put_reg(&regs.rax, &env->regs[R_EAX]);
    mshv_put_reg(&regs.rbx, &env->regs[R_EBX]);
    mshv_put_reg(&regs.rcx, &env->regs[R_ECX]);
    mshv_put_reg(&regs.rdx, &env->regs[R_EDX]);
    mshv_put_reg(&regs.rsi, &env->regs[R_ESI]);
    mshv_put_reg(&regs.rdi, &env->regs[R_EDI]);
    mshv_put_reg(&regs.rsp, &env->regs[R_ESP]);
    mshv_put_reg(&regs.rbp, &env->regs[R_EBP]);
    mshv_put_reg(&regs.rflags, &env->eflags);
    mshv_put_reg(&regs.rip, &env->eip);

    mshv_set_seg(&sregs.cs, &env->segs[R_CS]);
    mshv_set_seg(&sregs.ds, &env->segs[R_DS]);
    mshv_set_seg(&sregs.es, &env->segs[R_ES]);
    mshv_set_seg(&sregs.fs, &env->segs[R_FS]);
    mshv_set_seg(&sregs.gs, &env->segs[R_GS]);
    mshv_set_seg(&sregs.ss, &env->segs[R_SS]);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;

    mshv_put_reg(&sregs.cr0, &env->cr[0]);
    mshv_put_reg(&sregs.cr2, &env->cr[2]);
    mshv_put_reg(&sregs.cr3, &env->cr[3]);
    mshv_put_reg(&sregs.cr4, &env->cr[4]);

    mshv_put_reg(&sregs.efer, &env->efer);

    sregs.cr8 = cpu_get_apic_tpr(x86cpu->apic_state);
    sregs.apic_base = cpu_get_apic_base(x86cpu->apic_state);
    memset(&sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));
    memset(&fpu, 0, sizeof(fpu));

    mshv_configure_vcpu(cpu, &cpu_state, env->xcr0);

    return ret;
}

#define MSR_ENTRIES_COUNT 64

struct MsrList {
    MshvMsrEntry entries[MSR_ENTRIES_COUNT];
    uint32_t nmsrs;
};

static MshvMsrEntry *mshv_msr_entry_add(struct MsrList *msrs, uint32_t index,
                                        uint64_t value)
{
    MshvMsrEntry *entry = &msrs->entries[msrs->nmsrs];

    assert(msrs->nmsrs < MSR_ENTRIES_COUNT);

    entry->index = index;
    entry->reserved = 0;
    entry->data = value;
    msrs->nmsrs++;

    return entry;
}

static int mshv_put_msrs(CPUState *cpu)
{
	int ret = 0;
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    struct MsrList *msrs = g_malloc0(sizeof(struct MsrList));

    mshv_msr_entry_add(msrs, MSR_IA32_SYSENTER_CS, env->sysenter_cs);
    mshv_msr_entry_add(msrs, MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    mshv_msr_entry_add(msrs, MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    mshv_msr_entry_add(msrs, MSR_EFER, env->efer);
    mshv_msr_entry_add(msrs, MSR_PAT, env->pat);
    mshv_msr_entry_add(msrs, MSR_STAR, env->star);
    mshv_msr_entry_add(msrs, MSR_CSTAR, env->cstar);
    mshv_msr_entry_add(msrs, MSR_LSTAR, env->lstar);
    mshv_msr_entry_add(msrs, MSR_KERNELGSBASE, env->kernelgsbase);
    mshv_msr_entry_add(msrs, MSR_FMASK, env->fmask);
    mshv_msr_entry_add(msrs, MSR_MTRRdefType, env->mtrr_deftype);
    mshv_msr_entry_add(msrs, MSR_VM_HSAVE_PA, env->vm_hsave);
    mshv_msr_entry_add(msrs, MSR_SMI_COUNT, env->msr_smi_count);
    mshv_msr_entry_add(msrs, MSR_IA32_PKRS, env->pkrs);
    mshv_msr_entry_add(msrs, MSR_IA32_BNDCFGS, env->msr_bndcfgs);
    mshv_msr_entry_add(msrs, MSR_IA32_XSS, env->xss);
    mshv_msr_entry_add(msrs, MSR_IA32_UMWAIT_CONTROL, env->umwait);
    mshv_msr_entry_add(msrs, MSR_IA32_TSX_CTRL, env->tsx_ctrl);
    mshv_msr_entry_add(msrs, MSR_AMD64_TSC_RATIO, env->amd_tsc_scale_msr);
    mshv_msr_entry_add(msrs, MSR_TSC_AUX, env->tsc_aux);
    mshv_msr_entry_add(msrs, MSR_TSC_ADJUST, env->tsc_adjust);
    mshv_msr_entry_add(msrs, MSR_IA32_SMBASE, env->smbase);
    mshv_msr_entry_add(msrs, MSR_IA32_SPEC_CTRL, env->spec_ctrl);
    mshv_msr_entry_add(msrs, MSR_VIRT_SSBD, env->virt_ssbd);
    ret = mshv_configure_msr(mshv_vcpufd(cpu), &msrs->entries[0], msrs->nmsrs);
    g_free(msrs);
    return ret;
}

int mshv_arch_put_registers(MshvState *mshv_state, CPUState *cpu)
{
    int ret = 0;

    ret = mshv_put_regs(mshv_state, cpu);
    if (ret) {
        return ret;
    }

    ret = mshv_put_msrs(cpu);
    if (ret) {
        return ret;
    }

    return ret;
}
