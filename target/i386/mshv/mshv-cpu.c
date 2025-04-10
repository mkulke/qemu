#include "qemu/osdep.h"
#include "cpu.h"
#include "system/mshv.h"
#include "emulate/x86_flags.h"
#include "qemu/error-report.h"

int mshv_store_regs(CPUState *cpu)
{
	int ret;

	ret = mshv_set_standard_regs(cpu);
	if (ret < 0) {
		perror("Failed to store standard registers");
		return -1;
	}

    /* TODO: should store special registers? */

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
    FloatingPointUnit fpu = {0};
    int ret = 0;

    memset(&fpu, 0, sizeof(fpu));

    mshv_configure_vcpu(cpu, &fpu, env->xcr0);

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
