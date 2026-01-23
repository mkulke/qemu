/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors: Ziqiao Zhou   <ziqiaozhou@microsoft.com>
 *          Magnus Kulke  <magnuskulke@microsoft.com>
 *          Jinank Jain   <jinankjain@microsoft.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/memalign.h"
#include "qemu/typedefs.h"

#include "system/mshv.h"
#include "system/mshv_int.h"
#include "system/address-spaces.h"
#include "linux/mshv.h"
#include "hw/hyperv/hvgdk.h"
#include "hw/hyperv/hvgdk_mini.h"
#include "hw/hyperv/hvhdk_mini.h"
#include "hw/i386/apic_internal.h"

#include "cpu.h"
#include "host-cpu.h"
#include "emulate/x86_decode.h"
#include "emulate/x86_emu.h"
#include "emulate/x86_flags.h"

#include "accel/accel-cpu-target.h"

#include "trace-accel_mshv.h"
#include "trace.h"

#include <sys/ioctl.h>

#define MAX_REGISTER_COUNT (MAX_CONST(ARRAY_SIZE(STANDARD_REGISTER_NAMES), \
                            MAX_CONST(ARRAY_SIZE(SPECIAL_REGISTER_NAMES), \
                                      ARRAY_SIZE(FPU_REGISTER_NAMES))))

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

static enum hv_register_name SPECIAL_REGISTER_NAMES[17] = {
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

static int set_special_regs(const CPUState *cpu);
static int get_generic_regs(CPUState *cpu,
                            struct hv_register_assoc *assocs,
                            size_t n_regs);

#define XSTATE_BV_IN_HDR  offsetof(X86XSaveHeader, xstate_bv)
#define XCOMP_BV_IN_HDR   offsetof(X86XSaveHeader, xcomp_bvo)

typedef struct X86XSaveAreaView {
    X86LegacyXSaveArea legacy;  /* 512 */
    X86XSaveHeader     header;  /* 64 */
    /* followed by extended state areas */
} X86XSaveAreaView;

#define XSAVE_XSTATE_BV_OFFSET  offsetof(X86XSaveAreaView, header.xstate_bv)
#define XSAVE_XCOMP_BV_OFFSET   offsetof(X86XSaveAreaView, header.xcomp_bv)
#define XSAVE_EXT_OFFSET        (sizeof(X86LegacyXSaveArea) + \
                                 sizeof(X86XSaveHeader)) /* 576 */

static int get_xsave_state(CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;
    void *xsavec_buf;
    const size_t page = HV_HYP_PAGE_SIZE;
    size_t xsavec_buf_len = page;

    /* TODO: should properly determine xsavec size based on CPUID */
    xsavec_buf = qemu_memalign(page, xsavec_buf_len);
    memset(xsavec_buf, 0, xsavec_buf_len);

    struct mshv_get_set_vp_state args = {
        .type = MSHV_VP_STATE_XSAVE,
        .buf_sz = xsavec_buf_len,
        .buf_ptr = (uintptr_t)xsavec_buf,
    };

    ret = ioctl(cpu_fd, MSHV_GET_VP_STATE, &args);

    /* debug debug debug start */
    if (false) {
        uint64_t *xcomp_bv = xsavec_buf + XSAVE_XCOMP_BV_OFFSET;
        uint64_t *xstate_bv = xsavec_buf + XSAVE_XSTATE_BV_OFFSET;
        uint64_t hv_xcr0 = (*xcomp_bv) & ~(1ULL << 63);  // strip compacted bit

        error_report("mgns: HV xcomp_bv=0x%lx (xcr0=0x%lx) xstate_bv=0x%lx",
                     *xcomp_bv, hv_xcr0, *xstate_bv);

        uint32_t eax, ebx, ecx, edx;
        host_cpuid(0xD, 0, &eax, &ebx, &ecx, &edx);
        uint64_t cpuid_xcr0 = ((uint64_t)edx << 32) | eax;

        host_cpuid(0xD, 1, &eax, &ebx, &ecx, &edx);
        uint64_t cpuid_xss = ((uint64_t)edx << 32) | ecx;  /* IA32_XSS from ECX/EDX */

        uint64_t cpuid_combined = cpuid_xcr0 | cpuid_xss;
        error_report("mgns: host_cpuid xcr0=0x%lx xss=0x%lx combined=0x%lx "
                     "(mismatch=0x%lx)",
                     cpuid_xcr0, cpuid_xss, cpuid_combined,
                     (hv_xcr0 & ~cpuid_combined));
    }
    /* debug debug debug end */

    if (ret < 0) {
        error_report("failed to get xsave state: %s", strerror(errno));
        return -errno;
    }

    ret = decompact_xsave_area(xsavec_buf, xsavec_buf_len, env);
    g_free(xsavec_buf);
    if (ret < 0) {
        error_report("failed to decompact xsave area");
        return ret;
    }
    x86_cpu_xrstor_all_areas(x86cpu, env->xsave_buf, env->xsave_buf_len);

    return 0;
}

static int set_xsave_state(const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;
    void *xsavec_buf;
    size_t page = HV_HYP_PAGE_SIZE, xsavec_buf_len;

    /* allocate and populate compacted buffer */
    xsavec_buf = qemu_memalign(page, page);
    xsavec_buf_len = page;

    /* save registers to standard format buffer */
    x86_cpu_xsave_all_areas(x86cpu, env->xsave_buf, env->xsave_buf_len);

    /* store compacted version of xsave area in xsavec_buf */
    compact_xsave_area(env, xsavec_buf, xsavec_buf_len);

    /* debug debug debug start */
    if (false) {
        uint64_t *dbg_xcomp_bv = xsavec_buf + XSAVE_XCOMP_BV_OFFSET;
        uint64_t *dbg_xstate_bv = xsavec_buf + XSAVE_XSTATE_BV_OFFSET;

        error_report("mgns: set_xsave_state() env->xcr0=0x%lx", env->xcr0);

        error_report("mgns: SET xcomp_bv=0x%lx xstate_bv=0x%lx size=%zu "
                     "env->xcr0=0x%lx",
                     *dbg_xcomp_bv, *dbg_xstate_bv, xsavec_buf_len, env->xcr0);

        error_report("mgns: compacted xsave area size: %zu bytes",
                     xsavec_buf_len);
    }
    /* debug debug debug end */

    struct mshv_get_set_vp_state args = {
        .type = MSHV_VP_STATE_XSAVE,
        .buf_sz = xsavec_buf_len,
        .buf_ptr = (uintptr_t)xsavec_buf,
    };

    ret = ioctl(cpu_fd, MSHV_SET_VP_STATE, &args);
    g_free(xsavec_buf);
    if (ret < 0) {
        error_report("failed to set xsave state: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

static int get_lapic(CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    APICCommonState *apic = APIC_COMMON(x86cpu->apic_state);
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;
    struct hv_local_interrupt_controller_state lapic_state = { 0 };

    ret = mshv_get_lapic(cpu_fd, &lapic_state);
    if (ret < 0) {
        error_report("failed to get lapic state");
        return -1;
    }

    memcpy(&apic->hv_lapic_state, &lapic_state, sizeof(lapic_state));

    return 0;
}

static int get_synic_state(CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;

    ret = mshv_get_simp(cpu_fd, env->hv_simp_page);
    if (ret < 0) {
        error_report("failed to get simp state");
        return -1;
    }

    ret = mshv_get_siefp(cpu_fd, env->hv_siefp_page);
    if (ret < 0) {
        error_report("failed to get siefp state");
        return -1;
    }

    return 0;
}

static int get_msrs(CPUState *cpu)
{
    int ret = 0;
    size_t n_assocs = mshv_msr_mappable_reg_count();
    struct hv_register_assoc *assocs;

    assocs = g_new0(struct hv_register_assoc, n_assocs);
    mshv_msr_set_hv_name_in_assocs(assocs, n_assocs);

    ret = get_generic_regs(cpu, assocs, n_assocs);
    if (ret < 0) {
        g_free(assocs);
        error_report("failed to get msrs");
        return -1;
    }

    mshv_msr_store_in_env(cpu, assocs, n_assocs);
    g_free(assocs);

    return 0;
}

static void populate_fpu(const hv_register_assoc *assocs, X86CPU *x86cpu)
{
    union hv_register_value value;
    const union hv_x64_fp_control_status_register *ctrl_status;
    const union hv_x64_xmm_control_status_register *xmm_ctrl;
    CPUX86State *env = &x86cpu->env;
    size_t i, fp_i;
    bool valid;

    /* first 16 registers are xmm0-xmm15 */
    for (i = 0; i < 16; i++) {
        value = assocs[i].value;
        env->xmm_regs[i].ZMM_Q(0) = value.reg128.low_part;
        env->xmm_regs[i].ZMM_Q(1) = value.reg128.high_part;
    }

    /* next 8 registers are fp_mmx0-fp_mmx7 */
    for (i = 16; i < 24; i++) {
        fp_i = i - 16;
        value = assocs[i].value;

        env->fpregs[fp_i].d.low = value.fp.mantissa;
        env->fpregs[fp_i].d.high = (value.fp.sign << 15)
                                 | (value.fp.biased_exponent & 0x7FFF);

    }

    /* last two registers are fp_control_status and xmm_control_status */
    ctrl_status = &assocs[24].value.fp_control_status;
    env->fpuc = ctrl_status->fp_control;

    env->fpus = ctrl_status->fp_status & ~0x3800;
    /* bits 11,12,13 are the top of stack pointer */
    env->fpstt = (ctrl_status->fp_status >> 11) & 0x7;

    for (i = 0; i < 8; i++) {
        valid = ctrl_status->fp_tag & (1 << i);
        env->fptags[i] = valid ? 0 : 1;
    }

    env->fpop = ctrl_status->last_fp_op;
    env->fpip = ctrl_status->last_fp_rip;

    xmm_ctrl = &assocs[25].value.xmm_control_status;
    env->mxcsr = xmm_ctrl->xmm_status_control;
    env->fpdp = xmm_ctrl->last_fp_rdp;
}

static int get_fpu(CPUState *cpu)
{
    struct hv_register_assoc assocs[ARRAY_SIZE(FPU_REGISTER_NAMES)];
    int ret;
    X86CPU *x86cpu = X86_CPU(cpu);
    size_t n_regs = ARRAY_SIZE(FPU_REGISTER_NAMES);

    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = FPU_REGISTER_NAMES[i];
    }
    ret = get_generic_regs(cpu, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to get special registers");
        return -errno;
    }

    populate_fpu(assocs, x86cpu);

    return 0;
}

static int get_xc_reg(CPUState *cpu)
{
    int ret;
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    struct hv_register_assoc assocs[1];

    assocs[0].name = HV_X64_REGISTER_XFEM;

    ret = get_generic_regs(cpu, assocs, 1);
    if (ret < 0) {
        error_report("failed to get xcr0");
        return -1;
    }
    env->xcr0 = assocs[0].value.reg64;

    return 0;
}

static int translate_gva(const CPUState *cpu, uint64_t gva, uint64_t *gpa,
                         uint64_t flags)
{
    int ret;
    int cpu_fd = mshv_vcpufd(cpu);
    int vp_index = cpu->cpu_index;

    hv_input_translate_virtual_address in = { 0 };
    hv_output_translate_virtual_address out = { 0 };
    struct mshv_root_hvcall args = {0};
    uint64_t gva_page = gva >> HV_HYP_PAGE_SHIFT;

    in.vp_index = vp_index;
    in.control_flags = flags;
    in.gva_page = gva_page;

    /* create the hvcall envelope */
    args.code = HVCALL_TRANSLATE_VIRTUAL_ADDRESS;
    args.in_sz = sizeof(in);
    args.in_ptr = (uint64_t) &in;
    args.out_sz = sizeof(out);
    args.out_ptr = (uint64_t) &out;

    /* perform the call */
    ret = mshv_hvcall(cpu_fd, &args);
    if (ret < 0) {
        error_report("Failed to invoke gva->gpa translation");
        return -errno;
    }

    if (out.translation_result.result_code != HV_TRANSLATE_GVA_SUCCESS) {
        error_report("Failed to translate gva (" TARGET_FMT_lx ") to gpa", gva);
        return -1;
    }

    *gpa = ((out.gpa_page << HV_HYP_PAGE_SHIFT)
         | (gva & ~(uint64_t)HV_HYP_PAGE_MASK));

    return 0;
}

static int set_generic_regs(const CPUState *cpu,
                            const hv_register_assoc *assocs, size_t n_regs)
{
    int cpu_fd = mshv_vcpufd(cpu);
    int vp_index = cpu->cpu_index;
    size_t in_sz, assocs_sz;
    hv_input_set_vp_registers *in = cpu->accel->hvcall_args.input_page;
    struct mshv_root_hvcall args = {0};
    int ret;

    /* find out the size of the struct w/ a flexible array at the tail */
    assocs_sz = n_regs * sizeof(hv_register_assoc);
    in_sz = sizeof(hv_input_set_vp_registers) + assocs_sz;

    /* fill the input struct */
    memset(in, 0, sizeof(hv_input_set_vp_registers));
    in->vp_index = vp_index;
    memcpy(in->elements, assocs, assocs_sz);

    /* create the hvcall envelope */
    args.code = HVCALL_SET_VP_REGISTERS;
    args.in_sz = in_sz;
    args.in_ptr = (uint64_t) in;
    args.reps = (uint16_t) n_regs;

    /* perform the call */
    ret = mshv_hvcall(cpu_fd, &args);
    if (ret < 0) {
        error_report("Failed to set registers");
        return -1;
    }

    /* assert we set all registers */
    if (args.reps != n_regs) {
        error_report("Failed to set registers: expected %zu elements"
                     ", got %u", n_regs, args.reps);
        return -1;
    }

    return 0;
}

static int get_generic_regs(CPUState *cpu, hv_register_assoc *assocs,
                            size_t n_regs)
{
    int cpu_fd = mshv_vcpufd(cpu);
    int vp_index = cpu->cpu_index;
    hv_input_get_vp_registers *in = cpu->accel->hvcall_args.input_page;
    hv_register_value *values = cpu->accel->hvcall_args.output_page;
    size_t in_sz, names_sz, values_sz;
    int i, ret;
    struct mshv_root_hvcall args = {0};

    /* find out the size of the struct w/ a flexible array at the tail */
    names_sz = n_regs * sizeof(hv_register_name);
    in_sz = sizeof(hv_input_get_vp_registers) + names_sz;

    /* fill the input struct */
    memset(in, 0, sizeof(hv_input_get_vp_registers));
    in->vp_index = vp_index;
    for (i = 0; i < n_regs; i++) {
        in->names[i] = assocs[i].name;
    }

    /* determine size of value output buffer */
    values_sz = n_regs * sizeof(union hv_register_value);

    /* create the hvcall envelope */
    args.code = HVCALL_GET_VP_REGISTERS;
    args.in_sz = in_sz;
    args.in_ptr = (uint64_t) in;
    args.out_sz = values_sz;
    args.out_ptr = (uint64_t) values;
    args.reps = (uint16_t) n_regs;

    /* perform the call */
    ret = mshv_hvcall(cpu_fd, &args);
    if (ret < 0) {
        error_report("Failed to retrieve registers");
        return -1;
    }

    /* assert we got all registers */
    if (args.reps != n_regs) {
        error_report("Failed to retrieve registers: expected %zu elements"
                     ", got %u", n_regs, args.reps);
        return -1;
    }

    /* copy values into assoc */
    for (i = 0; i < n_regs; i++) {
        assocs[i].value = values[i];
    }

    return 0;
}

static int set_standard_regs(const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    hv_register_assoc assocs[ARRAY_SIZE(STANDARD_REGISTER_NAMES)];
    int ret;
    size_t n_regs = ARRAY_SIZE(STANDARD_REGISTER_NAMES);

    /* set names */
    for (size_t i = 0; i < ARRAY_SIZE(STANDARD_REGISTER_NAMES); i++) {
        assocs[i].name = STANDARD_REGISTER_NAMES[i];
    }
    assocs[0].value.reg64 = env->regs[R_EAX];
    assocs[1].value.reg64 = env->regs[R_EBX];
    assocs[2].value.reg64 = env->regs[R_ECX];
    assocs[3].value.reg64 = env->regs[R_EDX];
    assocs[4].value.reg64 = env->regs[R_ESI];
    assocs[5].value.reg64 = env->regs[R_EDI];
    assocs[6].value.reg64 = env->regs[R_ESP];
    assocs[7].value.reg64 = env->regs[R_EBP];
    assocs[8].value.reg64 = env->regs[R_R8];
    assocs[9].value.reg64 = env->regs[R_R9];
    assocs[10].value.reg64 = env->regs[R_R10];
    assocs[11].value.reg64 = env->regs[R_R11];
    assocs[12].value.reg64 = env->regs[R_R12];
    assocs[13].value.reg64 = env->regs[R_R13];
    assocs[14].value.reg64 = env->regs[R_R14];
    assocs[15].value.reg64 = env->regs[R_R15];
    assocs[16].value.reg64 = env->eip;
    lflags_to_rflags(env);
    assocs[17].value.reg64 = env->eflags;

    ret = set_generic_regs(cpu, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to set standard registers");
        return -errno;
    }
    return 0;
}

static int store_regs(CPUState *cpu)
{
    int ret;

    ret = set_standard_regs(cpu);
    if (ret < 0) {
        error_report("Failed to store standard registers");
        return -1;
    }

    ret = set_special_regs(cpu);
    if (ret < 0) {
        error_report("Failed to store speical registers");
        return ret;
    }

    return 0;
}

static void populate_standard_regs(const hv_register_assoc *assocs,
                                   CPUX86State *env)
{
    env->regs[R_EAX] = assocs[0].value.reg64;
    env->regs[R_EBX] = assocs[1].value.reg64;
    env->regs[R_ECX] = assocs[2].value.reg64;
    env->regs[R_EDX] = assocs[3].value.reg64;
    env->regs[R_ESI] = assocs[4].value.reg64;
    env->regs[R_EDI] = assocs[5].value.reg64;
    env->regs[R_ESP] = assocs[6].value.reg64;
    env->regs[R_EBP] = assocs[7].value.reg64;
    env->regs[R_R8]  = assocs[8].value.reg64;
    env->regs[R_R9]  = assocs[9].value.reg64;
    env->regs[R_R10] = assocs[10].value.reg64;
    env->regs[R_R11] = assocs[11].value.reg64;
    env->regs[R_R12] = assocs[12].value.reg64;
    env->regs[R_R13] = assocs[13].value.reg64;
    env->regs[R_R14] = assocs[14].value.reg64;
    env->regs[R_R15] = assocs[15].value.reg64;

    env->eip = assocs[16].value.reg64;
    env->eflags = assocs[17].value.reg64;
    rflags_to_lflags(env);
}

static int get_standard_regs(CPUState *cpu)
{
    struct hv_register_assoc assocs[ARRAY_SIZE(STANDARD_REGISTER_NAMES)];
    int ret;
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    size_t n_regs = ARRAY_SIZE(STANDARD_REGISTER_NAMES);

    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = STANDARD_REGISTER_NAMES[i];
    }
    ret = get_generic_regs(cpu, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to get standard registers");
        return -1;
    }

    populate_standard_regs(assocs, env);
    return 0;
}

static inline void populate_segment_reg(const hv_x64_segment_register *hv_seg,
                                        SegmentCache *seg)
{
    memset(seg, 0, sizeof(SegmentCache));

    seg->base = hv_seg->base;
    seg->limit = hv_seg->limit;
    seg->selector = hv_seg->selector;

    seg->flags = (hv_seg->segment_type << DESC_TYPE_SHIFT)
                 | (hv_seg->present * DESC_P_MASK)
                 | (hv_seg->descriptor_privilege_level << DESC_DPL_SHIFT)
                 | (hv_seg->_default << DESC_B_SHIFT)
                 | (hv_seg->non_system_segment * DESC_S_MASK)
                 | (hv_seg->_long << DESC_L_SHIFT)
                 | (hv_seg->granularity * DESC_G_MASK)
                 | (hv_seg->available * DESC_AVL_MASK);

}

static inline void populate_table_reg(const hv_x64_table_register *hv_seg,
                                      SegmentCache *tbl)
{
    memset(tbl, 0, sizeof(SegmentCache));

    tbl->base = hv_seg->base;
    tbl->limit = hv_seg->limit;
}

static void populate_special_regs(const hv_register_assoc *assocs,
                                  X86CPU *x86cpu)
{
    CPUX86State *env = &x86cpu->env;

    populate_segment_reg(&assocs[0].value.segment, &env->segs[R_CS]);
    populate_segment_reg(&assocs[1].value.segment, &env->segs[R_DS]);
    populate_segment_reg(&assocs[2].value.segment, &env->segs[R_ES]);
    populate_segment_reg(&assocs[3].value.segment, &env->segs[R_FS]);
    populate_segment_reg(&assocs[4].value.segment, &env->segs[R_GS]);
    populate_segment_reg(&assocs[5].value.segment, &env->segs[R_SS]);

    populate_segment_reg(&assocs[6].value.segment, &env->tr);
    populate_segment_reg(&assocs[7].value.segment, &env->ldt);

    populate_table_reg(&assocs[8].value.table, &env->gdt);
    populate_table_reg(&assocs[9].value.table, &env->idt);

    env->cr[0] = assocs[10].value.reg64;
    env->cr[2] = assocs[11].value.reg64;
    env->cr[3] = assocs[12].value.reg64;
    env->cr[4] = assocs[13].value.reg64;

    cpu_set_apic_tpr(x86cpu->apic_state, assocs[14].value.reg64);
    env->efer = assocs[15].value.reg64;
    cpu_set_apic_base(x86cpu->apic_state, assocs[16].value.reg64);
}

static int get_special_regs(CPUState *cpu)
{
    struct hv_register_assoc assocs[ARRAY_SIZE(SPECIAL_REGISTER_NAMES)];
    int ret;
    X86CPU *x86cpu = X86_CPU(cpu);
    size_t n_regs = ARRAY_SIZE(SPECIAL_REGISTER_NAMES);

    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = SPECIAL_REGISTER_NAMES[i];
    }
    ret = get_generic_regs(cpu, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to get special registers");
        return -errno;
    }

    populate_special_regs(assocs, x86cpu);
    return 0;
}

static int load_regs(CPUState *cpu)
{
    int ret;

    ret = get_standard_regs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_special_regs(cpu);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int update_hflags(CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;

    x86_update_hflags(env);

    return 0;
}

int mshv_arch_load_vcpu_state(CPUState *cpu) {
    int ret;

    ret = get_standard_regs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_special_regs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_xc_reg(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_fpu(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_xsave_state(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_msrs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_lapic(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = get_synic_state(cpu);
    if (ret < 0) {
        return ret;
    }

    update_hflags(cpu);

    return 0;
}

static void add_cpuid_entry(GList **cpuid_entries,
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

    *cpuid_entries = g_list_append(*cpuid_entries, entry);
}

static void collect_cpuid_entries(const CPUState *cpu, GList **cpuid_entries)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    uint32_t eax, ebx, ecx, edx;
    uint32_t leaf, subleaf;
    uint32_t max_basic_leaf, max_extended_leaf;
    uint32_t max_subleaf = 0x20;
    uint32_t leaves_with_subleaves[] = {0x04, 0x07, 0x0d, 0x0f, 0x10};
    int n_subleaf_leaves = ARRAY_SIZE(leaves_with_subleaves);

    /* Get maximum basic and and extended CPUID leaves */
    cpu_x86_cpuid(env, 0, 0, &max_basic_leaf, &ebx, &ecx, &edx);
    cpu_x86_cpuid(env, 0x80000000, 0, &max_extended_leaf, &ebx, &ecx, &edx);

    /* Collect basic leaves (0x0 to max_basic_leaf) */
    for (leaf = 0; leaf <= max_basic_leaf; leaf++) {
        bool has_subleaves = false;
        for (int i = 0; i < n_subleaf_leaves; i++) {
            if (leaf == leaves_with_subleaves[i]) {
                has_subleaves = true;
                break;
            }
        }

        if (!has_subleaves) {
            cpu_x86_cpuid(env, leaf, 0, &eax, &ebx, &ecx, &edx);
            add_cpuid_entry(cpuid_entries, leaf, 0, eax, ebx, ecx, edx);
            continue;
        }

        subleaf = 0;
        while (subleaf < max_subleaf) {
            cpu_x86_cpuid(env, leaf, subleaf, &eax, &ebx, &ecx, &edx);

            if (eax == 0 && ebx == 0 && ecx == 0 && edx == 0) {
                /* XSAVE */
                if (leaf == 0x0d) {
                    /* Subleaf 0 all-zeros means XSAVE disabled.
                     * Still register it to override hypervisor defaults.
                     * Continue to register all subleaves up to 63.
                     */
                    while (subleaf <= 63) {
                        add_cpuid_entry(cpuid_entries, 0x0d, subleaf,
                                        0, 0, 0, 0);
                        subleaf++;
                    }
                }
                break;
            }
            add_cpuid_entry(cpuid_entries, leaf, subleaf, eax, ebx, ecx, edx);
            subleaf++;
        }
    }

    /* Collect extended leaves (0x80000000 to max_extended_leaf) */
    for (leaf = 0x80000000; leaf <= max_extended_leaf; leaf++) {
        cpu_x86_cpuid(env, leaf, 0, &eax, &ebx, &ecx, &edx);
        add_cpuid_entry(cpuid_entries, leaf, 0, eax, ebx, ecx, edx);
    }
}

static int register_intercept_result_cpuid_entry(const CPUState *cpu,
                                                 uint8_t subleaf_specific,
                                                 uint8_t always_override,
                                                 struct hv_cpuid_entry *entry)
{
    int ret;
    int vp_index = cpu->cpu_index;
    int cpu_fd = mshv_vcpufd(cpu);

    struct hv_register_x64_cpuid_result_parameters cpuid_params = {
        .input.eax = entry->function,
        .input.ecx = entry->index,
        .input.subleaf_specific = subleaf_specific,
        .input.always_override = always_override,
        .input.padding = 0,
        /*
         * Masks specify which bits to override. Set to 0xFFFFFFFF to
         * override all bits with the values from the QEMU CPU model.
         */
        .result.eax = entry->eax,
        .result.eax_mask = 0xFFFFFFFF,
        .result.ebx = entry->ebx,
        .result.ebx_mask = 0xFFFFFFFF,
        .result.ecx = entry->ecx,
        .result.ecx_mask = 0xFFFFFFFF,
        .result.edx = entry->edx,
        .result.edx_mask = 0xFFFFFFFF,
    };
    union hv_register_intercept_result_parameters parameters = {
        .cpuid = cpuid_params,
    };

    hv_input_register_intercept_result in = {0};
    in.vp_index = vp_index;
    in.intercept_type = HV_INTERCEPT_TYPE_X64_CPUID;
    in.parameters = parameters;

    struct mshv_root_hvcall args = {0};
    args.code   = HVCALL_REGISTER_INTERCEPT_RESULT;
    args.in_sz  = sizeof(in);
    args.in_ptr = (uint64_t)&in;

    ret = mshv_hvcall(cpu_fd, &args);
    if (ret < 0) {
        error_report("failed to register intercept result for cpuid");
        return -1;
    }

    return 0;
}

static int register_intercept_result_cpuid(const CPUState *cpu,
                                           struct hv_cpuid *cpuid)
{
    int ret = 0, entry_ret;
    struct hv_cpuid_entry *entry;
    uint8_t subleaf_specific, always_override;

    for (size_t i = 0; i < cpuid->nent; i++) {
        entry = &cpuid->entries[i];

        /* set defaults */
        subleaf_specific = 0;
        always_override = 1;

        /*
         * Intel
         * 0xb - Extended Topology Enumeration Leaf
         * 0x1f - V2 Extended Topology Enumeration Leaf
         * AMD
         * 0x8000_001e - Processor Topology Information
         * 0x8000_0026 - Extended CPU Topology
         */
        if (entry->function == 0xb ||
            entry->function == 0x1f ||
            entry->function == 0x8000001e ||
            entry->function == 0x80000026) {
            subleaf_specific = 1;
            always_override = 1;
        /*
         * Feature enumeration leaves (subleaf-specific)
         * 0x04: Deterministic Cache Parameters
         * 0x07: Structured Extended Feature Flags
         * 0x0D: Processor Extended State Enumeration
         * 0x0F: Platform QoS Monitoring
         * 0x10: Platform QoS Enforcement
         */
        } else if (entry->function == 0x04 ||
                   entry->function == 0x07 ||
                   entry->function == 0x0d ||
                   entry->function == 0x0f ||
                   entry->function == 0x10) {
            subleaf_specific = 1;
            always_override = 1;
        /* Basic feature leaves (no subleaves) */
        } else if (entry->function == 0x00000001 ||
                   entry->function == 0x80000000 ||
                   entry->function == 0x80000001 ||
                   entry->function == 0x80000008) {
            subleaf_specific = 0;
            always_override = 1;
        }

        entry_ret = register_intercept_result_cpuid_entry(cpu, subleaf_specific,
                                                          always_override,
                                                          entry);
        if ((entry_ret < 0) && (ret == 0)) {
            ret = entry_ret;
        }
    }

    return ret;
}

static int init_cpuid2(const CPUState *cpu)
{
    int ret;
    size_t n_entries, cpuid_size;
    struct hv_cpuid *cpuid;
    struct hv_cpuid_entry *entry;
    GList *entries = NULL;

    collect_cpuid_entries(cpu, &entries);
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

    ret = register_intercept_result_cpuid(cpu, cpuid);
    g_free(cpuid);
    if (ret < 0) {
        error_report("failed to set cpuid");
        return ret;
    }

    return 0;
}

static inline void populate_hv_segment_reg(SegmentCache *seg,
                                           hv_x64_segment_register *hv_reg)
{
    uint32_t flags = seg->flags;

    hv_reg->base = seg->base;
    hv_reg->limit = seg->limit;
    hv_reg->selector = seg->selector;
    hv_reg->segment_type = (flags >> DESC_TYPE_SHIFT) & 0xF;
    hv_reg->non_system_segment = (flags & DESC_S_MASK) != 0;
    hv_reg->descriptor_privilege_level = (flags >> DESC_DPL_SHIFT) & 0x3;
    hv_reg->present = (flags & DESC_P_MASK) != 0;
    hv_reg->reserved = 0;
    hv_reg->available = (flags & DESC_AVL_MASK) != 0;
    hv_reg->_long = (flags >> DESC_L_SHIFT) & 0x1;
    hv_reg->_default = (flags >> DESC_B_SHIFT) & 0x1;
    hv_reg->granularity = (flags & DESC_G_MASK) != 0;
}

static inline void populate_hv_table_reg(const struct SegmentCache *seg,
                                         hv_x64_table_register *hv_reg)
{
    memset(hv_reg, 0, sizeof(*hv_reg));

    hv_reg->base = seg->base;
    hv_reg->limit = seg->limit;
}

static int set_special_regs(const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    struct hv_register_assoc assocs[ARRAY_SIZE(SPECIAL_REGISTER_NAMES)];
    size_t n_regs = ARRAY_SIZE(SPECIAL_REGISTER_NAMES);
    int ret;

    /* set names */
    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = SPECIAL_REGISTER_NAMES[i];
    }
    populate_hv_segment_reg(&env->segs[R_CS], &assocs[0].value.segment);
    populate_hv_segment_reg(&env->segs[R_DS], &assocs[1].value.segment);
    populate_hv_segment_reg(&env->segs[R_ES], &assocs[2].value.segment);
    populate_hv_segment_reg(&env->segs[R_FS], &assocs[3].value.segment);
    populate_hv_segment_reg(&env->segs[R_GS], &assocs[4].value.segment);
    populate_hv_segment_reg(&env->segs[R_SS], &assocs[5].value.segment);
    populate_hv_segment_reg(&env->tr, &assocs[6].value.segment);
    populate_hv_segment_reg(&env->ldt, &assocs[7].value.segment);

    populate_hv_table_reg(&env->gdt, &assocs[8].value.table);
    populate_hv_table_reg(&env->idt, &assocs[9].value.table);

    assocs[10].value.reg64 = env->cr[0];
    assocs[11].value.reg64 = env->cr[2];
    assocs[12].value.reg64 = env->cr[3];
    assocs[13].value.reg64 = env->cr[4];
    assocs[14].value.reg64 = cpu_get_apic_tpr(x86cpu->apic_state);
    assocs[15].value.reg64 = env->efer;
    assocs[16].value.reg64 = cpu_get_apic_base(x86cpu->apic_state);

    ret = set_generic_regs(cpu, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to set special registers");
        return -1;
    }

    return 0;
}

static int set_fpu(const CPUState *cpu)
{
    struct hv_register_assoc assocs[ARRAY_SIZE(FPU_REGISTER_NAMES)];
    union hv_register_value *value;
    union hv_x64_fp_control_status_register *ctrl_status;
    union hv_x64_xmm_control_status_register *xmm_ctrl_status;
    int ret;
    size_t n_regs = ARRAY_SIZE(FPU_REGISTER_NAMES);
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    size_t i, fp_i;
    bool valid;

    /* first 16 registers are xmm0-xmm15 */
    for (i = 0; i < 16; i++) {
        assocs[i].name = FPU_REGISTER_NAMES[i];
        value = &assocs[i].value;
        value->reg128.low_part  = env->xmm_regs[i].ZMM_Q(0);
        value->reg128.high_part = env->xmm_regs[i].ZMM_Q(1);
    }

    /* next 8 registers are fp_mmx0-fp_mmx7 */
    for (i = 16; i < 24; i++) {
        fp_i = (i - 16);
        assocs[i].name = FPU_REGISTER_NAMES[i];
        value = &assocs[i].value;
        value->fp.mantissa        = env->fpregs[fp_i].d.low;
        value->fp.biased_exponent = env->fpregs[fp_i].d.high & 0x7FFF;
        value->fp.sign            = (env->fpregs[fp_i].d.high >> 15) & 0x1;
        value->fp.reserved        = 0;
    }

    /* last two registers are fp_control_status and xmm_control_status */
    assocs[24].name = FPU_REGISTER_NAMES[24];
    value = &assocs[24].value;
    ctrl_status = &value->fp_control_status;

    ctrl_status->fp_control = env->fpuc;
    /* bits 11,12,13 are the top of stack pointer */
    ctrl_status->fp_status = (env->fpus & ~0x3800) | ((env->fpstt & 0x7) << 11);

    ctrl_status->fp_tag = 0;
    for (i = 0; i < 8; i++) {
        valid = (env->fptags[i] == 0);
        if (valid) {
            ctrl_status->fp_tag |= (1u << i);
        }
    }

    ctrl_status->reserved = 0;
    ctrl_status->last_fp_op = env->fpop;
    ctrl_status->last_fp_rip = env->fpip;

    assocs[25].name = FPU_REGISTER_NAMES[25];
    value = &assocs[25].value;
    xmm_ctrl_status = &value->xmm_control_status;
    xmm_ctrl_status->xmm_status_control = env->mxcsr;
    xmm_ctrl_status->xmm_status_control_mask = 0x0000ffff;
    xmm_ctrl_status->last_fp_rdp = env->fpdp;

    ret = set_generic_regs(cpu, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to set fpu registers");
        return -1;
    }

    return 0;
}

static int set_xc_reg(const CPUState *cpu)
{
    int ret;
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;

    struct hv_register_assoc assoc = {
        .name = HV_X64_REGISTER_XFEM,
        .value.reg64 = env->xcr0,
    };

    ret = set_generic_regs(cpu, &assoc, 1);
    if (ret < 0) {
        error_report("failed to set xcr0");
        return -errno;
    }
    return 0;
}

static uint32_t set_apic_delivery_mode(uint32_t reg, uint32_t mode)
{
    return ((reg) & ~0x700) | ((mode) << 8);
}

static int init_lint(const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    APICCommonState *apic = APIC_COMMON(x86cpu->apic_state);
    uint32_t *lvt_lint0, *lvt_lint1;
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;

    struct hv_local_interrupt_controller_state lapic_state = { 0 };
    ret = mshv_get_lapic(cpu_fd, &lapic_state);
    if (ret < 0) {
        return ret;
    }

    lvt_lint0 = &lapic_state.apic_lvt_lint0;
    *lvt_lint0 = set_apic_delivery_mode(*lvt_lint0, APIC_DM_EXTINT);

    lvt_lint1 = &lapic_state.apic_lvt_lint1;
    *lvt_lint1 = set_apic_delivery_mode(*lvt_lint1, APIC_DM_NMI);

    ret = mshv_set_lapic(cpu_fd, &lapic_state);
    if (ret < 0) {
        return -1;
    }

    memcpy(apic->hv_lapic_state, &lapic_state, sizeof(lapic_state));

    return 0;
}

static int set_msrs(const CPUState *cpu)
{
    int ret = 0;
    size_t n_assocs = mshv_msr_mappable_reg_count();
    struct hv_register_assoc *assocs;
    size_t i, j;

    assocs = g_new0(struct hv_register_assoc, n_assocs);
    mshv_msr_load_from_env(cpu, assocs, n_assocs);

    /* Filter out MSRs that cannot be written at boot */
    X86CPU *x86cpu = X86_CPU(cpu);
    bool synic_enabled = x86cpu->env.msr_hv_synic_control & 1;
    for (i = 0, j = 0; i < n_assocs; i++) {
        uint32_t name = assocs[i].name;

        /* Partition-wide MSR: only write on vCPU 0 */
        if (cpu->cpu_index != 0 && name == HV_X64_REGISTER_HYPERCALL) {
            continue;
        }

        /* SINT MSRs: only write if SynIC is enabled */
        if (name >= HV_REGISTER_SINT0 && name <= HV_REGISTER_SINT15 &&
            !synic_enabled) {
            continue;
        }

        if (j != i) {
            assocs[j] = assocs[i];
        }
        j++;
    }
    n_assocs = j;

    ret = set_generic_regs(cpu, assocs, n_assocs);
    g_free(assocs);
    if (ret < 0) {
        error_report("failed to put msrs");
        return -1;
    }

    return 0;
}

static int set_lapic(const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    APICCommonState *apic = APIC_COMMON(x86cpu->apic_state);
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;

    struct hv_local_interrupt_controller_state lapic_state = { 0 };
    memcpy(&lapic_state, &apic->hv_lapic_state, sizeof(lapic_state));
    ret = mshv_set_lapic(cpu_fd, &lapic_state);
    if (ret < 0) {
        error_report("failed to set lapic");
        return -1;
    }

    return 0;
}

static int set_synic_state(const CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    int cpu_fd = mshv_vcpufd(cpu);
    int ret;

    ret = mshv_set_simp(cpu_fd, env->hv_simp_page);
    if (ret < 0) {
        error_report("failed to set simp state");
        return -1;
    }

    ret = mshv_set_siefp(cpu_fd, env->hv_siefp_page);
    if (ret < 0) {
        error_report("failed to set siefp state");
        return -1;
    }

    return 0;
}

int mshv_arch_store_vcpu_state(const CPUState *cpu)
{
    int ret;

    ret = set_standard_regs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_special_regs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_xc_reg(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_fpu(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_xsave_state(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_msrs(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_lapic(cpu);
    if (ret < 0) {
        return ret;
    }

    ret = set_synic_state(cpu);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

void mshv_arch_amend_proc_features(
    union hv_partition_synthetic_processor_features *features)
{
    features->access_guest_idle_reg = 1;
}

static int set_memory_info(const struct hyperv_message *msg,
                           struct hv_x64_memory_intercept_message *info)
{
    if (msg->header.message_type != HVMSG_GPA_INTERCEPT
            && msg->header.message_type != HVMSG_UNMAPPED_GPA
            && msg->header.message_type != HVMSG_UNACCEPTED_GPA) {
        error_report("invalid message type");
        return -1;
    }
    memcpy(info, msg->payload, sizeof(*info));

    return 0;
}

static int emulate_instruction(CPUState *cpu,
                               const uint8_t *insn_bytes, size_t insn_len,
                               uint64_t gva, uint64_t gpa)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    struct x86_decode decode = { 0 };
    int ret;
    x86_insn_stream stream = { .bytes = insn_bytes, .len = insn_len };

    ret = load_regs(cpu);
    if (ret < 0) {
        error_report("Failed to load registers");
        return -1;
    }

    decode_instruction_stream(env, &decode, &stream);
    exec_instruction(env, &decode);

    ret = store_regs(cpu);
    if (ret < 0) {
        error_report("failed to store registers");
        return -1;
    }

    return 0;
}

static int handle_mmio(CPUState *cpu, const struct hyperv_message *msg,
                       MshvVmExit *exit_reason)
{
    struct hv_x64_memory_intercept_message info = { 0 };
    size_t insn_len;
    uint8_t access_type;
    uint8_t *instruction_bytes;
    int ret;

    ret = set_memory_info(msg, &info);
    if (ret < 0) {
        error_report("failed to convert message to memory info");
        return -1;
    }
    insn_len = info.instruction_byte_count;
    access_type = info.header.intercept_access_type;

    if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_EXECUTE) {
        error_report("invalid intercept access type: execute");
        return -1;
    }

    if (insn_len > 16) {
        error_report("invalid mmio instruction length: %zu", insn_len);
        return -1;
    }

    trace_mshv_handle_mmio(info.guest_virtual_address,
                           info.guest_physical_address,
                           info.instruction_byte_count, access_type);

    instruction_bytes = info.instruction_bytes;

    ret = emulate_instruction(cpu, instruction_bytes, insn_len,
                              info.guest_virtual_address,
                              info.guest_physical_address);
    if (ret < 0) {
        error_report("failed to emulate mmio");
        return -1;
    }

    *exit_reason = MshvVmExitIgnore;

    return 0;
}

static int set_ioport_info(const struct hyperv_message *msg,
                           hv_x64_io_port_intercept_message *info)
{
    if (msg->header.message_type != HVMSG_X64_IO_PORT_INTERCEPT) {
        error_report("Invalid message type");
        return -1;
    }
    memcpy(info, msg->payload, sizeof(*info));

    return 0;
}

static int set_x64_registers(const CPUState *cpu, const uint32_t *names,
                             const uint64_t *values)
{

    hv_register_assoc assocs[2];
    int ret;

    for (size_t i = 0; i < ARRAY_SIZE(assocs); i++) {
        assocs[i].name = names[i];
        assocs[i].value.reg64 = values[i];
    }

    ret = set_generic_regs(cpu, assocs, ARRAY_SIZE(assocs));
    if (ret < 0) {
        error_report("failed to set x64 registers");
        return -1;
    }

    return 0;
}

static inline MemTxAttrs get_mem_attrs(bool is_secure_mode)
{
    MemTxAttrs memattr = {0};
    memattr.secure = is_secure_mode;
    return memattr;
}

static void pio_read(uint64_t port, uint8_t *data, uintptr_t size,
                     bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           false);
    if (ret != MEMTX_OK) {
        error_report("Failed to read from port %lx: %d", port, ret);
        abort();
    }
}

static int pio_write(uint64_t port, const uint8_t *data, uintptr_t size,
                     bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           true);
    return ret;
}

static int handle_pio_non_str(const CPUState *cpu,
                              hv_x64_io_port_intercept_message *info)
{
    size_t len = info->access_info.access_size;
    uint8_t access_type = info->header.intercept_access_type;
    int ret;
    uint32_t val, eax;
    const uint32_t eax_mask =  0xffffffffu >> (32 - len * 8);
    size_t insn_len;
    uint64_t rip, rax;
    uint32_t reg_names[2];
    uint64_t reg_values[2];
    uint16_t port = info->port_number;

    if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_WRITE) {
        union {
            uint32_t u32;
            uint8_t bytes[4];
        } conv;

        /* convert the first 4 bytes of rax to bytes */
        conv.u32 = (uint32_t)info->rax;
        /* secure mode is set to false */
        ret = pio_write(port, conv.bytes, len, false);
        if (ret < 0) {
            error_report("Failed to write to io port");
            return -1;
        }
    } else {
        uint8_t data[4] = { 0 };
        /* secure mode is set to false */
        pio_read(info->port_number, data, len, false);

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

    ret = set_x64_registers(cpu, reg_names, reg_values);
    if (ret < 0) {
        error_report("Failed to set x64 registers");
        return -1;
    }

    cpu->accel->dirty = false;

    return 0;
}

static int read_memory(const CPUState *cpu, uint64_t initial_gva,
                       uint64_t initial_gpa, uint64_t gva, uint8_t *data,
                       size_t len)
{
    int ret;
    uint64_t gpa, flags;

    if (gva == initial_gva) {
        gpa = initial_gpa;
    } else {
        flags = HV_TRANSLATE_GVA_VALIDATE_READ;
        ret = translate_gva(cpu, gva, &gpa, flags);
        if (ret < 0) {
            return -1;
        }

        ret = mshv_guest_mem_read(gpa, data, len, false, false);
        if (ret < 0) {
            error_report("failed to read guest mem");
            return -1;
        }
    }

    return 0;
}

static int write_memory(const CPUState *cpu, uint64_t initial_gva,
                        uint64_t initial_gpa, uint64_t gva, const uint8_t *data,
                        size_t len)
{
    int ret;
    uint64_t gpa, flags;

    if (gva == initial_gva) {
        gpa = initial_gpa;
    } else {
        flags = HV_TRANSLATE_GVA_VALIDATE_WRITE;
        ret = translate_gva(cpu, gva, &gpa, flags);
        if (ret < 0) {
            error_report("failed to translate gva to gpa");
            return -1;
        }
    }
    ret = mshv_guest_mem_write(gpa, data, len, false);
    if (ret != MEMTX_OK) {
        error_report("failed to write to mmio");
        return -1;
    }

    return 0;
}

static int handle_pio_str_write(CPUState *cpu,
                                hv_x64_io_port_intercept_message *info,
                                size_t repeat, uint16_t port,
                                bool direction_flag)
{
    int ret;
    uint64_t src;
    uint8_t data[4] = { 0 };
    size_t len = info->access_info.access_size;

    src = linear_addr(cpu, info->rsi, R_DS);

    for (size_t i = 0; i < repeat; i++) {
        ret = read_memory(cpu, 0, 0, src, data, len);
        if (ret < 0) {
            error_report("Failed to read memory");
            return -1;
        }
        ret = pio_write(port, data, len, false);
        if (ret < 0) {
            error_report("Failed to write to io port");
            return -1;
        }
        src += direction_flag ? -len : len;
        info->rsi += direction_flag ? -len : len;
    }

    return 0;
}

static int handle_pio_str_read(CPUState *cpu,
                               hv_x64_io_port_intercept_message *info,
                               size_t repeat, uint16_t port,
                               bool direction_flag)
{
    int ret;
    uint64_t dst;
    size_t len = info->access_info.access_size;
    uint8_t data[4] = { 0 };

    dst = linear_addr(cpu, info->rdi, R_ES);

    for (size_t i = 0; i < repeat; i++) {
        pio_read(port, data, len, false);

        ret = write_memory(cpu, 0, 0, dst, data, len);
        if (ret < 0) {
            error_report("Failed to write memory");
            return -1;
        }
        dst += direction_flag ? -len : len;
        info->rdi += direction_flag ? -len : len;
    }

    return 0;
}

static int handle_pio_str(CPUState *cpu, hv_x64_io_port_intercept_message *info)
{
    uint8_t access_type = info->header.intercept_access_type;
    uint16_t port = info->port_number;
    bool repop = info->access_info.rep_prefix == 1;
    size_t repeat = repop ? info->rcx : 1;
    size_t insn_len = info->header.instruction_length;
    bool direction_flag;
    uint32_t reg_names[3];
    uint64_t reg_values[3];
    int ret;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;

    ret = load_regs(cpu);
    if (ret < 0) {
        error_report("Failed to load registers");
        return -1;
    }

    direction_flag = (env->eflags & DESC_E_MASK) != 0;

    if (access_type == HV_X64_INTERCEPT_ACCESS_TYPE_WRITE) {
        ret = handle_pio_str_write(cpu, info, repeat, port, direction_flag);
        if (ret < 0) {
            error_report("Failed to handle pio str write");
            return -1;
        }
        reg_names[0] = HV_X64_REGISTER_RSI;
        reg_values[0] = info->rsi;
    } else {
        ret = handle_pio_str_read(cpu, info, repeat, port, direction_flag);
        if (ret < 0) {
            error_report("Failed to handle pio str read");
            return -1;
        }
        reg_names[0] = HV_X64_REGISTER_RDI;
        reg_values[0] = info->rdi;
    }

    reg_names[1] = HV_X64_REGISTER_RIP;
    reg_values[1] = info->header.rip + insn_len;
    reg_names[2] = HV_X64_REGISTER_RAX;
    reg_values[2] = info->rax;

    ret = set_x64_registers(cpu, reg_names, reg_values);
    if (ret < 0) {
        error_report("Failed to set RIP and RAX registers");
        return -1;
    }

    cpu->accel->dirty = false;

    return 0;
}

static int handle_pio(CPUState *cpu, const struct hyperv_message *msg)
{
    struct hv_x64_io_port_intercept_message info = { 0 };
    int ret;

    ret = set_ioport_info(msg, &info);
    if (ret < 0) {
        error_report("Failed to convert message to ioport info");
        return -1;
    }

    if (info.access_info.string_op) {
        return handle_pio_str(cpu, &info);
    }

    return handle_pio_non_str(cpu, &info);
}

int mshv_run_vcpu(int vm_fd, CPUState *cpu, hv_message *msg, MshvVmExit *exit)
{
    int ret;
    enum MshvVmExit exit_reason;
    int cpu_fd = mshv_vcpufd(cpu);

    ret = ioctl(cpu_fd, MSHV_RUN_VP, msg);
    if (ret < 0) {
        return MshvVmExitShutdown;
    }

    switch (msg->header.message_type) {
    case HVMSG_UNRECOVERABLE_EXCEPTION:
        return MshvVmExitShutdown;
    case HVMSG_UNMAPPED_GPA:
    case HVMSG_GPA_INTERCEPT:
        ret = handle_mmio(cpu, msg, &exit_reason);
        if (ret < 0) {
            error_report("failed to handle mmio");
            return -1;
        }
        return exit_reason;
    case HVMSG_X64_IO_PORT_INTERCEPT:
        ret = handle_pio(cpu, msg);
        if (ret < 0) {
            return MshvVmExitSpecial;
        }
        return MshvVmExitIgnore;
    default:
        break;
    }

    *exit = MshvVmExitIgnore;
    return 0;
}

void mshv_remove_vcpu(int vm_fd, int cpu_fd)
{
    close(cpu_fd);
}


int mshv_create_vcpu(int vm_fd, uint8_t vp_index, int *cpu_fd)
{
    int ret;
    struct mshv_create_vp vp_arg = {
        .vp_index = vp_index,
    };
    ret = ioctl(vm_fd, MSHV_CREATE_VP, &vp_arg);
    if (ret < 0) {
        error_report("failed to create mshv vcpu: %s", strerror(errno));
        return -1;
    }

    *cpu_fd = ret;

    return 0;
}

static int guest_mem_read_with_gva(const CPUState *cpu, uint64_t gva,
                                   uint8_t *data, uintptr_t size,
                                   bool fetch_instruction)
{
    int ret;
    uint64_t gpa, flags;

    flags = HV_TRANSLATE_GVA_VALIDATE_READ;
    ret = translate_gva(cpu, gva, &gpa, flags);
    if (ret < 0) {
        error_report("failed to translate gva to gpa");
        return -1;
    }

    ret = mshv_guest_mem_read(gpa, data, size, false, fetch_instruction);
    if (ret < 0) {
        error_report("failed to read from guest memory");
        return -1;
    }

    return 0;
}

static int guest_mem_write_with_gva(const CPUState *cpu, uint64_t gva,
                                    const uint8_t *data, uintptr_t size)
{
    int ret;
    uint64_t gpa, flags;

    flags = HV_TRANSLATE_GVA_VALIDATE_WRITE;
    ret = translate_gva(cpu, gva, &gpa, flags);
    if (ret < 0) {
        error_report("failed to translate gva to gpa");
        return -1;
    }
    ret = mshv_guest_mem_write(gpa, data, size, false);
    if (ret < 0) {
        error_report("failed to write to guest memory");
        return -1;
    }
    return 0;
}

static void write_mem(CPUState *cpu, void *data, target_ulong addr, int bytes)
{
    if (guest_mem_write_with_gva(cpu, addr, data, bytes) < 0) {
        error_report("failed to write memory");
        abort();
    }
}

static void fetch_instruction(CPUState *cpu, void *data,
                              target_ulong addr, int bytes)
{
    if (guest_mem_read_with_gva(cpu, addr, data, bytes, true) < 0) {
        error_report("failed to fetch instruction");
        abort();
    }
}

static void read_mem(CPUState *cpu, void *data, target_ulong addr, int bytes)
{
    if (guest_mem_read_with_gva(cpu, addr, data, bytes, false) < 0) {
        error_report("failed to read memory");
        abort();
    }
}

static void read_segment_descriptor(CPUState *cpu,
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

static const struct x86_emul_ops mshv_x86_emul_ops = {
    .fetch_instruction = fetch_instruction,
    .read_mem = read_mem,
    .write_mem = write_mem,
    .read_segment_descriptor = read_segment_descriptor,
};

void mshv_init_mmio_emu(void)
{
    init_decoder();
    init_emu(&mshv_x86_emul_ops);
}

static int init_msrs(const CPUState *cpu)
{
    int ret;
    uint64_t d_t = MSR_MTRR_ENABLE | MSR_MTRR_MEM_TYPE_WB;

    const struct hv_register_assoc assocs[] = {
        { .name = HV_X64_REGISTER_SYSENTER_CS,       .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_SYSENTER_ESP,      .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_SYSENTER_EIP,      .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_STAR,              .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_CSTAR,             .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_LSTAR,             .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_KERNEL_GS_BASE,    .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_SFMASK,            .value.reg64 = 0x0 },
        { .name = HV_X64_REGISTER_MSR_MTRR_DEF_TYPE, .value.reg64 = d_t },
    };
    QEMU_BUILD_BUG_ON(ARRAY_SIZE(assocs) > MSHV_MSR_ENTRIES_COUNT);

    ret = set_generic_regs(cpu, assocs, ARRAY_SIZE(assocs));
    if (ret < 0) {
        error_report("failed to put msrs");
        return -1;
    }

    return 0;
}

void mshv_arch_init_vcpu(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    AccelCPUState *state = cpu->accel;
    size_t page = HV_HYP_PAGE_SIZE, xsave_len;
    void *mem = qemu_memalign(page, 2 * page);
    int ret;
    X86XSaveHeader *header;

    /* sanity check, to make sure we don't overflow the page */
    QEMU_BUILD_BUG_ON((MAX_REGISTER_COUNT
                      * sizeof(hv_register_assoc)
                      + sizeof(hv_input_get_vp_registers)
                      > HV_HYP_PAGE_SIZE));

    state->hvcall_args.base = mem;
    state->hvcall_args.input_page = mem;
    state->hvcall_args.output_page = (uint8_t *)mem + page;

    /* buffer for mmio instructions */
    env->emu_mmio_buf = g_new(char, 4096);
    /* enable x2apic feature statically */
    env->features[FEAT_1_ECX] |= CPUID_EXT_X2APIC;

    /* Initialize XSAVE buffer page-aligned */
    /* TODO: pick proper size based on CPUID */
    xsave_len = page;
    env->xsave_buf = qemu_memalign(page, xsave_len);
    env->xsave_buf_len = xsave_len;
    memset(env->xsave_buf, 0, env->xsave_buf_len);

    /* we need to set the compacted format bit in xsave header for mshv */
    header = (X86XSaveHeader *)(env->xsave_buf + sizeof(X86LegacyXSaveArea));
    header->xcomp_bv = header->xstate_bv | (1ULL << 63);

    /*
     * TODO: populate topology info:
     * X86CPUTopoInfo *topo_info = &env->topo_info;
     */

    ret = init_cpuid2(cpu);
    assert(ret == 0);

    ret = init_msrs(cpu);
    assert(ret == 0);

    ret = init_lint(cpu);
    assert(ret == 0);
}

void mshv_arch_destroy_vcpu(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    AccelCPUState *state = cpu->accel;

    g_free(state->hvcall_args.base);
    state->hvcall_args = (MshvHvCallArgs){0};
    g_clear_pointer(&env->emu_mmio_buf, g_free);

    qemu_vfree(env->xsave_buf);
    env->xsave_buf = NULL;
    env->xsave_buf_len = 0;
}

uint32_t mshv_get_supported_cpuid(uint32_t func, uint32_t idx, int reg)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t ret = 0;

    host_cpuid(func, idx, &eax, &ebx, &ecx, &edx);
    switch (reg) {
    case R_EAX:
        ret = eax; break;
    case R_EBX:
        ret = ebx; break;
    case R_ECX:
        ret = ecx; break;
    case R_EDX:
        ret = edx; break;
    }

    /* Disable nested virtualization features not yet supported by MSHV */
    if (func == 0x80000001 && reg == R_ECX) {
        ret &= ~CPUID_EXT3_SVM;
    }
    if (func == 0x01       && reg == R_ECX) {
        ret &= ~CPUID_EXT_VMX;
    }
    return ret;
}

/*
 * Default Microsoft Hypervisor behavior for unimplemented MSR is to send a
 * fault to the guest if it tries to access it. It is possible to override
 * this behavior with a more suitable option i.e., ignore writes from the guest
 * and return zero in attempt to read unimplemented.
 */
static int set_unimplemented_msr_action(int vm_fd)
{
    struct hv_input_set_partition_property in = {0};
    struct mshv_root_hvcall args = {0};

    in.property_code  = HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION;
    in.property_value = HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO;

    args.code   = HVCALL_SET_PARTITION_PROPERTY;
    args.in_sz  = sizeof(in);
    args.in_ptr = (uint64_t)&in;

    trace_mshv_hvcall_args("unimplemented_msr_action", args.code, args.in_sz);

    int ret = mshv_hvcall(vm_fd, &args);
    if (ret < 0) {
        error_report("Failed to set unimplemented MSR action");
        return -1;
    }
    return 0;
}

int mshv_arch_post_init_vm(int vm_fd)
{
    int ret;

    ret = set_unimplemented_msr_action(vm_fd);
    if (ret < 0) {
        error_report("Failed to set unimplemented MSR action");
    }

    return ret;
}

static void mshv_cpu_instance_init(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);

    host_cpu_instance_init(cpu);
}

static void mshv_cpu_accel_class_init(ObjectClass *oc, const void *data)
{
    AccelCPUClass *acc = ACCEL_CPU_CLASS(oc);

    acc->cpu_instance_init = mshv_cpu_instance_init;
}

static const TypeInfo mshv_cpu_accel_type_info = {
    .name = ACCEL_CPU_NAME("mshv"),
    .parent = TYPE_ACCEL_CPU,
    .class_init = mshv_cpu_accel_class_init,
    .abstract = true,
};

static void mshv_cpu_accel_register_types(void)
{
    type_register_static(&mshv_cpu_accel_type_info);
}

type_init(mshv_cpu_accel_register_types);
