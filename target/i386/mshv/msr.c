/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors: Magnus Kulke  <magnuskulke@microsoft.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "system/mshv.h"
#include "system/mshv_int.h"
#include "hw/hyperv/hvgdk_mini.h"
#include "linux/mshv.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include <stddef.h>
#include <stdint.h>

#define MSHV_ENV_FIELD_32(env, offset) (*(uint32_t *)((char *)(env) + (offset)))
#define MSHV_ENV_FIELD_64(env, offset) (*(uint64_t *)((char *)(env) + (offset)))

enum MshvMsrWidth {
    MSHV_MSR_WIDTH_32 = 0,
    MSHV_MSR_WIDTH_64 = 1,
};

typedef struct MshvMsrEnvMap {
    uint32_t msr_index;
    uint32_t hv_name;
    ptrdiff_t env_offset;
    enum MshvMsrWidth width;
} MshvMsrEnvMap;

/*
 * Those MSRs have a direct mapping to fields in CPUX86State.
 * They are stored/restored when entering/exiting the guest.
 */
static const MshvMsrEnvMap msr_env_map[] = {
    /* Architectural */
    { IA32_MSR_EFER,         HV_X64_REGISTER_EFER,
      offsetof(CPUX86State, efer), MSHV_MSR_WIDTH_64 },
    { IA32_MSR_PAT,          HV_X64_REGISTER_PAT,
      offsetof(CPUX86State, pat) , MSHV_MSR_WIDTH_64 },
    /* Syscall */
    { IA32_MSR_SYSENTER_CS,  HV_X64_REGISTER_SYSENTER_CS,
      offsetof(CPUX86State, sysenter_cs),  MSHV_MSR_WIDTH_32 },
    { IA32_MSR_SYSENTER_ESP, HV_X64_REGISTER_SYSENTER_ESP,
      offsetof(CPUX86State, sysenter_esp), MSHV_MSR_WIDTH_64 },
    { IA32_MSR_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_EIP,
      offsetof(CPUX86State, sysenter_eip), MSHV_MSR_WIDTH_64 },
    { IA32_MSR_STAR,         HV_X64_REGISTER_STAR,
      offsetof(CPUX86State, star),         MSHV_MSR_WIDTH_64 },
    { IA32_MSR_LSTAR,        HV_X64_REGISTER_LSTAR,
      offsetof(CPUX86State, lstar),        MSHV_MSR_WIDTH_64 },
    { IA32_MSR_CSTAR,        HV_X64_REGISTER_CSTAR,
      offsetof(CPUX86State, cstar),        MSHV_MSR_WIDTH_64 },
    { IA32_MSR_SFMASK,       HV_X64_REGISTER_SFMASK,
      offsetof(CPUX86State, fmask),        MSHV_MSR_WIDTH_64 },
    { IA32_MSR_KERNEL_GS_BASE, HV_X64_REGISTER_KERNEL_GS_BASE,
      offsetof(CPUX86State, kernelgsbase), MSHV_MSR_WIDTH_64 },

    /* TSC-related */
    { IA32_MSR_TSC,          HV_X64_REGISTER_TSC,
      offsetof(CPUX86State, tsc),        MSHV_MSR_WIDTH_64 },
    { IA32_MSR_TSC_AUX,      HV_X64_REGISTER_TSC_AUX,
      offsetof(CPUX86State, tsc_aux),    MSHV_MSR_WIDTH_64 },
    /* { IA32_MSR_TSC_ADJUST,   HV_X64_REGISTER_TSC_ADJUST, */
    /*   offsetof(CPUX86State, tsc_adjust), MSHV_MSR_WIDTH_64 }, */

    /* Hyper-V per-partition MSRs */
    { HV_X64_MSR_HYPERCALL,  HV_X64_REGISTER_HYPERCALL,
      offsetof(CPUX86State, msr_hv_hypercall),   MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_GUEST_OS_ID, HV_REGISTER_GUEST_OS_ID,
      offsetof(CPUX86State, msr_hv_guest_os_id), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_REFERENCE_TSC, HV_REGISTER_REFERENCE_TSC,
      offsetof(CPUX86State, msr_hv_tsc),         MSHV_MSR_WIDTH_64 },

    /* Hyper-V MSRs (non-SINT) */
    { HV_X64_MSR_SCONTROL,  HV_REGISTER_SCONTROL,
      offsetof(CPUX86State, msr_hv_synic_control),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SIEFP,     HV_REGISTER_SIEFP,
      offsetof(CPUX86State, msr_hv_synic_evt_page), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SIMP,      HV_REGISTER_SIMP,
      offsetof(CPUX86State, msr_hv_synic_msg_page), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_EOM,       HV_REGISTER_EOM,
      offsetof(CPUX86State, msr_hv_eom),            MSHV_MSR_WIDTH_64 },

    /* Hyper-V SINT MSRs */
    { HV_X64_MSR_SINT0,  HV_REGISTER_SINT0,
      offsetof(CPUX86State, msr_hv_synic_sint[0]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT1,  HV_REGISTER_SINT1,
      offsetof(CPUX86State, msr_hv_synic_sint[1]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT2,  HV_REGISTER_SINT2,
      offsetof(CPUX86State, msr_hv_synic_sint[2]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT3,  HV_REGISTER_SINT3,
      offsetof(CPUX86State, msr_hv_synic_sint[3]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT4,  HV_REGISTER_SINT4,
      offsetof(CPUX86State, msr_hv_synic_sint[4]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT5,  HV_REGISTER_SINT5,
      offsetof(CPUX86State, msr_hv_synic_sint[5]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT6,  HV_REGISTER_SINT6,
      offsetof(CPUX86State, msr_hv_synic_sint[6]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT7,  HV_REGISTER_SINT7,
      offsetof(CPUX86State, msr_hv_synic_sint[7]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT8,  HV_REGISTER_SINT8,
      offsetof(CPUX86State, msr_hv_synic_sint[8]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT9,  HV_REGISTER_SINT9,
      offsetof(CPUX86State, msr_hv_synic_sint[9]),  MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT10, HV_REGISTER_SINT10,
      offsetof(CPUX86State, msr_hv_synic_sint[10]), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT11, HV_REGISTER_SINT11,
      offsetof(CPUX86State, msr_hv_synic_sint[11]), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT12, HV_REGISTER_SINT12,
      offsetof(CPUX86State, msr_hv_synic_sint[12]), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT13, HV_REGISTER_SINT13,
      offsetof(CPUX86State, msr_hv_synic_sint[13]), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT14, HV_REGISTER_SINT14,
      offsetof(CPUX86State, msr_hv_synic_sint[14]), MSHV_MSR_WIDTH_64 },
    { HV_X64_MSR_SINT15, HV_REGISTER_SINT15,
      offsetof(CPUX86State, msr_hv_synic_sint[15]), MSHV_MSR_WIDTH_64 },

    /* MTRR default type */
    { IA32_MSR_MTRR_DEF_TYPE, HV_X64_REGISTER_MSR_MTRR_DEF_TYPE,
      offsetof(CPUX86State, mtrr_deftype), MSHV_MSR_WIDTH_64 },

    /* Other */
    /* { IA32_MSR_MISC_ENABLE,  HV_X64_REGISTER_MSR_IA32_MISC_ENABLE, */
    /*   offsetof(CPUX86State, msr_ia32_misc_enable), MSHV_MSR_WIDTH_64 }, */

    /* { IA32_MSR_BNDCFGS,      HV_X64_REGISTER_BNDCFGS, */
    /*   offsetof(CPUX86State, msr_bndcfgs), MSHV_MSR_WIDTH_64 }, */

    { IA32_MSR_SPEC_CTRL,    HV_X64_REGISTER_SPEC_CTRL,
      offsetof(CPUX86State, spec_ctrl), MSHV_MSR_WIDTH_64 },
};

static size_t MTRR_MSR_COUNT  = 27;

/*
 * The assocs have to be set according to this schema:
 *      8  entries for 0-7 mtrr_base
 *      8  entries for mtrr_mask 0-7
 *      11 entries for 1 x 64k, 2 x 16k, 8 x 4k fixed MTRR
 *      27 total entries
 */

static void msr_store_in_env_mtrr_phys(CPUState *cpu,
                                       const struct hv_register_assoc *assocs,
                                       size_t n_assocs)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    size_t i, fixed_offset;
    hv_register_name hv_name;
    uint64_t base, mask;

    assert(n_assocs == MTRR_MSR_COUNT);

    for (i = 0; i < MSR_MTRRcap_VCNT; i++) {
        hv_name = HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0 + i;
        assert(assocs[i].name == hv_name);
        hv_name = HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0 + i;
        assert(assocs[i + MSR_MTRRcap_VCNT].name == hv_name);

        base = assocs[i].value.reg64;
        mask = assocs[i + MSR_MTRRcap_VCNT].value.reg64;
        env->mtrr_var[i].base = base;
        env->mtrr_var[i].mask = mask;
    }

    /* fixed 1x 64, 2x 16, 8x 4 kB */
    fixed_offset = MSR_MTRRcap_VCNT * 2;
    for (i = 0; i < 11; i++) {
        hv_name = HV_X64_REGISTER_MSR_MTRR_FIX64K00000 + i;
        assert(assocs[fixed_offset + i].name == hv_name);
        env->mtrr_fixed[i] = assocs[fixed_offset + i].value.reg64;
    }
}

/*
 * The assocs have to be set according to this schema:
 *      8  entries for 0-7 mtrr_base
 *      8  entries for mtrr_mask 0-7
 *      11 entries for 1 x 64k, 2 x 16k, 8 x 4k fixed MTRR
 *      27 total entries
 */
static void msr_load_from_env_mtrr_phys(const CPUState *cpu,
                                        struct hv_register_assoc *assocs,
                                        size_t n_assocs)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    size_t i, fixed_offset;
    uint64_t base, mask, fixed_value;
    hv_register_name base_name, mask_name, fixed_name;
    hv_register_assoc *assoc;

    assert(n_assocs == MTRR_MSR_COUNT);

    for (i = 0; i < MSR_MTRRcap_VCNT; i++) {
        base = env->mtrr_var[i].base;
        mask = env->mtrr_var[i].mask;

        base_name = HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0 + i;
        mask_name = HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0 + i;

        assoc = &assocs[i];
        assoc->name = base_name;
        assoc->value.reg64 = base;

        assoc = &assocs[i + MSR_MTRRcap_VCNT];
        assoc->name = mask_name;
        assoc->value.reg64 = mask;
    }

    /* fixed 1x 64, 2x 16, 8x 4 kB */
    fixed_offset = MSR_MTRRcap_VCNT * 2;
    for (i = 0; i < 11; i++) {
        fixed_name = HV_X64_REGISTER_MSR_MTRR_FIX64K00000 + i;
        fixed_value = env->mtrr_fixed[i];

        assoc = &assocs[fixed_offset + i];
        assoc->name = fixed_name;
        assoc->value.reg64 = fixed_value;
    }
}

/*
 * Note: this function requires that assocs are in the same order and length
 * as they appear in msr_env_map.
 */
void mshv_msr_store_in_env(CPUState *cpu,
                           const struct hv_register_assoc *assocs,
                           size_t n_assocs)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    size_t i;
    const MshvMsrEnvMap *mapping;
    union hv_register_value hv_value;
    ptrdiff_t offset;
    size_t mtrr_offset;

    assert(n_assocs == (ARRAY_SIZE(msr_env_map) + MTRR_MSR_COUNT));

    for (i = 0; i < ARRAY_SIZE(msr_env_map); i++) {
        mapping = &msr_env_map[i];
        offset = mapping->env_offset;
        hv_value = assocs[i].value;
        if (mapping->width == MSHV_MSR_WIDTH_32) {
            MSHV_ENV_FIELD_32(env, offset) = hv_value.reg32;
            continue;
        }
        MSHV_ENV_FIELD_64(env, offset) = hv_value.reg64;
    }

    mtrr_offset = ARRAY_SIZE(msr_env_map);
    msr_store_in_env_mtrr_phys(cpu, &assocs[mtrr_offset], MTRR_MSR_COUNT);
}

void mshv_msr_load_from_env(const CPUState *cpu,
                            struct hv_register_assoc *assocs, size_t n_assocs)
{
    size_t i;
    const MshvMsrEnvMap *mapping;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    ptrdiff_t offset;
    union hv_register_value *hv_value;
    size_t mtrr_offset;

    assert(n_assocs == (ARRAY_SIZE(msr_env_map) + MTRR_MSR_COUNT));

    for (i = 0; i < ARRAY_SIZE(msr_env_map); i++) {
        mapping = &msr_env_map[i];
        offset = mapping->env_offset;
        assocs[i].name = mapping->hv_name;
        hv_value = &assocs[i].value;
        if (mapping->width == MSHV_MSR_WIDTH_32) {
            hv_value->reg32 = MSHV_ENV_FIELD_32(env, offset);
            continue;
        }
        hv_value->reg64 = MSHV_ENV_FIELD_64(env, offset);
    }

    mtrr_offset = ARRAY_SIZE(msr_env_map);
    msr_load_from_env_mtrr_phys(cpu, &assocs[mtrr_offset], MTRR_MSR_COUNT);
}

size_t mshv_msr_mappable_reg_count(void)
{
    return ARRAY_SIZE(msr_env_map) + MTRR_MSR_COUNT;
}

void mshv_msr_set_hv_name_in_assocs(struct hv_register_assoc *assocs,
                                    size_t n_assocs)
{
    size_t i;
    size_t mtrr_offset, mtrr_fixed_offset;
    hv_register_name hv_name;

    assert(n_assocs == (ARRAY_SIZE(msr_env_map) + MTRR_MSR_COUNT));

    for (i = 0; i < ARRAY_SIZE(msr_env_map); i++) {
        assocs[i].name = msr_env_map[i].hv_name;
    }

    mtrr_offset = ARRAY_SIZE(msr_env_map);
    for (i = 0; i < MSR_MTRRcap_VCNT; i++) {
        hv_name = HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0 + i;
        assocs[mtrr_offset + i].name = hv_name;
        hv_name = HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0 + i;
        assocs[mtrr_offset + MSR_MTRRcap_VCNT + i].name = hv_name;
    }

    /* fixed 1x 64, 2x 16, 8x 4 kB */
    mtrr_fixed_offset = mtrr_offset + MSR_MTRRcap_VCNT * 2;
    for (i = 0; i < 11; i++) {
        hv_name = HV_X64_REGISTER_MSR_MTRR_FIX64K00000 + i;
        assocs[mtrr_fixed_offset + i].name = hv_name;
    }
}
