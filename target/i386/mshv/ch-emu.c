#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/error-report.h"
#include "qemu/memalign.h"
#include "system/mshv.h"
#include "system/address-spaces.h"
#include "hw/i386/x86.h"
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "emulate/x86_decode.h"
#include "emulate/x86_emu.h"
#include "qemu/atomic.h"
#include "trace-accel_mshv.h"
#include "trace.h"

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

static inline MemTxAttrs mshv_get_mem_attrs(bool is_secure_mode)
{
    return ((MemTxAttrs){ .secure = is_secure_mode });
}

static void pio_read_fn(uint64_t port, uint8_t *data, uintptr_t size,
                        bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           false);
    assert(ret == MEMTX_OK);
}

static int pio_write_fn(uint64_t port, const uint8_t *data, uintptr_t size,
                        bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           true);
    return ret;
}

static int get_generic_regs(int cpu_fd,
                            struct hv_register_assoc *assocs,
                            size_t n_regs)
{
    struct mshv_vp_registers input = {
        .count = n_regs,
        .regs = assocs,
    };

    return ioctl(cpu_fd, MSHV_GET_VP_REGISTERS, &input);
}

static int set_generic_regs(int cpu_fd, struct hv_register_assoc *assocs,
                            size_t n_regs)
{
    struct mshv_vp_registers input = {
        .count = n_regs,
        .regs = assocs,
    };

    return ioctl(cpu_fd, MSHV_SET_VP_REGISTERS, &input);
}

static void populate_standard_regs(const struct hv_register_assoc *assocs,
                                   struct StandardRegisters *regs)
{
    regs->rax = assocs[0].value.reg64;
    regs->rbx = assocs[1].value.reg64;
    regs->rcx = assocs[2].value.reg64;
    regs->rdx = assocs[3].value.reg64;
    regs->rsi = assocs[4].value.reg64;
    regs->rdi = assocs[5].value.reg64;
    regs->rsp = assocs[6].value.reg64;
    regs->rbp = assocs[7].value.reg64;
    regs->r8  = assocs[8].value.reg64;
    regs->r9  = assocs[9].value.reg64;
    regs->r10 = assocs[10].value.reg64;
    regs->r11 = assocs[11].value.reg64;
    regs->r12 = assocs[12].value.reg64;
    regs->r13 = assocs[13].value.reg64;
    regs->r14 = assocs[14].value.reg64;
    regs->r15 = assocs[15].value.reg64;
    regs->rip = assocs[16].value.reg64;

    regs->rflags = assocs[17].value.reg64;
}

static void populate_segment_reg(const struct hv_x64_segment_register *hv_seg,
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

static void populate_table_reg(const struct hv_x64_table_register *hv_seg,
                               struct TableRegister *reg)
{
    memset(reg, 0, sizeof(TableRegister));

    reg->base = hv_seg->base;
    reg->limit = hv_seg->limit;
}

static void populate_interrupt_bitmap(uint64_t pending_reg, uint64_t *bitmap)
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
            error_report("invalid interrupt vector number > 255");
            abort();
        }

        /* Compute the bit offset (lower 6 bits, i.e. 0-63) */
        uint64_t bit_offset = pending_reg & 0x3FULL;
        /* The index is stored in remaining higher bits (shift right by 6) */
        uint64_t index = pending_reg >> 6;

        /* Set the corresponding bit in the interrupt bitmap. */
        /* (63 - bit_offset) shifts from the left. */
        bitmap[index] = 1ULL << (63 - bit_offset);
    }
}

static void populate_special_regs(const struct hv_register_assoc *assocs,
                                  struct SpecialRegisters *regs)
{
    uint64_t pending_reg;

    populate_segment_reg(&assocs[0].value.segment, &regs->cs);
    populate_segment_reg(&assocs[1].value.segment, &regs->ds);
    populate_segment_reg(&assocs[2].value.segment, &regs->es);
    populate_segment_reg(&assocs[3].value.segment, &regs->fs);
    populate_segment_reg(&assocs[4].value.segment, &regs->gs);
    populate_segment_reg(&assocs[5].value.segment, &regs->ss);
    populate_segment_reg(&assocs[6].value.segment, &regs->tr);
    populate_segment_reg(&assocs[7].value.segment, &regs->ldt);

    populate_table_reg(&assocs[8].value.table, &regs->gdt);
    populate_table_reg(&assocs[9].value.table, &regs->idt);

    regs->cr0       = assocs[10].value.reg64;
    regs->cr2       = assocs[11].value.reg64;
    regs->cr3       = assocs[12].value.reg64;
    regs->cr4       = assocs[13].value.reg64;
    regs->cr8       = assocs[14].value.reg64;
    regs->efer      = assocs[15].value.reg64;
    regs->apic_base = assocs[16].value.reg64;

    pending_reg = assocs[17].value.pending_interruption.as_uint64;
    populate_interrupt_bitmap(pending_reg, regs->interrupt_bitmap);
}

static int get_standard_regs(int cpu_fd, struct StandardRegisters *regs)
{
    size_t n_regs = sizeof(STANDARD_REGISTER_NAMES)
                    / sizeof(enum hv_register_name);
    struct hv_register_assoc *assocs;
    int ret;

    // TODO: maybe make this global?
    assocs = g_new0(struct hv_register_assoc, n_regs);
    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = STANDARD_REGISTER_NAMES[i];
    }
    ret = get_generic_regs(cpu_fd, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to get standard registers");
        g_free(assocs);
        return -errno;
    }

    populate_standard_regs(assocs, regs);

    g_free(assocs);
    return 0;
}

static int set_standard_regs(int cpu_fd, const struct StandardRegisters *regs)
{
    struct hv_register_assoc *assocs;
    size_t n_regs = sizeof(STANDARD_REGISTER_NAMES)
                    / sizeof(enum hv_register_name);
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

    ret = set_generic_regs(cpu_fd, assocs, n_regs);
    g_free(assocs);
    if (ret < 0) {
        error_report("failed to set standard registers");
        return -errno;
    }
    return 0;
}

static int get_special_regs(int cpu_fd, struct SpecialRegisters *regs)
{
    size_t n_regs = sizeof(SPECIAL_REGISTER_NAMES)
                    / sizeof(enum hv_register_name);
    struct hv_register_assoc *assocs;
    int ret;

    assocs = g_new0(struct hv_register_assoc, n_regs);
    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = SPECIAL_REGISTER_NAMES[i];
    }
    ret = get_generic_regs(cpu_fd, assocs, n_regs);
    if (ret < 0) {
        error_report("failed to get special registers");
        g_free(assocs);
        return -errno;
    }

    populate_special_regs(assocs, regs);

    g_free(assocs);
    return 0;
}

static void populate_hv_segment_reg(const struct SegmentRegister *reg,
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

static void populate_hv_table_reg(const struct TableRegister *reg,
                                  struct hv_x64_table_register *hv_reg)
{
    hv_reg->base = reg->base;
    hv_reg->limit = reg->limit;
    memset(hv_reg->pad, 0, sizeof(hv_reg->pad));
}

static int set_special_regs(int cpu_fd, const struct SpecialRegisters *regs)
{
    struct hv_register_assoc *assocs;
    uint64_t bits;
    size_t n_regs = sizeof(SPECIAL_REGISTER_NAMES)
                    / sizeof(enum hv_register_name);
    int ret;

    assocs = g_new0(struct hv_register_assoc, n_regs);

    /* set names */
    for (size_t i = 0; i < n_regs; i++) {
        assocs[i].name = SPECIAL_REGISTER_NAMES[i];
    }
    populate_hv_segment_reg(&regs->cs, &assocs[0].value.segment);
    populate_hv_segment_reg(&regs->ds, &assocs[1].value.segment);
    populate_hv_segment_reg(&regs->es, &assocs[2].value.segment);
    populate_hv_segment_reg(&regs->fs, &assocs[3].value.segment);
    populate_hv_segment_reg(&regs->gs, &assocs[4].value.segment);
    populate_hv_segment_reg(&regs->ss, &assocs[5].value.segment);
    populate_hv_segment_reg(&regs->tr, &assocs[6].value.segment);
    populate_hv_segment_reg(&regs->ldt, &assocs[7].value.segment);

    populate_hv_table_reg(&regs->gdt, &assocs[8].value.table);
    populate_hv_table_reg(&regs->idt, &assocs[9].value.table);

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
            error_report("asserting an interrupt is not supported");
            return -EINVAL;
        }
    }

    ret = set_generic_regs(cpu_fd, assocs, n_regs);
    g_free(assocs);
    if (ret < 0) {
        error_report("failed to set special registers");
        return -1;
    }
    return 0;
}

/* static int register_intercept_result_cpuid_entry(int cpu_fd, */
/*                                                  uint8_t subleaf_specific, */
/*                                                  uint8_t always_override, */
/*                                                  struct hv_cpuid_entry *entry) */
/* { */
/*     struct hv_register_x64_cpuid_result_parameters cpuid_params = { */
/*         .input.eax = entry->function, */
/*         .input.ecx = entry->index, */
/*         .input.subleaf_specific = subleaf_specific, */
/*         .input.always_override = always_override, */
/*         .input.padding = 0, */
/*         /1* With regard to masks - these are to specify bits to be overwritten. *1/ */
/*         /1* The current CpuidEntry structure wouldn't allow to carry the masks *1/ */
/*         /1* in addition to the actual register values. For this reason, the *1/ */
/*         /1* masks are set to the exact values of the corresponding register bits *1/ */
/*         /1* to be registered for an overwrite. To view resulting values the *1/ */
/*         /1* hypervisor would return, HvCallGetVpCpuidValues hypercall can be used. *1/ */
/*         .result.eax = entry->eax, */
/*         .result.eax_mask = entry->eax, */
/*         .result.ebx = entry->ebx, */
/*         .result.ebx_mask = entry->ebx, */
/*         .result.ecx = entry->ecx, */
/*         .result.ecx_mask = entry->ecx, */
/*         .result.edx = entry->edx, */
/*         .result.edx_mask = entry->edx, */
/*     }; */
/*     union hv_register_intercept_result_parameters parameters = { */
/*         .cpuid = cpuid_params, */
/*     }; */
/*     struct mshv_register_intercept_result args = { */
/*         .intercept_type = HV_INTERCEPT_TYPE_X64_CPUID, */
/*         .parameters = parameters, */
/*     }; */
/*     int ret; */

/*     ret = ioctl(cpu_fd, MSHV_VP_REGISTER_INTERCEPT_RESULT, &args); */
/*     if (ret < 0) { */
/*         perror("failed to register intercept result for cpuid"); */
/*         return -errno; */
/*     } */

/*     return 0; */
/* } */

/* static int register_intercept_result_cpuid(int cpu_fd, struct hv_cpuid *cpuid) */
/* { */
/*     int ret = 0, entry_ret; */
/*     struct hv_cpuid_entry *entry; */
/*     uint8_t subleaf_specific, always_override; */

/*     for (size_t i = 0; i < cpuid->nent; i++) { */
/*         entry = &cpuid->entries[i]; */

/*         /1* set defaults *1/ */
/*         subleaf_specific = 0; */
/*         always_override = 1; */

/*         /1* Intel *1/ */
/*         /1* 0xb - Extended Topology Enumeration Leaf *1/ */
/*         /1* 0x1f - V2 Extended Topology Enumeration Leaf *1/ */
/*         /1* AMD *1/ */
/*         /1* 0x8000_001e - Processor Topology Information *1/ */
/*         /1* 0x8000_0026 - Extended CPU Topology *1/ */
/*         if (entry->function == 0xb */
/*             || entry->function == 0x1f */
/*             || entry->function == 0x8000001e */
/*             || entry->function == 0x80000026) { */
/*             subleaf_specific = 1; */
/*             always_override = 1; */
/*         } */
/*         else if (entry->function == 0x00000001 */
/*             || entry->function == 0x80000000 */
/*             || entry->function == 0x80000001 */
/*             || entry->function == 0x80000008) { */
/*             subleaf_specific = 0; */
/*             always_override = 1; */
/*         } */

/*         entry_ret = register_intercept_result_cpuid_entry(cpu_fd, */
/*                                                           subleaf_specific, */
/*                                                           always_override, */
/*                                                           entry); */
/*         if ((entry_ret < 0) && (ret == 0)) { */
/*             ret = entry_ret; */
/*         } */
/*     } */

/*     return ret; */
/* } */

/* static int set_cpuid2(int cpu_fd, struct hv_cpuid *cpuid) */
/* { */
/*     int ret; */

/*     ret = register_intercept_result_cpuid(cpu_fd, cpuid); */
/*     if (ret < 0) { */
/*         return ret; */
/*     } */

/*     return 0; */
/* } */

/* TODO: Note this function is still using the cpuid impl from mshv-c */
/* static int set_cpuid2_mgns(int cpu_fd, struct CpuId *cpuid_mgns) */
/* { */
/*     int ret; */
/*     size_t n_entries = cpuid_mgns->len; */
/*     size_t cpuid_size = sizeof(struct hv_cpuid) */
/*         + n_entries * sizeof(struct hv_cpuid_entry); */
/*     struct hv_cpuid *cpuid; */
/*     struct hv_cpuid_entry *entry; */
/*     struct CpuIdEntry *mgns_entry; */

/*     cpuid = g_malloc0(cpuid_size); */
/*     cpuid->nent = n_entries; */
/*     cpuid->padding = 0; */
/*     for (size_t i = 0; i < n_entries; i++) { */
/*         mgns_entry = &cpuid_mgns->entries[i]; */
/*         entry = &cpuid->entries[i]; */
/*         entry->function = mgns_entry->function; */
/*         entry->index = mgns_entry->index; */
/*         entry->flags = mgns_entry->flags; */
/*         entry->eax = mgns_entry->eax; */
/*         entry->ebx = mgns_entry->ebx; */
/*         entry->ecx = mgns_entry->ecx; */
/*         entry->edx = mgns_entry->edx; */
/*         /1* padding is covered, due to 0ing  *1/ */
/*     } */

/*     ret = set_cpuid2(cpu_fd, cpuid); */
/*     g_free(cpuid); */
/*     if (ret < 0) { */
/*         return ret; */
/*     } */

/*     printf("[mgns-qemu] set_cpuid2_mgns2() done\n"); */

/*     return 0; */
/* } */

/* static void free_cpuid_mgns(CpuId *cpu_id) { */
/*     if (cpu_id != NULL) { */
/*         if (cpu_id->entries != NULL) { */
/*             g_free(cpu_id->entries); */
/*         } */
/*         g_free(cpu_id); */
/*     } */
/* } */

static int set_cpu_state_ch(int cpu_fd,
                            const StandardRegisters *standard_regs,
                            const SpecialRegisters *special_regs)
{
    int ret;

    ret = set_standard_regs(cpu_fd, standard_regs);
    if (ret < 0) {
        error_report("failed to set standard registers");
        return ret;
    }

    ret = set_special_regs(cpu_fd, special_regs);
    if (ret < 0) {
        error_report("failed to set special registers");
        return ret;
    }

    return 0;
}

static int get_cpu_state_ch(int cpu_fd,
                            StandardRegisters *standard_regs,
                            SpecialRegisters *special_regs)
{
    int ret;

    ret = get_standard_regs(cpu_fd, standard_regs);
    if (ret < 0) {
        error_report("failed to get cpu state");
        return ret;
    }

    ret = get_special_regs(cpu_fd, special_regs);
    if (ret < 0) {
        error_report("failed to get cpu state");
        return ret;
    }
    return 0;
}

static int translate_gva(int cpu_fd, uint64_t gva, uint64_t *gpa, uint64_t flags)
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
        error_report("failed to invoke gva translation");
        return -errno;
    }
    if (result.result_code != HV_TRANSLATE_GVA_SUCCESS) {
        error_report("failed to translate gva (" TARGET_FMT_lx ") to gpa", gva);
        return -1;

    }

    return 0;
}

static int guest_mem_read_fn(uint64_t gpa, uint8_t *data, uintptr_t size,
                             bool is_secure_mode, bool instruction_fetch)
{
    int ret;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);

    if (instruction_fetch) {
        trace_mshv_insn_fetch(gpa, size);
    } else {
        trace_mshv_mem_read(gpa, size);
    }

    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, false);
    if (ret != MEMTX_OK) {
        error_report("Failed to read guest memory from gpa " TARGET_FMT_lx,
                     gpa);
        return -1;
    }

    return 0;
}

static int guest_mem_write_fn(uint64_t gpa, const uint8_t *data, uintptr_t size,
                              bool is_secure_mode)
{
    trace_mshv_mem_write(gpa, size);
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, true);
    return ret;
}

static int read_memory(int cpu_fd, uint64_t initial_gva, uint64_t initial_gpa,
                       uint64_t gva, uint8_t *data, size_t len)
{
    int ret;
    uint64_t gpa, flags;

    if (gva == initial_gva) {
        gpa = initial_gpa;
    } else {
        flags = HV_TRANSLATE_GVA_VALIDATE_READ;
        ret = translate_gva(cpu_fd, gva, &gpa, flags);
        if (ret < 0) {
            error_report("failed to translate gva to gpa");
            return -1;
        }

        /* TODO: it's unfortunate that this fn doesn't fail
         * the rust code has a code path for failed reads at this point,
         * but it's dead code */
        guest_mem_read_fn(gpa, data, len, false, false);
    }

    return 0;
}

static int write_memory(int cpu_fd, uint64_t initial_gva, uint64_t initial_gpa,
                        uint64_t gva, const uint8_t *data, size_t len)
{
    int ret;
    uint64_t gpa, flags;

    if (gva == initial_gva) {
        gpa = initial_gpa;
    } else {
        flags = HV_TRANSLATE_GVA_VALIDATE_WRITE;
        ret = translate_gva(cpu_fd, gva, &gpa, flags);
        if (ret < 0) {
            error_report("failed to translate gva to gpa");
            return -1;
        }
    }
    ret = guest_mem_write_fn(gpa, data, len, false);
    if (ret != MEMTX_OK) {
        error_report("failed to write to mmio");
        return -1;
    }

    return 0;
}

static MshvOps emu_ops_ch = {
    /* trait impls for the emulator */
    .guest_mem_write_fn = guest_mem_write_fn,
    .guest_mem_read_fn  = guest_mem_read_fn,
    .pio_read_fn        = pio_read_fn,
    .pio_write_fn       = pio_write_fn,
    /* cb's for the plaform in the emulator */
    .read_memory_fn     = read_memory,
    .write_memory_fn    = write_memory,
    .set_cpu_state_fn   = set_cpu_state_ch,
    .get_cpu_state_fn   = get_cpu_state_ch,
    .translate_gva_fn   = translate_gva,
};

void mshv_emulate_instruction_ch(CPUState *cpu,
                                 struct hv_x64_memory_intercept_message *info)
{
    int cpu_fd = mshv_vcpufd(cpu);
    emulate_ch(cpu_fd,
               info->guest_virtual_address, info->guest_physical_address,
               info->instruction_bytes, info->instruction_byte_count,
               &emu_ops_ch);
}
