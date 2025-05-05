/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors:
 *  Ziqiao Zhou       <ziqiaozhou@microsoft.com>
 *  Magnus Kulke      <magnuskulke@microsoft.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MSHV_INT_H
#define QEMU_MSHV_INT_H

#include "qemu/osdep.h"
#include "qemu/accel.h"
#include "qemu/log.h"
#include "qemu/queue.h"
#include "hw/hyperv/hv-balloon.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hw/hyperv/linux-mshv.h"
#include "hw/hyperv/hvhdk.h"
#include "qapi/qapi-types-common.h"
#include "system/memory.h"
#include <stdint.h>

#ifdef COMPILING_PER_TARGET
#ifdef CONFIG_MSHV
#define CONFIG_MSHV_IS_POSSIBLE
#endif
#else
#define CONFIG_MSHV_IS_POSSIBLE
#endif

typedef struct hyperv_message hv_message;

/*
 * Set to 0 if we do not want to use eventfd to optimize the MMIO events.
 * Set to 1 so that mshv kernel driver receives doorbell when the VM access
 * MMIO memory and then signal eventfd to notify the qemu device
 * without extra switching to qemu to emulate mmio access.
 */
#define MSHV_USE_IOEVENTFD 1

#define MSHV_USE_KERNEL_GSI_IRQFD 1

#define MSHV_MAX_MSI_ROUTES 4096

#define MSHV_PAGE_SHIFT 12

#define MSHV_MSR_ENTRIES_COUNT 64

#define mshv_err(FMT, ...)                                                     \
  do {                                                                         \
    fprintf(stderr, FMT, ##__VA_ARGS__);                                       \
  } while (0)

#ifdef DEBUG_MSHV
#define mshv_debug()                                                           \
  do {                                                                         \
    fprintf(stderr, "%s:%d\n", __func__, __LINE__);                            \
  } while (0)

#else
#define mshv_debug()
#endif

#ifdef CONFIG_MSHV_IS_POSSIBLE
extern bool mshv_allowed;
#define mshv_enabled() (mshv_allowed)

typedef struct MshvMemoryListener {
  MemoryListener listener;
  int as_id;
} MshvMemoryListener;

typedef struct MshvAddressSpace {
    MshvMemoryListener *ml;
    AddressSpace *as;
} MshvAddressSpace;

typedef struct MshvState {
  AccelState parent_obj;
  int vm;
  MshvMemoryListener memory_listener;
  /* number of listeners */
  int nr_as;
  MshvAddressSpace *as;
} MshvState;
extern MshvState *mshv_state;

struct AccelCPUState {
  int cpufd;
};

typedef struct MshvMsiControl {
    bool updated;
    GHashTable *gsi_routes;
} MshvMsiControl;

typedef struct MshvCreatePartitionArgsMgns {
    uint64_t pt_flags;
    uint64_t pt_isolation;
} MshvCreatePartitionArgsMgns;

#define mshv_vcpufd(cpu) (cpu->accel->cpufd)

#else /* CONFIG_MSHV_IS_POSSIBLE */
#define mshv_enabled() false
#endif
#ifdef MSHV_USE_KERNEL_GSI_IRQFD
#define mshv_msi_via_irqfd_enabled() mshv_enabled()
#else
#define mshv_msi_via_irqfd_enabled() false
#endif

/* cpu */
/* EFER (technically not a register) bits */
#define EFER_LMA   ((uint64_t)0x400)
#define EFER_LME   ((uint64_t)0x100)

/* CR0 bits */
#define CR0_PE     ((uint64_t)0x1)
#define CR0_PG     ((uint64_t)0x80000000)

/* CR4 bits */
#define CR4_PAE    ((uint64_t)0x20)
#define CR4_LA57   ((uint64_t)0x1000)

/* rflags bits (shift values) */
#define CF_SHIFT   0
#define PF_SHIFT   2
#define AF_SHIFT   4
#define ZF_SHIFT   6
#define SF_SHIFT   7
#define DF_SHIFT   10
#define OF_SHIFT   11

/* rflags bits (bit masks) */
#define CF         ((uint64_t)1 << CF_SHIFT)
#define PF         ((uint64_t)1 << PF_SHIFT)
#define AF         ((uint64_t)1 << AF_SHIFT)
#define ZF         ((uint64_t)1 << ZF_SHIFT)
#define SF         ((uint64_t)1 << SF_SHIFT)
#define DF         ((uint64_t)1 << DF_SHIFT)
#define OF         ((uint64_t)1 << OF_SHIFT)

typedef struct MshvFPU {
  uint8_t fpr[8][16];
  uint16_t fcw;
  uint16_t fsw;
  uint8_t ftwx;
  uint8_t pad1;
  uint16_t last_opcode;
  uint64_t last_ip;
  uint64_t last_dp;
  uint8_t xmm[16][16];
  uint32_t mxcsr;
  uint32_t pad2;
} MshvFPU;

typedef enum MshvVmExit {
    MshvVmExitIgnore   = 0,
    MshvVmExitShutdown = 1,
    MshvVmExitSpecial  = 2,
} MshvVmExit;

void mshv_init_cpu_logic(void);
int mshv_create_vcpu(int vm_fd, uint8_t vp_index, int *cpu_fd);
void mshv_remove_vcpu(int vm_fd, int cpu_fd);
int mshv_configure_vcpu(const CPUState *cpu, const MshvFPU *fpu, uint64_t xcr0);
int mshv_get_standard_regs(CPUState *cpu);
int mshv_get_special_regs(CPUState *cpu);
int mshv_run_vcpu(int vm_fd, CPUState *cpu, hv_message *msg, MshvVmExit *exit);
int mshv_load_regs(CPUState *cpu);
int mshv_store_regs(CPUState *cpu);
int mshv_set_generic_regs(int cpu_fd, hv_register_assoc *assocs, size_t n_regs);
int mshv_arch_put_registers(const CPUState *cpu);

/* pio */
int mshv_pio_write(uint64_t port, const uint8_t *data, uintptr_t size,
                   bool is_secure_mode);
void mshv_pio_read(uint64_t port, uint8_t *data, uintptr_t size,
                   bool is_secure_mode);

/* generic */
enum MshvMiscError {
    MSHV_USERSPACE_ADDR_REMAP_ERROR = 2001,
};

int mshv_hvcall(int mshv_fd, const struct mshv_root_hvcall *args);

/* msr */
typedef struct MshvMsrEntry {
  uint32_t index;
  uint32_t reserved;
  uint64_t data;
} MshvMsrEntry;

typedef struct MshvMsrEntries {
    MshvMsrEntry entries[MSHV_MSR_ENTRIES_COUNT];
    uint32_t nmsrs;
} MshvMsrEntries;

int mshv_configure_msr(int cpu_fd, const MshvMsrEntry *msrs, size_t n_msrs);
int mshv_is_supported_msr(uint32_t msr);
int mshv_msr_to_hv_reg_name(uint32_t msr, uint32_t *hv_reg);

/* memory */
typedef struct MshvMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    bool readonly;
} MshvMemoryRegion;

typedef struct MshvMemoryEntry {
    MshvMemoryRegion mr;
    bool mapped;
} MshvMemoryEntry;

typedef struct MshvMemManager {
    GList *mem_entries;
    QemuMutex mutex;
} MshvMemManager;

void mshv_init_mem_manager(void);
int mshv_add_mem(int vm_fd, const MshvMemoryRegion *mr);
int mshv_remove_mem(int vm_fd, const MshvMemoryRegion *mr);
bool mshv_find_entry_idx_by_gpa(uint64_t addr, size_t *index);
bool mshv_remap_overlapped_region(int vm_fd, uint64_t gpa);
int mshv_guest_mem_read(uint64_t gpa, uint8_t *data, uintptr_t size,
                        bool is_secure_mode, bool instruction_fetch);
int mshv_guest_mem_write(uint64_t gpa, const uint8_t *data, uintptr_t size,
                         bool is_secure_mode);
void mshv_set_phys_mem(MshvMemoryListener *mml, MemoryRegionSection *section,
                       bool add);

/* mem: exposed for unit testing */
bool mshv_find_idx_by_gpa_in_entries(const GList *entries, uint64_t addr,
                                     size_t *index);
MshvMemoryEntry *mshv_find_entry_by_userspace_addr(const GList *entries,
                                                   uint64_t addr);

/* interrupt */
void mshv_init_msicontrol(void);
int mshv_request_interrupt(int vm_fd, uint32_t interrupt_type, uint32_t vector,
                           uint32_t vp_index, bool logical_destination_mode,
                           bool level_triggered);

int mshv_irqchip_add_msi_route(int vector, PCIDevice *dev);
int mshv_irqchip_update_msi_route(int virq, MSIMessage msg, PCIDevice *dev);
void mshv_irqchip_commit_routes(void);
void mshv_irqchip_release_virq(int virq);
int mshv_irqchip_add_irqfd_notifier_gsi(const EventNotifier *n,
                                        const EventNotifier *rn, int virq);
int mshv_irqchip_remove_irqfd_notifier_gsi(const EventNotifier *n, int virq);

#endif
