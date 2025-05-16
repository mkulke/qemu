/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors:
 *  Ziqiao Zhou       <ziqiaozhou@microsoft.com>
 *  Magnus Kulke      <magnuskulke@microsoft.com>
 *  Jinank Jain       <jinankjain@microsoft.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MSHV_INT_H
#define QEMU_MSHV_INT_H

#include "qemu/osdep.h"
#include "qemu/accel.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hw/hyperv/linux-mshv.h"
#include "hw/hyperv/hvhdk.h"
#include "qapi/qapi-types-common.h"
#include "system/memory.h"

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
  bool dirty;
};

typedef struct MshvMsiControl {
    bool updated;
    GHashTable *gsi_routes;
} MshvMsiControl;

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

typedef enum MshvVmExit {
    MshvVmExitIgnore   = 0,
    MshvVmExitShutdown = 1,
    MshvVmExitSpecial  = 2,
} MshvVmExit;

void mshv_init_cpu_logic(void);
int mshv_create_vcpu(int vm_fd, uint8_t vp_index, int *cpu_fd);
void mshv_remove_vcpu(int vm_fd, int cpu_fd);
int mshv_get_standard_regs(CPUState *cpu);
int mshv_run_vcpu(int vm_fd, CPUState *cpu, hv_message *msg, MshvVmExit *exit);
int mshv_load_regs(CPUState *cpu);
int mshv_store_regs(CPUState *cpu);
int mshv_set_generic_regs(int cpu_fd, hv_register_assoc *assocs, size_t n_regs);
int mshv_arch_put_registers(const CPUState *cpu);
void mshv_arch_init_vcpu(CPUState *cpu);
void mshv_arch_destroy_vcpu(CPUState *cpu);
void mshv_arch_amend_proc_features(
    union hv_partition_synthetic_processor_features *features);
int mshv_arch_post_init_vm(int vm_fd);

int mshv_hvcall(int mshv_fd, const struct mshv_root_hvcall *args);


/* memory */
typedef struct MshvMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    bool readonly;
} MshvMemoryRegion;

int mshv_add_mem(int vm_fd, const MshvMemoryRegion *mr);
int mshv_remove_mem(int vm_fd, const MshvMemoryRegion *mr);
void mshv_set_phys_mem(MshvMemoryListener *mml, MemoryRegionSection *section,
                       bool add);
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
