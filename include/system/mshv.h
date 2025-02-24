#ifndef QEMU_MSHV_INT_H
#define QEMU_MSHV_INT_H

#include "exec/memory.h"
#include "hw/hyperv/hv-balloon.h"
#include "hw/hyperv/hyperv-proto.h"
#include "hw/hyperv/linux-mshv.h"
#include "hw/hyperv/hvhdk.h"
#include "qapi/qapi-types-common.h"
#include "qemu/accel.h"
#include "qemu/log.h"
#include "qemu/queue.h"
#include <stdint.h>

#ifdef COMPILING_PER_TARGET
#ifdef CONFIG_MSHV
#define CONFIG_MSHV_IS_POSSIBLE
#endif
#else
#define CONFIG_MSHV_IS_POSSIBLE
#endif

typedef struct hyperv_message hv_message;

// Set to 0 if we do not want to use eventfd to optimize the MMIO events.
// Set to 1 so that mshv kernel driver receives doorbell when the VM access
// MMIO memory and then signal eventfd to notify the qemu device
// without extra switching to qemu to emulate mmio access.
#define MSHV_USE_IOEVENTFD 1

#define MSHV_USE_KERNEL_GSI_IRQFD 1

#define MSHV_MAX_MSI_ROUTES 4096

#define MSHV_PAGE_SHIFT 12

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
#include <qemu-mshv.h>
extern bool mshv_allowed;
#define mshv_enabled() (mshv_allowed)


typedef struct MshvMemoryListener {
  MemoryListener listener;
  int as_id;
} MshvMemoryListener;

typedef struct MshvState {
  AccelState parent_obj;
  int vm;
  MshvMemoryListener memory_listener;
  int nr_as; // number of listener;
  struct MshvAs {
    MshvMemoryListener *ml;
    AddressSpace *as;
  } * as;
} MshvState;
extern MshvState *mshv_state;

struct AccelCPUState {
  int cpufd;
};

struct MsiControlMgns {
	bool updated;
	GHashTable *gsi_routes;
};

typedef struct MshvVmMgns {
    int fd;
} MshvVmMgns;

typedef struct MshvCreatePartitionArgsMgns {
	uint64_t pt_flags;
	uint64_t pt_isolation;
} MshvCreatePartitionArgsMgns;

#define mshv_vcpufd(cpu) (cpu->accel->cpufd)

int mshv_arch_put_registers(MshvState *s, CPUState *cpu);

int mshv_arch_get_registers(MshvState *s, CPUState *cpu);


#else //! CONFIG_MSHV_IS_POSSIBLE
#define mshv_enabled() false
#endif
#ifdef MSHV_USE_KERNEL_GSI_IRQFD
#define mshv_msi_via_irqfd_enabled() mshv_enabled()
#else
#define mshv_msi_via_irqfd_enabled() false
#endif

enum hv_partition_property_code_mgns {
	/* Privilege properties */
    HV_PARTITION_PROPERTY_PRIVILEGE_FLAGS				= 0x00010000,
    HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES		= 0x00010001,
    HV_PARTITION_PROPERTY_TIME_FREEZE				    = 0x00030003,
    HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION		= 0x00050017,
};

enum hv_unimplemented_msr_action_mgns {
	HV_UNIMPLEMENTED_MSR_ACTION_FAULT = 0,
	HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO = 1,
	HV_UNIMPLEMENTED_MSR_ACTION_COUNT = 2,
};


/* Declare the various hypercall operations. from hvgdk_mini.h */
/* HV_CALL_CODE */
#define HVCALL_GET_PARTITION_PROPERTY		0x0044
#define HVCALL_SET_PARTITION_PROPERTY		0x0045
#define HVCALL_ASSERT_VIRTUAL_INTERRUPT		0x0094

enum mapping_errors_mgns {
	MSHV_USERSPACE_ADDR_REMAP_ERROR = 2001,
};

typedef enum {
    DATAMATCH_NONE,
    DATAMATCH_U32,
    DATAMATCH_U64,
} DatamatchTagMgns;

typedef struct {
    DatamatchTagMgns tag;
    union {
        uint32_t u32;
        uint64_t u64;
    } value;
} DatamatchMgns;

typedef struct MemoryRegionMgns {
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;
	bool readonly;
} MemoryRegionMgns;

typedef struct MemEntryMgns {
	MemoryRegionMgns mr;
	bool mapped;
} MemEntryMgns;

typedef struct MemManagerMgns {
	GList *mem_entries;
 	QemuMutex mutex;
} MemManagerMgns;

typedef struct DirtyLogSlotMgns {
	uint64_t guest_pfn;
	uint64_t memory_size;
} DirtyLogSlotMgns;

typedef struct PerCpuInfoMgns {
	int vp_fd;
	uint8_t vp_index;
	MshvOps *ops;
} PerCpuInfoMgns;

/* cpu */
void init_cpu_db_mgns(void);
int new_vcpu_mgns(int mshv_fd, uint8_t vp_index, MshvOps *ops);
void remove_vcpu_mgns(int mshv_fd);

/* memory */
void init_dirty_log_slots_mgns(void);
void init_mem_manager_mgns(void);
int set_dirty_log_slot_mgns(uint64_t guest_pfn, uint64_t memory_size);
int remove_dirty_log_slot_mgns(uint64_t guest_pfn);
int add_mem_mgns(int vm_fd, const MemoryRegionMgns *mr);
int remove_mem_mgns(int vm_fd, const MemoryRegionMgns *mr);
bool find_entry_idx_by_gpa_mgns(uint64_t addr, size_t *index);
bool map_overlapped_region_mgns(int vm_fd, uint64_t gpa);

/* interrupt */
void init_msicontrol_mgns(void);
int set_msi_routing_mgns(uint32_t gsi, uint64_t addr, uint32_t data);
int remove_msi_routing_mgns(uint32_t gsi);
int add_msi_routing_mgns(uint64_t addr, uint32_t data);
int commit_msi_routing_table_mgns(int vm_fd);
int irqfd_mgns(int vm_fd, int fd, int resample_fd, uint32_t gsi, uint32_t flags);
int request_interrupt_mgns(int vm_fd, uint32_t interrupt_type, uint32_t vector,
						   uint32_t vp_index, bool logical_destination_mode,
						   bool level_triggered);
int register_irqfd_mgns(int vm_fd, int event_fd, uint32_t gsi);
int register_irqfd_with_resample_mgns(int vm_fd, int event_fd, int resample_fd,
									  uint32_t gsi);
int unregister_irqfd_mgns(int vm_fd, int event_fd, uint32_t gsi);

void init_vm_db_mgns(void);
void update_vm_db_mgns(int vm_fd, MshvVmMgns *vm);
MshvVmMgns *get_vm_from_db_mgns(int vm_fd);
// dead fn
void update_cpu_db_mgns(int vm_fd, MshvVmMgns *vm);
int create_vm_with_type_mgns(uint64_t vm_type, int mshv_fd);
int create_partition_mgns(int mshv_fd);
int hvcall_mgns(int mshv_fd, const struct mshv_root_hvcall *args);
int initialize_vm_mgns(int vm_fd);
int pause_vm_mgns(int vm_fd);
int resume_vm_mgns(int vm_fd);
int set_synthetic_proc_features_mgns(int vm_fd);
int set_unimplemented_msr_action_mgns(int vm_fd);
int register_ioevent_mgns(int vm_fd, int event_fd, uint64_t mmio_addr, uint64_t val, bool is_64bit, bool is_datamatch);
int unregister_ioevent_mgns(int vm_fd, int event_fd, uint64_t mmio_addr);
void dump_user_ioeventfd_mgns(const struct mshv_user_ioeventfd *ioevent);
int init_vcpu_mgns(CPUState *cpu);

int mshv_irqchip_add_msi_route(int vector, PCIDevice *dev);
int mshv_irqchip_update_msi_route(int virq, MSIMessage msg, PCIDevice *dev);
void mshv_irqchip_commit_routes(void);
void mshv_irqchip_release_virq(int virq);
int mshv_irqchip_add_irqfd_notifier_gsi(EventNotifier *n, EventNotifier *rn,
                                        int virq);
int mshv_irqchip_remove_irqfd_notifier_gsi(EventNotifier *n, int virq);

/* taken from github.com/rust-vmm/mshv-ioctls/src/ioctls/system.rs */
static const uint32_t msr_list_mgns[] = {
    IA32_MSR_TSC,
    IA32_MSR_EFER,
    IA32_MSR_KERNEL_GS_BASE,
    IA32_MSR_APIC_BASE,
    IA32_MSR_PAT,
    IA32_MSR_SYSENTER_CS,
    IA32_MSR_SYSENTER_ESP,
    IA32_MSR_SYSENTER_EIP,
    IA32_MSR_STAR,
    IA32_MSR_LSTAR,
    IA32_MSR_CSTAR,
    IA32_MSR_SFMASK,
    IA32_MSR_MTRR_DEF_TYPE,
    IA32_MSR_MTRR_PHYSBASE0,
    IA32_MSR_MTRR_PHYSMASK0,
    IA32_MSR_MTRR_PHYSBASE1,
    IA32_MSR_MTRR_PHYSMASK1,
    IA32_MSR_MTRR_PHYSBASE2,
    IA32_MSR_MTRR_PHYSMASK2,
    IA32_MSR_MTRR_PHYSBASE3,
    IA32_MSR_MTRR_PHYSMASK3,
    IA32_MSR_MTRR_PHYSBASE4,
    IA32_MSR_MTRR_PHYSMASK4,
    IA32_MSR_MTRR_PHYSBASE5,
    IA32_MSR_MTRR_PHYSMASK5,
    IA32_MSR_MTRR_PHYSBASE6,
    IA32_MSR_MTRR_PHYSMASK6,
    IA32_MSR_MTRR_PHYSBASE7,
    IA32_MSR_MTRR_PHYSMASK7,
    IA32_MSR_MTRR_FIX64K_00000,
    IA32_MSR_MTRR_FIX16K_80000,
    IA32_MSR_MTRR_FIX16K_A0000,
    IA32_MSR_MTRR_FIX4K_C0000,
    IA32_MSR_MTRR_FIX4K_C8000,
    IA32_MSR_MTRR_FIX4K_D0000,
    IA32_MSR_MTRR_FIX4K_D8000,
    IA32_MSR_MTRR_FIX4K_E0000,
    IA32_MSR_MTRR_FIX4K_E8000,
    IA32_MSR_MTRR_FIX4K_F0000,
    IA32_MSR_MTRR_FIX4K_F8000,
    IA32_MSR_TSC_AUX,
    IA32_MSR_DEBUG_CTL,
	HV_X64_MSR_GUEST_OS_ID,
	HV_X64_MSR_SINT0,
	HV_X64_MSR_SINT1,
	HV_X64_MSR_SINT2,
	HV_X64_MSR_SINT3,
	HV_X64_MSR_SINT4,
	HV_X64_MSR_SINT5,
	HV_X64_MSR_SINT6,
	HV_X64_MSR_SINT7,
	HV_X64_MSR_SINT8,
	HV_X64_MSR_SINT9,
	HV_X64_MSR_SINT10,
	HV_X64_MSR_SINT11,
	HV_X64_MSR_SINT12,
	HV_X64_MSR_SINT13,
	HV_X64_MSR_SINT14,
	HV_X64_MSR_SINT15,
	HV_X64_MSR_SCONTROL,
	HV_X64_MSR_SIEFP,
	HV_X64_MSR_SIMP,
	HV_X64_MSR_REFERENCE_TSC,
	HV_X64_MSR_EOM,
};

#define MSR_LIST_SIZE_mgns (sizeof(msr_list_mgns) / sizeof(msr_list_mgns[0]))

#endif
