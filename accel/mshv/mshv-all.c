#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/module.h"

#include "hw/hyperv/hvhdk.h"
#include "hw/hyperv/linux-mshv.h"

#include "exec/address-spaces.h"
#include "hw/i386/x86.h"
#include "qemu/accel.h"
#include "qemu/guest-random.h"
#include "system/accel-ops.h"
#include "system/cpus.h"
#include "system/runstate.h" //vm_stop
#include "system/accel-blocker.h"
#include "system/mshv.h"
#include "system/reset.h" //register reset
#include "trace.h"
#include <stdint.h>
#include <sys/ioctl.h>

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

DECLARE_INSTANCE_CHECKER(MshvState, MSHV_STATE, TYPE_MSHV_ACCEL)

bool mshv_allowed;

MshvState *mshv_state;

static GHashTable *vm_db_mgns;
static QemuMutex vm_db_mutex_mgns;

static GHashTable *cpu_db_mgns;
static QemuMutex cpu_db_mutex_mgns;

void init_vm_db_mgns(void) {
	trace_mgns_init_vm_db();

    vm_db_mgns = g_hash_table_new(g_direct_hash, g_direct_equal);
    qemu_mutex_init(&vm_db_mutex_mgns);
}

static int init_mshv_mgns(void) {
    // Open /dev/mshv device (hypervisor initialization)
    int mshv_fd = open("/dev/mshv", O_RDWR | O_CLOEXEC);
    if (mshv_fd < 0) {
        perror("[mshv] Failed to open /dev/mshv");
        return -errno;
    }
	return mshv_fd;
}

void update_vm_db_mgns(int vm_fd, MshvVmMgns *vm)
{
	trace_mgns_update_vm_db(vm_fd);

	qemu_mutex_lock(&vm_db_mutex_mgns);
	g_hash_table_insert(vm_db_mgns, GINT_TO_POINTER(vm_fd), vm);
	qemu_mutex_unlock(&vm_db_mutex_mgns);
}

MshvVmMgns *get_vm_from_db_mgns(int vm_fd)
{
	trace_mgns_get_vm_from_db(vm_fd);

    MshvVmMgns *vm = NULL;

    qemu_mutex_lock(&vm_db_mutex_mgns);
    vm = g_hash_table_lookup(vm_db_mgns, GINT_TO_POINTER(vm_fd));
    qemu_mutex_unlock(&vm_db_mutex_mgns);

    return vm;
}

void update_cpu_db_mgns(int vm_fd, MshvVmMgns *vm)
{
	trace_mgns_update_vm_db(vm_fd);

	qemu_mutex_lock(&cpu_db_mutex_mgns);
	g_hash_table_insert(cpu_db_mgns, GINT_TO_POINTER(vm_fd), vm);
	qemu_mutex_unlock(&cpu_db_mutex_mgns);
}

static int do_mshv_set_memory_mgns(const MemoryRegionMgns *mshv_mr, bool add)
{
    int ret = 0;

    if (!mshv_mr) {
        return -1;
    }

    trace_mshv_set_memory(add, mshv_mr->guest_phys_addr, mshv_mr->memory_size,
                          mshv_mr->userspace_addr, mshv_mr->readonly, ret);
    if (add) {
        return add_mem_mgns(mshv_state->vm, mshv_mr);
    }
	return remove_mem_mgns(mshv_state->vm, mshv_mr);
}

/*
 * Calculate and align the start address and the size of the section.
 * Return the size. If the size is 0, the aligned section is empty.
 */
static hwaddr align_section(MemoryRegionSection *section, hwaddr *start)
{
    hwaddr size = int128_get64(section->size);
    hwaddr delta, aligned;

    /* works in page size chunks, but the function may be called
   with sub-page size and unaligned start address. Pad the start
   address to next and truncate size to previous page boundary. */
    aligned = ROUND_UP(section->offset_within_address_space,
                       qemu_real_host_page_size());
    delta = aligned - section->offset_within_address_space;
    *start = aligned;
    if (delta > size) {
        return 0;
    }

    return (size - delta) & qemu_real_host_page_mask();
}

static int mshv_set_phys_mem(MshvMemoryListener *mml,
                             MemoryRegionSection *section, bool add,
                             const char *name)
{
    int ret = 0;
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    hwaddr start_addr, mr_offset, size;
    void *ram;
    /* MshvMemoryRegion tmp, *mshv_mr = &tmp; */
    MemoryRegionMgns tmp, *mshv_mr = &tmp;

    if (!memory_region_is_ram(area)) {
        if (writable) {
            return ret;
        } else if (!memory_region_is_romd(area)) {
            /*
             * If the memory device is not in romd_mode, then we actually want
             * to remove the memory slot so all accesses will trap.
             */
            add = false;
        }
    }

    size = align_section(section, &start_addr);
    if (!size) {
        return ret;
    }

    mr_offset = section->offset_within_region + start_addr -
                section->offset_within_address_space;

    ram = memory_region_get_ram_ptr(area) + mr_offset;

    memset(mshv_mr, 0, sizeof(*mshv_mr));
    mshv_mr->guest_phys_addr = start_addr;
    mshv_mr->memory_size = size;
    mshv_mr->readonly = !writable;
    mshv_mr->userspace_addr = (uint64_t)ram;

    /* ret = do_mshv_set_memory(mshv_mr, add); */
    ret = do_mshv_set_memory_mgns(mshv_mr, add);
    if (add && (ret == 17)) {
        // qemu may create a memory alias as rom.
        // However, mshv may not support the overlapped regions.
        // the mshv-qemu shim will handle the overlapped issue.
        return ret;
    }
    assert(ret == 0);
    return ret;
}

static void mshv_region_add(MemoryListener *listener,
                            MemoryRegionSection *section)
{
    MshvMemoryListener *mml =
        container_of(listener, MshvMemoryListener, listener);
    memory_region_ref(section->mr);
    mshv_set_phys_mem(mml, section, true, "add");
}

static void mshv_region_del(MemoryListener *listener,
                            MemoryRegionSection *section)
{
    MshvMemoryListener *mml =
        container_of(listener, MshvMemoryListener, listener);
    mshv_set_phys_mem(mml, section, false, "remove");
    memory_region_unref(section->mr);
}

void dump_user_ioeventfd_mgns(const struct mshv_user_ioeventfd *ioevent)
{
    printf("mshv_user_ioeventfd:\n");
    printf("  fd: %d\n", ioevent->fd);
    printf("  addr: %llu\n", ioevent->addr);
    printf("  datamatch: %llu\n", ioevent->datamatch);
    printf("  len: %u\n", ioevent->len);
    printf("  flags: %u\n", ioevent->flags);
    printf("  rsvd: %u %u %u %u\n",
           ioevent->rsvd[0], ioevent->rsvd[1],
           ioevent->rsvd[2], ioevent->rsvd[3]);
}

/* flags: determine whether to de/assign */
static int ioeventfd_mgns(int vm_fd,
						  int event_fd,
						  uint64_t addr,
						  DatamatchMgns dm,
						  uint32_t flags)
{
	int ret = 0;
	struct mshv_user_ioeventfd args = {0};
	args.fd = event_fd;
	args.addr = addr;
	args.flags = flags;

	if (dm.tag == DATAMATCH_NONE) {
		args.datamatch = 0;
	} else {
		flags |= BIT(MSHV_IOEVENTFD_BIT_DATAMATCH);
		args.flags = flags;
		if (dm.tag == DATAMATCH_U64) {
			args.len = sizeof(uint64_t);
			args.datamatch = dm.value.u64;
		} else {
			args.len = sizeof(uint32_t);
			args.datamatch = dm.value.u32;
		}
	}

	/* dump_mshv_user_ioeventfd_mgns(&args); */

	ret = ioctl(vm_fd, MSHV_IOEVENTFD, &args);
	return ret;
}

int unregister_ioevent_mgns(int vm_fd,
						    int event_fd,
						    uint64_t mmio_addr)
{
	uint32_t flags = 0;
	flags |= BIT(MSHV_IOEVENTFD_BIT_DEASSIGN);
	DatamatchMgns dm = {0};
	dm.tag = DATAMATCH_NONE;
	return ioeventfd_mgns(vm_fd, event_fd, mmio_addr, dm, flags);
}

int register_ioevent_mgns(int vm_fd,
						  int event_fd,
						  uint64_t mmio_addr,
						  uint64_t val,
						  bool is_64bit,
						  bool is_datamatch)
{
	uint32_t flags = 0;
	DatamatchMgns dm = {0};
	if (!is_datamatch) {
		dm.tag = DATAMATCH_NONE;
	} else if (is_64bit) {
		dm.tag = DATAMATCH_U64;
		dm.value.u64 = val;
	} else {
		dm.tag = DATAMATCH_U32;
		dm.value.u32 = val;
	}
	return ioeventfd_mgns(vm_fd, event_fd, mmio_addr, dm, flags);
}

static void mshv_mem_ioeventfd_add(MemoryListener *listener,
                                   MemoryRegionSection *section,
                                   bool match_data, uint64_t data,
                                   EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;
	/* TODO: mgns does this really matter if we 0 out the ioctl
	 * arg anyway?
	 */
    bool is_64 = int128_get64(section->size) == 8;
	uint64_t addr = section->offset_within_address_space
							 & 0xffffffff;

    trace_mshv_mem_ioeventfd_add(addr,
                                 int128_get64(section->size),
								 data);
	r = register_ioevent_mgns(mshv_state->vm, fd, addr, data,
							  is_64, match_data);

    if (r < 0) {
        mshv_err("%s: error adding ioeventfd: %s (%d)\n",
				 __func__,
                 strerror(-r), -r);
        abort();
    }
}

static void mshv_mem_ioeventfd_del(MemoryListener *listener,
                                   MemoryRegionSection *section,
                                   bool match_data, uint64_t data,
                                   EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r = 0;

    trace_mshv_mem_ioeventfd_del(section->offset_within_address_space,
                                 int128_get64(section->size), data);
	uint64_t addr = section->offset_within_address_space & 0xffffffff;
    r = unregister_ioevent_mgns(mshv_state->vm, fd, addr);
    if (r < 0) {
        mshv_err("%s: error adding ioeventfd: %s (%d)\n", __func__,
                 strerror(-r), -r);
        abort();
    }
}

static MemoryListener mshv_memory_listener = {
    .name = "mshv",
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
    .region_add = mshv_region_add,
    .region_del = mshv_region_del,
#ifdef MSHV_USE_IOEVENTFD
    .eventfd_add = mshv_mem_ioeventfd_add,
    .eventfd_del = mshv_mem_ioeventfd_del,
#endif
};

static MemoryListener mshv_io_listener = {
    .name = "mshv", .priority = MEMORY_LISTENER_PRIORITY_DEV_BACKEND,
    // MSHV does not support PIO eventfd
};

static void mshv_memory_listener_register(MshvState *s, MshvMemoryListener *mml,
                                          AddressSpace *as, int as_id,
                                          const char *name)
{
    int i;

    mml->listener = mshv_memory_listener;
    mml->listener.name = name;
    memory_listener_register(&mml->listener, as);
    for (i = 0; i < s->nr_as; ++i) {
        if (!s->as[i].as) {
            s->as[i].as = as;
            s->as[i].ml = mml;
            break;
        }
    }
}

static void mshv_reset(void *param)
{
    fprintf(stderr, "mshv_reset\n");
}

static void mshv_init_irq(MshvState *s) {}

static int mshv_init(MachineState *ms)
{
    MshvState *s;
    uint64_t vm_type;
	int mshv_fd, ret;

    s = MSHV_STATE(ms->accelerator);

    accel_blocker_init();

    /* mshv_new(); */
    s->vm = 0;

	init_vm_db_mgns();
	ret = init_mshv_mgns();
	if (ret < 0) {
		return -errno;
	}
	mshv_fd = ret;
	// cpu
	init_cpu_db_mgns();
	// irq
	init_msicontrol_mgns();
	// memory
	init_mem_manager_mgns();

    // TODO: object_property_find(OBJECT(current_machine), "mshv-type")
    vm_type = 0;
    do {
		// this creates an internal entry in the VM_DB hash table as a side
		// effect, we can make the fn return the PerVMInfo struct instead and
		// store it ourselves
		int vm_fd = create_vm_with_type_mgns(vm_type, mshv_fd);
		s->vm = vm_fd;
    } while (!s->vm);

	resume_vm_mgns(s->vm);

    // MAX number of address spaces:
    // address_space_memory
    s->nr_as = 1;
    s->as = g_new0(struct MshvAs, s->nr_as);

    mshv_state = s;

    qemu_register_reset(mshv_reset, NULL);

    mshv_init_irq(s);

    // register memory listener
    mshv_memory_listener_register(s, &s->memory_listener, &address_space_memory,
                                  0, "mshv-memory");
    memory_listener_register(&mshv_io_listener, &address_space_io);

    return 0;
}

static void mshv_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);

    ac->name = "MSHV";
    ac->init_machine = mshv_init;
    ac->allowed = &mshv_allowed;
}

static void mshv_accel_instance_init(Object *obj)
{
    MshvState *s = MSHV_STATE(obj);

    s->vm = 0;
}

static const TypeInfo mshv_accel_type = {
    .name = TYPE_MSHV_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = mshv_accel_instance_init,
    .class_init = mshv_accel_class_init,
    .instance_size = sizeof(MshvState),
};

static inline MemTxAttrs mshv_get_mem_attrs(bool is_secure_mode)
{
    return ((MemTxAttrs){ .secure = is_secure_mode });
}

void guest_mem_read_fn(uint64_t gpa, uint8_t *data, uintptr_t size,
					   bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, false);
    assert(ret == MEMTX_OK);
}

int guest_mem_write_fn(uint64_t gpa, const uint8_t *data, uintptr_t size,
                              bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, true);
    return ret;
}

void mmio_read_fn(uint64_t gpa, uint8_t *data, uintptr_t size,
                         bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, false);
    assert(ret == MEMTX_OK);
}

int mmio_write_fn(uint64_t gpa, const uint8_t *data, uintptr_t size,
				  bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, true);
    return ret;
}

void pio_read_fn(uint64_t port, uint8_t *data, uintptr_t size,
                 bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           false);
    assert(ret == MEMTX_OK);
}

int pio_write_fn(uint64_t port, const uint8_t *data, uintptr_t size,
			     bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = mshv_get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           true);
    return ret;
}

static int mshv_init_vcpu(CPUState *cpu)
{
    cpu->accel = g_new0(AccelCPUState, 1);

	int vm_fd = mshv_state->vm;
	uint8_t id = cpu->cpu_index;
    mshv_vcpufd(cpu) = create_vcpu_mgns(vm_fd, id);
    cpu->vcpu_dirty = false;

    return 0;
}

/* returns vm_fd on success, -errno on failure */
int create_partition_mgns(int mshv_fd)
{
	int ret;
	struct mshv_create_partition args = {0};

	// Initialize pt_flags with the desired features
	uint64_t pt_flags = (1ULL << MSHV_PT_BIT_LAPIC) |
						(1ULL << MSHV_PT_BIT_X2APIC) |
						(1ULL << MSHV_PT_BIT_GPA_SUPER_PAGES);

	// Set default isolation type
	uint64_t pt_isolation = MSHV_PT_ISOLATION_NONE;

	args.pt_flags = pt_flags;
	args.pt_isolation = pt_isolation;

	ret = ioctl(mshv_fd, MSHV_CREATE_PARTITION, &args);
	if (ret < 0) {
		perror("[mshv] Failed to create partition");
		return -errno;
	}
	return ret;
}

int initialize_vm_mgns(int vm_fd) {
	int ret = ioctl(vm_fd, MSHV_INITIALIZE_PARTITION);
	if (ret < 0) {
		perror("[mshv] Failed to initialize partition");
		return -errno;
	}
	return 0;
}

int hvcall_mgns(int mshv_fd, const struct mshv_root_hvcall *args) {
	int ret = 0;

	/* printf("args->code: %d\n", args->code); */
	/* printf("args->in_sz: %d\n", args->in_sz); */
	/* printf("args->in_ptr: %llu\n", args->in_ptr); */

	ret = ioctl(mshv_fd, MSHV_ROOT_HVCALL, args);
	if (ret < 0) {
		perror("[mshv] Failed to perform hvcall");
		return -errno;
	}
	return ret;
}

int create_vm_with_type_mgns(uint64_t vm_type, int mshv_fd) {
    MshvVmMgns *vm;
	int vm_fd;

	/* return error if vm_type is not 0 */
	if (vm_type != 0) {
		perror("[mgns] Invalid VM type");
		return -EINVAL;
	}

    /* Allocate and initialize MshvVm structure */
	vm = g_new0(MshvVmMgns, 1);
    if (!vm) {
        perror("[mgns] Failed to allocate memory for VM struct");
        close(mshv_fd);
        return -ENOMEM;
    }
    vm->fd = mshv_fd;

	/* Create partition */
	int ret = create_partition_mgns(mshv_fd);
	if (ret < 0) {
		close(mshv_fd);
		return -errno;
	}
	vm_fd = ret;
	printf("[mgns] Partition created w/ fd %d\n", vm_fd);

	/* Set synthetic proc features */
	ret = set_synthetic_proc_features_mgns(vm_fd);
	if (ret < 0) {
		return -errno;
	}
	printf("[mgns] Synthetic proc features set for fd %d\n", vm_fd);

	/* Initialize partition */
	ret = initialize_vm_mgns(vm_fd);
	if (ret < 0) {
		perror("[mgns] Failed to initialize partition");
		return -errno;
	}

	ret = set_unimplemented_msr_action_mgns(vm_fd);
	if (ret < 0) {
		return -errno;
	}

	/* Always create a frozen partition */
	pause_vm_mgns(vm_fd);
	printf("[mgns] Partition half-initialized for fd %d\n", vm_fd);

    /* Store VM in a global hash table (similar to VM_DB in Rust) */
	update_vm_db_mgns(vm_fd, vm);

    return vm_fd;
}

/* Default Microsoft Hypervisor behavior for unimplemented MSR is to  send a
 * fault to the guest if it tries to access it. It is possible to override
 * this behavior with a more suitable option i.e., ignore writes from the guest
 * and return zero in attempt to read unimplemented */
int set_unimplemented_msr_action_mgns(int vm_fd) {
    struct hv_input_set_partition_property in = {0};
    struct mshv_root_hvcall args = {0};

    in.property_code  = HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION;
    in.property_value = HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO;

    args.code   = HVCALL_SET_PARTITION_PROPERTY;
    args.in_sz  = sizeof(in);
    args.in_ptr = (uint64_t)&in;

	trace_mgns_hvcall_args("unimplemented_msr_action", args.code, args.in_sz);

	int ret = hvcall_mgns(vm_fd, &args);
    if (ret < 0) {
        perror("[mgns] Failed to set unimplemented MSR action");
        return -errno;
    }
    return 0;
}

int set_synthetic_proc_features_mgns(int vm_fd) {
	int ret;

	struct hv_input_set_partition_property in = {0};

	union hv_partition_synthetic_processor_features features = {0};

    // Access the bitfield and set the desired features
	features.hypervisor_present = 1;
	features.hv1 = 1;
	features.access_partition_reference_counter = 1;
	features.access_synic_regs = 1;
	features.access_synthetic_timer_regs = 1;
	features.access_partition_reference_tsc = 1;
	features.access_frequency_regs = 1;
	features.access_intr_ctrl_regs = 1;
	features.access_vp_index = 1;
	features.access_hypercall_regs = 1;
	features.access_guest_idle_reg = 1;
	features.tb_flush_hypercalls = 1;
	features.synthetic_cluster_ipi = 1;
	features.direct_synthetic_timers = 1;

	in.property_code = HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES;
	in.property_value = features.as_uint64[0];

	struct mshv_root_hvcall args = {0};
	args.code = HVCALL_SET_PARTITION_PROPERTY;
	args.in_sz = sizeof(in);
	args.in_ptr = (uint64_t)&in;

    trace_mgns_hvcall_args("synthetic_proc_features", args.code, args.in_sz);

	ret = hvcall_mgns(vm_fd, &args);
	if (ret < 0) {
		perror("[mgns] Failed to set synthethic proc features");
		return -errno;
	}
	return 0;
}

/* freeze 1 to pause, 0 to resume */
static inline int set_time_freeze_mgns(int vm_fd, int freeze) {
	int ret;

	if (freeze != 0 && freeze != 1) {
		perror("[mshv] Invalid time freeze value");
		return -1;
	}

	struct hv_input_set_partition_property in = {0};
	in.property_code = HV_PARTITION_PROPERTY_TIME_FREEZE;
	in.property_value = freeze;

	struct mshv_root_hvcall args = {0};
	args.code = HVCALL_SET_PARTITION_PROPERTY;
	args.in_sz = sizeof(in);
	args.in_ptr = (uint64_t)&in;

	ret = hvcall_mgns(vm_fd, &args);
	if (ret < 0) {
		perror("[mgns] Failed to set time freeze");
		return -errno;
	}

	return 0;
}

int pause_vm_mgns(int vm_fd) {
	int ret;

	ret = set_time_freeze_mgns(vm_fd, 1);
	if (ret < 0) {
		perror("[mgns] Failed to pause partition");
		ret = -errno;
	}

	return 0;
}


int resume_vm_mgns(int vm_fd) {
	int ret;

	ret = set_time_freeze_mgns(vm_fd, 0);
	if (ret < 0) {
		perror("[mgns] Failed to resume partition");
		ret = -errno;
	}

	return 0;
}

static int mshv_destroy_vcpu(CPUState *cpu)
{
    remove_vcpu_mgns(mshv_vcpufd(cpu));
    mshv_vcpufd(cpu) = 0;
    g_free(cpu->accel);
    return 0;
}

static int mshv_cpu_exec(CPUState *cpu)
{
    hv_message mshv_msg;
    enum VmExitMgns exit_reason;
    int ret = 0;

    bql_unlock();
    cpu_exec_start(cpu);

    do {
        if (cpu->vcpu_dirty) {
            ret = mshv_arch_put_registers(mshv_state, cpu);
            if (ret) {
                cpu->vcpu_dirty = false;
            }
        }

        if (qatomic_read(&cpu->exit_request)) {
            qemu_cpu_kick_self();
        }

        /* Read cpu->exit_request before KVM_RUN reads run->immediate_exit.
         * Matching barrier in kvm_eat_signals.
         */
        smp_rmb();

        exit_reason = run_vcpu_mgns(mshv_state->vm,
								    mshv_vcpufd(cpu),
									&mshv_msg);

        switch (exit_reason) {
        case VmExitIgnore:
            break;
        default:
            ret = EXCP_INTERRUPT;
            break;
        }
    } while (ret == 0);

    cpu_exec_end(cpu);
    bql_lock();

    if (ret < 0) {
        cpu_dump_state(cpu, stderr, CPU_DUMP_CODE);
        vm_stop(RUN_STATE_INTERNAL_ERROR);
    }

    qatomic_set(&cpu->exit_request, 0);
    return ret;
}

// The signal handler is triggered when QEMU's main thread receives a SIG_IPI
// (SIGUSR1). This signal causes the current CPU thread to be kicked, forcing a
// VM exit on the CPU. The VM exit generates an exit reason that breaks the loop
// (see mshv_cpu_exec). If the exit is due to a Ctrl+A+x command, the system
// will shut down. For other cases, the system will continue running.
static void sa_ipi_handler(int sig)
{
    qemu_cpu_kick_self();
}

static void mshv_init_signal(CPUState *cpu)
{
    /* init cpu signals */
    struct sigaction sigact;
    sigset_t set;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = sa_ipi_handler;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    pthread_sigmask(SIG_SETMASK, &set, NULL);
}

static void *mshv_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;

    rcu_register_thread();

    bql_lock();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    current_cpu = cpu;
    mshv_init_vcpu(cpu);
    mshv_init_signal(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        if (cpu_can_run(cpu)) {
            mshv_cpu_exec(cpu);
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));
    mshv_destroy_vcpu(cpu);
    cpu_thread_signal_destroyed(cpu);
    bql_unlock();
    rcu_unregister_thread();
    return NULL;
}

static void mshv_start_vcpu_thread(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));

    qemu_cond_init(cpu->halt_cond);

    trace_mshv_start_vcpu_thread(thread_name, cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, mshv_vcpu_thread_fn, cpu,
                       QEMU_THREAD_JOINABLE);
}

static void mshv_cpu_synchronize_post_init(CPUState *cpu)
{
    mshv_arch_put_registers(mshv_state, cpu);

    cpu->vcpu_dirty = false;
}

static void do_mshv_cpu_synchronize_pre_loadvm(CPUState *cpu,
                                               run_on_cpu_data arg)
{
    cpu->vcpu_dirty = true;
}

static void mshv_cpu_synchronize_pre_loadvm(CPUState *cpu)
{
    run_on_cpu(cpu, do_mshv_cpu_synchronize_pre_loadvm, RUN_ON_CPU_NULL);
}

static void do_mshv_cpu_synchronize(CPUState *cpu, run_on_cpu_data arg)
{
    mshv_arch_get_registers(mshv_state, cpu);
}

static void mshv_cpu_synchronize(CPUState *cpu)
{
    run_on_cpu(cpu, do_mshv_cpu_synchronize, RUN_ON_CPU_NULL);
}

static bool mshv_cpus_are_resettable(void)
{
    return false;
}

static void mshv_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->create_vcpu_thread = mshv_start_vcpu_thread;
    ops->synchronize_post_init = mshv_cpu_synchronize_post_init;
    ops->synchronize_state = mshv_cpu_synchronize;
    ops->synchronize_pre_loadvm = mshv_cpu_synchronize_pre_loadvm;
    ops->cpus_are_resettable = mshv_cpus_are_resettable;
}

static const TypeInfo mshv_accel_ops_type = {
    .name = ACCEL_OPS_NAME("mshv"),
    .parent = TYPE_ACCEL_OPS,
    .class_init = mshv_accel_ops_class_init,
    .abstract = true,
};

static void mshv_type_init(void)
{
    type_register_static(&mshv_accel_type);
    type_register_static(&mshv_accel_ops_type);
}

type_init(mshv_type_init);
