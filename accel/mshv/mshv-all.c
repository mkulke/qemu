#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/module.h"

#include "hw/hyperv/hvhdk.h"
#include "hw/hyperv/hvhdk_mini.h"
#include "hw/hyperv/hvgdk.h"
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

#include "emulate/x86_decode.h"
#include "emulate/x86_emu.h"

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

DECLARE_INSTANCE_CHECKER(MshvState, MSHV_STATE, TYPE_MSHV_ACCEL)

bool mshv_allowed;

MshvState *mshv_state;

static int init_mshv(void) {
    int mshv_fd = open("/dev/mshv", O_RDWR | O_CLOEXEC);
    if (mshv_fd < 0) {
        error_report("Failed to open /dev/mshv: %s", strerror(errno));
        return -1;
    }
    return mshv_fd;
}

/* freeze 1 to pause, 0 to resume */
static int set_time_freeze(int vm_fd, int freeze)
{
    int ret;

    if (freeze != 0 && freeze != 1) {
        error_report("Invalid time freeze value");
        return -1;
    }

    struct hv_input_set_partition_property in = {0};
    in.property_code = HV_PARTITION_PROPERTY_TIME_FREEZE;
    in.property_value = freeze;

    struct mshv_root_hvcall args = {0};
    args.code = HVCALL_SET_PARTITION_PROPERTY;
    args.in_sz = sizeof(in);
    args.in_ptr = (uint64_t)&in;

    ret = mshv_hvcall(vm_fd, &args);
    if (ret < 0) {
        error_report("Failed to set time freeze");
        return -1;
    }

    return 0;
}

static int pause_vm(int vm_fd)
{
    int ret;

    ret = set_time_freeze(vm_fd, 1);
    if (ret < 0) {
        error_report("Failed to pause partition");
        ret = -1;
    }

    return 0;
}

static int resume_vm(int vm_fd)
{
    int ret;

    ret = set_time_freeze(vm_fd, 0);
    if (ret < 0) {
        error_report("Failed to resume partition");
        ret = -1;
    }

    return 0;
}

/* returns vm_fd on success, -errno on failure */
static int create_partition(int mshv_fd)
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
        error_report("Failed to create partition: %s", strerror(errno));
        return -1;
    }
    return ret;
}

static int set_synthetic_proc_features(int vm_fd) {
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

    trace_mshv_hvcall_args("synthetic_proc_features", args.code, args.in_sz);

    ret = mshv_hvcall(vm_fd, &args);
    if (ret < 0) {
        error_report("Failed to set synthethic proc features");
        return -errno;
    }
    return 0;
}

static int initialize_vm(int vm_fd)
{
    int ret = ioctl(vm_fd, MSHV_INITIALIZE_PARTITION);
    if (ret < 0) {
        error_report("Failed to initialize partition");
        return -errno;
    }
    return 0;
}

/* Default Microsoft Hypervisor behavior for unimplemented MSR is to  send a
 * fault to the guest if it tries to access it. It is possible to override
 * this behavior with a more suitable option i.e., ignore writes from the guest
 * and return zero in attempt to read unimplemented */
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

static int create_vm_with_type(MshvVmType vm_type, int mshv_fd)
{
    int vm_fd;

    if (vm_type != MSHV_VM_TYPE_DEFAULT) {
        error_report("Invalid VM type: %d", vm_type);
        return -EINVAL;
    }

    int ret = create_partition(mshv_fd);
    if (ret < 0) {
        close(mshv_fd);
        return -errno;
    }
    vm_fd = ret;

    ret = set_synthetic_proc_features(vm_fd);
    if (ret < 0) {
        return -errno;
    }

    ret = initialize_vm(vm_fd);
    if (ret < 0) {
        return -1;
    }

    ret = set_unimplemented_msr_action(vm_fd);
    if (ret < 0) {
        return -1;
    }

    /* Always create a frozen partition */
    pause_vm(vm_fd);

    return vm_fd;
}

static int set_memory(const MshvMemoryRegion *mshv_mr, bool add)
{
    int ret = 0;

    if (!mshv_mr) {
        error_report("Invalid mshv_mr");
        return -1;
    }

    trace_mshv_set_memory(add, mshv_mr->guest_phys_addr,
                          mshv_mr->memory_size,
                          mshv_mr->userspace_addr, mshv_mr->readonly,
                          ret);
    if (add) {
        return mshv_add_mem(mshv_state->vm, mshv_mr);
    }
    return mshv_remove_mem(mshv_state->vm, mshv_mr);
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

static int set_phys_mem(MshvMemoryListener *mml, MemoryRegionSection *section,
                        bool add, const char *name)
{
    int ret = 0;
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    hwaddr start_addr, mr_offset, size;
    void *ram;
    MshvMemoryRegion tmp, *mshv_mr = &tmp;

    if (!memory_region_is_ram(area)) {
        if (writable) {
            return ret;
        } else if (!memory_region_is_romd(area)) {
            /* If the memory device is not in romd_mode, then we
             * actually want to remove the memory slot so all accesses
             * will trap.
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

    ret = set_memory(mshv_mr, add);
    if (add && (ret == 17)) {
        /* TODO: Qemu may create a memory alias as rom. However, mshv may not
         * support the overlapped regions. We'll have to handle it in upper
         * layers.
         */
        return ret;
    }
    assert(ret == 0);

    return ret;
}

static void mem_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    MshvMemoryListener *mml;
    mml = container_of(listener, MshvMemoryListener, listener);
    memory_region_ref(section->mr);
    set_phys_mem(mml, section, true, "add");
}

static void mem_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    MshvMemoryListener *mml;
    mml = container_of(listener, MshvMemoryListener, listener);
    set_phys_mem(mml, section, false, "remove");
    memory_region_unref(section->mr);
}

typedef enum {
    DATAMATCH_NONE,
    DATAMATCH_U32,
    DATAMATCH_U64,
} DatamatchTag;

typedef struct {
    DatamatchTag tag;
    union {
        uint32_t u32;
        uint64_t u64;
    } value;
} Datamatch;

/* flags: determine whether to de/assign */
static int ioeventfd(int vm_fd, int event_fd, uint64_t addr, Datamatch dm,
                     uint32_t flags)
{
    int ret = 0;
    mshv_user_ioeventfd args = {0};
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

    ret = ioctl(vm_fd, MSHV_IOEVENTFD, &args);
    return ret;
}

static int unregister_ioevent(int vm_fd, int event_fd, uint64_t mmio_addr)
{
    uint32_t flags = 0;
    Datamatch dm = {0};

    flags |= BIT(MSHV_IOEVENTFD_BIT_DEASSIGN);
    dm.tag = DATAMATCH_NONE;

    return ioeventfd(vm_fd, event_fd, mmio_addr, dm, flags);
}

static int register_ioevent(int vm_fd, int event_fd, uint64_t mmio_addr,
                            uint64_t val, bool is_64bit, bool is_datamatch)
{
    uint32_t flags = 0;
    Datamatch dm = {0};

    if (!is_datamatch) {
        dm.tag = DATAMATCH_NONE;
    } else if (is_64bit) {
        dm.tag = DATAMATCH_U64;
        dm.value.u64 = val;
    } else {
        dm.tag = DATAMATCH_U32;
        dm.value.u32 = val;
    }

    return ioeventfd(vm_fd, event_fd, mmio_addr, dm, flags);
}

static void mem_ioeventfd_add(MemoryListener *listener,
                              MemoryRegionSection *section,
                              bool match_data, uint64_t data,
                              EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int ret;
    bool is_64 = int128_get64(section->size) == 8;
    uint64_t addr = section->offset_within_address_space & 0xffffffff;

    trace_mshv_mem_ioeventfd_add(addr, int128_get64(section->size), data);

    ret = register_ioevent(mshv_state->vm, fd, addr, data, is_64, match_data);

    if (ret < 0) {
        error_report("Failed to register ioeventfd: %s (%d)\n", strerror(-ret),
                     -ret);
        abort();
    }
}

static void mem_ioeventfd_del(MemoryListener *listener,
                              MemoryRegionSection *section,
                              bool match_data, uint64_t data,
                              EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int ret;
    uint64_t addr = section->offset_within_address_space & 0xffffffff;

    trace_mshv_mem_ioeventfd_del(section->offset_within_address_space,
                                 int128_get64(section->size), data);

    ret = unregister_ioevent(mshv_state->vm, fd, addr);
    if (ret < 0) {
        error_report("Failed to unregister ioeventfd: %s (%d)\n",
                     strerror(-ret), -ret);
        abort();
    }
}

static MemoryListener mshv_memory_listener = {
    .name = "mshv",
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
    .region_add = mem_region_add,
    .region_del = mem_region_del,
#ifdef MSHV_USE_IOEVENTFD
    .eventfd_add = mem_ioeventfd_add,
    .eventfd_del = mem_ioeventfd_del,
#endif
};

static MemoryListener mshv_io_listener = {
    .name = "mshv", .priority = MEMORY_LISTENER_PRIORITY_DEV_BACKEND,
    /* MSHV does not support PIO eventfd */
};

static void register_mshv_memory_listener(MshvState *s, MshvMemoryListener *mml,
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

int mshv_hvcall(int mshv_fd, const struct mshv_root_hvcall *args)
{
    int ret = 0;

    ret = ioctl(mshv_fd, MSHV_ROOT_HVCALL, args);
    if (ret < 0) {
        error_report("Failed to perform hvcall: %s", strerror(errno));
        return -1;
    }
    return ret;
}

static inline MemTxAttrs get_mem_attrs(bool is_secure_mode)
{
    MemTxAttrs memattr = {0};
    memattr.secure = is_secure_mode;
    return memattr;
}

void mshv_pio_read(uint64_t port, uint8_t *data, uintptr_t size,
                 bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           false);
    assert(ret == MEMTX_OK);
}

int mshv_pio_write(uint64_t port, const uint8_t *data, uintptr_t size,
                 bool is_secure_mode)
{
    int ret = 0;
    MemTxAttrs memattr = get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_io, port, memattr, (void *)data, size,
                           true);
    return ret;
}

static int mshv_init_vcpu(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    int vm_fd = mshv_state->vm;
    uint8_t vp_index = cpu->cpu_index;
    int ret;

    env->emu_mmio_buf = g_new(char, 4096);
    cpu->accel = g_new0(AccelCPUState, 1);

    ret = mshv_create_vcpu(vm_fd, vp_index, &cpu->accel->cpufd);
    if (ret < 0) {
        return -1;
    }

    cpu->vcpu_dirty = false;

    return 0;
}

static int mshv_init(MachineState *ms)
{
    MshvState *s;
    MshvVmType vm_type;
    int mshv_fd, ret;

    s = MSHV_STATE(ms->accelerator);

    accel_blocker_init();

    s->vm = 0;

    ret = init_mshv();
    if (ret < 0) {
        return -errno;
    }
    mshv_fd = ret;

    // cpu
    mshv_init_cpu_logic();

    // irq
    mshv_init_msicontrol();

    // memory
    mshv_init_mem_manager();

    /* TODO: object_property_find(OBJECT(current_machine), "mshv-type") */
    vm_type = 0;
    do {
        /* this creates an internal entry in the VM_DB hash table as a side */
        /* effect, we can make the fn return the PerVMInfo struct instead and */
        /* store it ourselves */
        int vm_fd = create_vm_with_type(vm_type, mshv_fd);
        s->vm = vm_fd;
    } while (!s->vm);

    resume_vm(s->vm);

    /* MAX number of address spaces: */
    /* address_space_memory */
    s->nr_as = 1;
    s->as = g_new0(struct MshvAs, s->nr_as);

    mshv_state = s;

    qemu_register_reset(mshv_reset, NULL);

    mshv_init_irq(s);

    register_mshv_memory_listener(s, &s->memory_listener, &address_space_memory,
                                  0, "mshv-memory");
    memory_listener_register(&mshv_io_listener, &address_space_io);

    return 0;
}

static int mshv_destroy_vcpu(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    int cpu_fd = mshv_vcpufd(cpu);
    int vm_fd = mshv_state->vm;

    mshv_remove_vcpu(vm_fd, cpu_fd);
    mshv_vcpufd(cpu) = 0;

    g_free(env->emu_mmio_buf);
    g_free(cpu->accel);
    return 0;
}

static int mshv_cpu_exec(CPUState *cpu)
{
    hv_message mshv_msg;
    enum MshvVmExit exit_reason;
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

        ret = mshv_run_vcpu(mshv_state->vm, cpu, &mshv_msg, &exit_reason);
        if (ret < 0) {
            error_report("Failed to to run on vcpu");
            abort();
        }

        switch (exit_reason) {
        case MshvVmExitIgnore:
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
    mshv_load_regs(cpu);
}

static void mshv_cpu_synchronize(CPUState *cpu)
{
    run_on_cpu(cpu, do_mshv_cpu_synchronize, RUN_ON_CPU_NULL);
}

static bool mshv_cpus_are_resettable(void)
{
    return false;
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
