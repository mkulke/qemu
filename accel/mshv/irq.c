/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors: Ziqiao Zhou <ziqiaozhou@microsoft.com>
 *          Magnus Kulke <magnuskulke@microsoft.com>
 *          Stanislav Kinsburskii <skinsburskii@microsoft.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "linux/mshv.h"
#include "hw/hyperv/hvhdk_mini.h"
#include "qemu/osdep.h"
#include "hw/pci/msi.h"
#include "system/mshv.h"
#include "trace.h"
#include <stdint.h>
#include <sys/ioctl.h>

#define MSHV_IRQFD_RESAMPLE_FLAG (1 << MSHV_IRQFD_BIT_RESAMPLE)
#define MSHV_IRQFD_BIT_DEASSIGN_FLAG (1 << MSHV_IRQFD_BIT_DEASSIGN)

static MshvMsiControl *msi_control;
static QemuMutex msi_control_mutex;

void mshv_init_msicontrol(void)
{
    qemu_mutex_init(&msi_control_mutex);
    msi_control = g_new0(MshvMsiControl, 1);
    msi_control->gsi_routes = g_hash_table_new(g_direct_hash, g_direct_equal);
    msi_control->updated = false;
}

static int compare_irq_entry_ptr(const void *pa, const void *pb)
{
    const mshv_user_irq_entry *ea = (const mshv_user_irq_entry*)pa;
    const mshv_user_irq_entry *eb = (const mshv_user_irq_entry*)pb;

    if (ea->gsi < eb->gsi) return -1;
    if (ea->gsi > eb->gsi) return  1;
    return 0;
}

static int dump_msi_routing_table(void)
{
    GHashTableIter iter;
    gpointer        value;
    GPtrArray      *arr = g_ptr_array_new();

    g_hash_table_iter_init(&iter, msi_control->gsi_routes);
    while (g_hash_table_iter_next(&iter, NULL, &value))
    {
        g_ptr_array_add(arr, value);
    }

    qsort(arr->pdata, arr->len, sizeof(arr->pdata[0]), compare_irq_entry_ptr);

    for (guint i = 0; i < arr->len; i++) {
        struct mshv_user_irq_entry *e = arr->pdata[i];
        trace_mshv_msi_route(e->gsi, e->address_hi, e->address_lo, e->data);
    }

    g_ptr_array_free(arr, true);

    return 0;
}

/* Pass an eventfd which is to be used for injecting interrupts from userland */
static int irqfd(int vm_fd, int fd, int resample_fd, uint32_t gsi,
                 uint32_t flags)
{
    int ret;
    struct mshv_user_irqfd arg = {
        .fd = fd,
        .resamplefd = resample_fd,
        .gsi = gsi,
        .flags = flags,
    };

    ret = ioctl(vm_fd, MSHV_IRQFD, &arg);
    if (ret < 0) {
        error_report("Failed to set irqfd: gsi=%u, fd=%d", gsi, fd);
        return -1;
    }
    return ret;
}

static int unregister_irqfd(int vm_fd, int event_fd, uint32_t gsi)
{
    int ret;
    uint32_t flags = MSHV_IRQFD_BIT_DEASSIGN_FLAG;

    ret = irqfd(vm_fd, event_fd, 0, gsi, flags);
    if (ret < 0) {
        error_report("Failed to unregister irqfd: gsi=%u", gsi);
        return -errno;
    }
    return 0;
}

static int set_msi_routing(uint32_t gsi, uint64_t addr, uint32_t data)
{
    struct mshv_user_irq_entry *route;
    uint32_t high_addr = addr >> 32;
    uint32_t low_addr = addr & 0xFFFFFFFF;
    GHashTable *gsi_routes;

    trace_mshv_set_msi_routing(gsi, addr, data);

    if (gsi >= MSHV_MAX_MSI_ROUTES) {
        error_report("gsi >= MSHV_MAX_MSI_ROUTES");
        return -1;
    }

    assert(msi_control);

    WITH_QEMU_LOCK_GUARD(&msi_control_mutex) {
        gsi_routes = msi_control->gsi_routes;
        route = g_hash_table_lookup(gsi_routes, GINT_TO_POINTER(gsi));
        if (route) {
            if (route->address_hi == high_addr &&
                route->address_lo == low_addr  &&
                route->data       == data)
            {
                /* nothing to update */
                return 0;
            }

            /* free old route */
            g_free(route);
        }

        /* create new entry */
        route = g_new0(mshv_user_irq_entry, 1);
        route->gsi = gsi;
        route->address_hi = high_addr;
        route->address_lo = low_addr;
        route->data = data;

        g_hash_table_insert(gsi_routes, GINT_TO_POINTER(gsi), route);
        msi_control->updated = true;
    }

    return 0;
}

static int add_msi_routing(uint64_t addr, uint32_t data)
{
    struct mshv_user_irq_entry *route;
    uint32_t high_addr = addr >> 32;
    uint32_t low_addr = addr & 0xFFFFFFFF;
    int gsi;
    GHashTable *gsi_routes;

    trace_mshv_add_msi_routing(addr, data);

    assert(msi_control);

    WITH_QEMU_LOCK_GUARD(&msi_control_mutex) {
        /* find an empty slot */
        gsi = 0;
        gsi_routes = msi_control->gsi_routes;
        while (gsi < MSHV_MAX_MSI_ROUTES) {
            route = g_hash_table_lookup(gsi_routes, GINT_TO_POINTER(gsi));
            if (!route) {
                break;
            }
            gsi++;
        }
        if (gsi >= MSHV_MAX_MSI_ROUTES) {
            error_report("No empty gsi slot available");
            return -1;
        }

        /* create new entry */
        route = g_new0(struct mshv_user_irq_entry, 1);
        route->gsi = gsi;
        route->address_hi = high_addr;
        route->address_lo = low_addr;
        route->data = data;

        g_hash_table_insert(gsi_routes, GINT_TO_POINTER(gsi), route);
        msi_control->updated = true;
    }

    return gsi;
}

static int register_irqfd(int vm_fd, int event_fd, uint32_t gsi)
{
    int ret;

    trace_mshv_register_irqfd(vm_fd, event_fd, gsi);

    assert(msi_control);

    ret = irqfd(vm_fd, event_fd, 0, gsi, 0);
    if (ret < 0) {
        error_report("Failed to register irqfd: gsi=%u", gsi);
        return -1;
    }

    return 0;
}

static int commit_msi_routing_table(void)
{
    guint len;
    int i, ret, vm_fd = mshv_state->vm;
    size_t table_size;
    struct mshv_user_irq_table *table;
    GHashTableIter iter;
    gpointer key, value;
    mshv_user_irq_entry *route;

    assert(msi_control);

    WITH_QEMU_LOCK_GUARD(&msi_control_mutex) {
        if (!msi_control->updated) {
            /* nothing to update */
            return 0;
        }

        /* Calculate the size of the table */
        len = g_hash_table_size(msi_control->gsi_routes);
        table_size = sizeof(struct mshv_user_irq_table)
                     + len * sizeof(struct mshv_user_irq_entry);
        table = g_malloc0(table_size);

        g_hash_table_iter_init(&iter, msi_control->gsi_routes);
        i = 0;
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            route = value;
            table->entries[i] = *route;
            i++;
        }
        table->nr = i;

        trace_mshv_commit_msi_routing_table(vm_fd, len);
        dump_msi_routing_table();

        ret = ioctl(vm_fd, MSHV_SET_MSI_ROUTING, table);
        if (ret < 0) {
            error_report("Failed to commit msi routing table");
            g_free(table);
            return -1;
        }

        msi_control->updated = false;
    }
    return 0;
}

static int remove_msi_routing(uint32_t gsi)
{
    struct mshv_user_irq_entry *route;
    GHashTable *gsi_routes;

    trace_mshv_remove_msi_routing(gsi);

    if (gsi >= MSHV_MAX_MSI_ROUTES) {
        error_report("Invalid GSI: %u", gsi);
        return -1;
    }

    assert(msi_control);

    WITH_QEMU_LOCK_GUARD(&msi_control_mutex) {
        gsi_routes = msi_control->gsi_routes;
        route = g_hash_table_lookup(gsi_routes, GINT_TO_POINTER(gsi));
        if (route) {
            g_hash_table_remove(gsi_routes, GINT_TO_POINTER(gsi));
            g_free(route);
            msi_control->updated = true;
        }
    }

    return 0;
}

static int register_irqfd_with_resample(int vm_fd, int event_fd,
                                        int resample_fd, uint32_t gsi)
{
    int ret;
    uint32_t flags = MSHV_IRQFD_RESAMPLE_FLAG;

    ret = irqfd(vm_fd, event_fd, resample_fd, gsi, flags);
    if (ret < 0) {
        error_report("Failed to register irqfd with resample: gsi=%u", gsi);
        return -errno;
    }
    return 0;
}

static int irqchip_update_irqfd_notifier_gsi(const EventNotifier *event,
                                             const EventNotifier *resample,
                                             int virq, bool add)
{
    int fd = event_notifier_get_fd(event);
    int rfd = resample ? event_notifier_get_fd(resample) : -1;
    int vm_fd = mshv_state->vm;

    trace_mshv_irqchip_update_irqfd_notifier_gsi(fd, rfd, virq, add);

    if (!add) {
        return unregister_irqfd(vm_fd, fd, virq);
    }

    if (rfd > 0) {
        return register_irqfd_with_resample(vm_fd, fd, rfd, virq);
    }

    return register_irqfd(vm_fd, fd, virq);
}


int mshv_irqchip_add_msi_route(int vector, PCIDevice *dev)
{
    MSIMessage msg = { 0, 0 };
    int virq = 0;

    if (pci_available && dev) {
        msg = pci_get_msi_message(dev, vector);
        virq = add_msi_routing(msg.address, le32_to_cpu(msg.data));
    }

    return virq;
}

void mshv_irqchip_release_virq(int virq)
{
    remove_msi_routing(virq);
}

int mshv_irqchip_update_msi_route(int virq, MSIMessage msg, PCIDevice *dev)
{
    int ret;

    ret = set_msi_routing(virq, msg.address, le32_to_cpu(msg.data));
    if (ret < 0) {
        error_report("Failed to set msi routing");
        return -1;
    }

    return 0;
}

int mshv_request_interrupt(int vm_fd, uint32_t interrupt_type, uint32_t vector,
                           uint32_t vp_index, bool logical_dest_mode,
                           bool level_triggered)
{
    int ret;

    if (vector == 0) {
        warn_report("Ignoring request for interrupt vector 0");
        return 0;
    }

    union hv_interrupt_control control = {
        .interrupt_type = interrupt_type,
        .level_triggered = level_triggered,
        .logical_dest_mode = logical_dest_mode,
        .rsvd = 0,
    };

    struct hv_input_assert_virtual_interrupt arg = {0};
    arg.control = control;
    arg.dest_addr = (uint64_t)vp_index;
    arg.vector = vector;

    struct mshv_root_hvcall args = {0};
    args.code   = HVCALL_ASSERT_VIRTUAL_INTERRUPT;
    args.in_sz  = sizeof(arg);
    args.in_ptr = (uint64_t)&arg;

    ret = mshv_hvcall(vm_fd, &args);
    if (ret < 0) {
        error_report("Failed to request interrupt");
        return -errno;
    }
    return 0;
}

void mshv_irqchip_commit_routes(void)
{
    int ret;

    ret = commit_msi_routing_table();
    if (ret < 0) {
        error_report("Failed to commit msi routing table");
        abort();
    }
}

int mshv_irqchip_add_irqfd_notifier_gsi(const EventNotifier *event,
                                        const EventNotifier *resample,
                                        int virq)
{
    return irqchip_update_irqfd_notifier_gsi(event, resample, virq, true);
}

int mshv_irqchip_remove_irqfd_notifier_gsi(const EventNotifier *event,
                                           int virq)
{
    return irqchip_update_irqfd_notifier_gsi(event, NULL, virq, false);
}
