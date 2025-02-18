#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "hw/pci/msi.h"
#include "sysemu/mshv.h"
#include "trace.h"
#include <stdint.h>
#include <sys/ioctl.h>

static struct MsiControlMgns *msi_control_mgns;
static QemuMutex msi_control_mutex_mgns;
/* gint global_counter_mgns = 0; */

void init_msicontrol_mgns(void) {
    qemu_mutex_init(&msi_control_mutex_mgns);
    msi_control_mgns = g_new0(struct MsiControlMgns, 1);
	msi_control_mgns->gsi_routes = g_hash_table_new(g_direct_hash, g_direct_equal);
	msi_control_mgns->updated = false;
}

int set_msi_routing_mgns(uint32_t gsi, uint64_t addr, uint32_t data)
{
	struct mshv_user_irq_entry *entry;
	uint32_t high_addr = addr >> 32;
	uint32_t low_addr = addr & 0xFFFFFFFF;

	trace_mgns_set_msi_routing(gsi, addr, data);

	if (gsi >= MSHV_MAX_MSI_ROUTES) {
		perror("gsi >= MSHV_MAX_MSI_ROUTES");
		return -1;
	}

	WITH_QEMU_LOCK_GUARD(&msi_control_mutex_mgns) {
		entry = g_hash_table_lookup(msi_control_mgns->gsi_routes, GINT_TO_POINTER(gsi));
		if (entry) {
			if (entry->address_hi == high_addr && entry->address_lo == low_addr && entry->data == data)
			{
				/* nothing to update */
				return 0;
			}
		}
		/* free old entry */
		g_free(entry);
		/* create new entry */
		entry = g_new0(struct mshv_user_irq_entry, 1);
		entry->gsi = gsi;
		entry->address_hi = high_addr;
		entry->address_lo = low_addr;
		entry->data = data;

		g_hash_table_insert(msi_control_mgns->gsi_routes, GINT_TO_POINTER(gsi), entry);
		msi_control_mgns->updated = true;
	}

	return 0;
}

int add_msi_routing_mgns(uint64_t addr, uint32_t data)
{
	struct mshv_user_irq_entry *route_entry;
	uint32_t high_addr = addr >> 32;
	uint32_t low_addr = addr & 0xFFFFFFFF;
	int gsi;

	trace_mgns_add_msi_routing(addr, data);

	WITH_QEMU_LOCK_GUARD(&msi_control_mutex_mgns) {
		/* find an empty slot */
		gsi = 0;
		while (gsi < MSHV_MAX_MSI_ROUTES) {
			route_entry = g_hash_table_lookup(msi_control_mgns->gsi_routes, GINT_TO_POINTER(gsi));
			if (!route_entry) {
				break;
			}
			gsi++;
		}
		if (gsi >= MSHV_MAX_MSI_ROUTES) {
			perror("no empty gsi slot available. gsi >= MSHV_MAX_MSI_ROUTES");
			return -1;
		}
		/* create new entry */
		route_entry = g_new0(struct mshv_user_irq_entry, 1);
		route_entry->gsi = gsi;
		route_entry->address_hi = high_addr;
		route_entry->address_lo = low_addr;
		route_entry->data = data;

		g_hash_table_insert(msi_control_mgns->gsi_routes, GINT_TO_POINTER(gsi), route_entry);
		msi_control_mgns->updated = true;
	}

	return gsi;
}

int commit_msi_routing_table_mgns(int vm_fd)
{
	guint len;
	int i, ret;
	size_t table_size;
	struct mshv_user_irq_table *table;
	GHashTableIter iter;
	gpointer key, value;

	WITH_QEMU_LOCK_GUARD(&msi_control_mutex_mgns) {
		if (!msi_control_mgns->updated) {
			/* nothing to update */
			return 0;
		}

		/* Calculate the size of the table */
		len = g_hash_table_size(msi_control_mgns->gsi_routes);
		table_size = sizeof(struct mshv_user_irq_table)
					 + len * sizeof(struct mshv_user_irq_entry);
		table = g_malloc0(table_size);

		g_hash_table_iter_init(&iter, msi_control_mgns->gsi_routes);
		i = 0;
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			struct mshv_user_irq_entry *entry = value;
			table->entries[i] = *entry;
			i++;
		}

		trace_mgns_commit_msi_routing_table(vm_fd, len);

		ret = ioctl(vm_fd, MSHV_SET_MSI_ROUTING, table);
		g_free(table);
		if (ret < 0) {
			perror("[mshv] failed to update msi routing table");
			return -1;
		}
		msi_control_mgns->updated = false;
	}
	return 0;
}

int remove_msi_routing_mgns(uint32_t gsi)
{
	struct mshv_user_irq_entry *route_entry;

	trace_mgns_remove_msi_routing(gsi);

	WITH_QEMU_LOCK_GUARD(&msi_control_mutex_mgns) {
		route_entry = g_hash_table_lookup(msi_control_mgns->gsi_routes, GINT_TO_POINTER(gsi));
		if (route_entry) {
			g_hash_table_remove(msi_control_mgns->gsi_routes, GINT_TO_POINTER(gsi));
			g_free(route_entry);
			msi_control_mgns->updated = true;
		}
	}

	return 0;
}

int register_irqfd_mgns(int vm_fd, int event_fd, uint32_t gsi)
{
	int ret;

	trace_mgns_register_irqfd(vm_fd, event_fd, gsi);

	ret = irqfd_mgns(vm_fd, event_fd, 0, gsi, 0);
	if (ret < 0) {
		perror("[mshv] failed to register irqfd");
		return -errno;
	}
	return 0;
}

int register_irqfd_with_resample_mgns(int vm_fd, int event_fd, int resample_fd, uint32_t gsi)
{
	int ret;
	uint32_t flags = (1 << MSHV_IRQFD_BIT_RESAMPLE);

	ret = irqfd_mgns(vm_fd, event_fd, resample_fd, gsi, flags);
	if (ret < 0) {
		perror("[mshv] failed to register irqfd with resample");
		return -errno;
	}
	return 0;
}

int unregister_irqfd_mgns(int vm_fd, int event_fd, uint32_t gsi)
{
	int ret;
	uint32_t flags = (1 << MSHV_IRQFD_BIT_DEASSIGN);

	ret = irqfd_mgns(vm_fd, event_fd, 0, gsi, flags);
	if (ret < 0) {
		perror("[mshv] failed to unregister irqfd");
		return -errno;
	}
	return 0;
}

/* Pass an eventfd which is to be used for injecting interrupts from userland */
int irqfd_mgns(int vm_fd, int fd, int resample_fd, uint32_t gsi, uint32_t flags)
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
		perror("[mshv] failed to set irqfd");
		return -errno;
	}
	return ret;
}

int mshv_irqchip_add_msi_route(int vector, PCIDevice *dev)
{
    MSIMessage msg = { 0, 0 };
    int virq = 0;

    if (pci_available && dev) {
        msg = pci_get_msi_message(dev, vector);
		virq = add_msi_routing_mgns(msg.address, le32_to_cpu(msg.data));
    }

    return virq;
}

void mshv_irqchip_release_virq(int virq)
{
	remove_msi_routing_mgns(virq);
}

int mshv_irqchip_update_msi_route(int virq, MSIMessage msg, PCIDevice *dev)
{
	int ret;

	ret = set_msi_routing_mgns(virq, msg.address, le32_to_cpu(msg.data));
	if (ret < 0) {
		perror("failed to set msi routing");
		return -1;
	}

    return 0;
}

int request_interrupt_mgns(int vm_fd, uint32_t interrupt_type, uint32_t vector,
						   uint32_t vp_index, bool logical_dest_mode,
						   bool level_triggered)
{
	int ret;

	if (vector == 0) {
		// TODO: why do we receive this?
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

	ret = hvcall_mgns(vm_fd, &args);
    if (ret < 0) {
        perror("[mgns] failed to request interrupt");
        return -errno;
    }
	return 0;
}


void mshv_irqchip_commit_routes(void)
{
	commit_msi_routing_table_mgns(mshv_state->vm);
}

static int mshv_irqchip_update_irqfd_notifier_gsi(MshvState *s,
                                                  EventNotifier *event,
                                                  EventNotifier *resample,
                                                  int virq, bool add)
{
    int fd = event_notifier_get_fd(event);
    int rfd = resample ? event_notifier_get_fd(resample) : -1;

	trace_mshv_irqchip_update_irqfd_notifier_gsi(fd, rfd, virq, add);

	if (!add) {
		return unregister_irqfd_mgns(s->vm, fd, virq);
	}

	if (rfd > 0) {
		return register_irqfd_with_resample_mgns(s->vm, fd, rfd, virq);
	}

	return register_irqfd_mgns(s->vm, fd, virq);
}

int mshv_irqchip_add_irqfd_notifier_gsi(EventNotifier *n, EventNotifier *rn,
                                        int virq)
{
    return mshv_irqchip_update_irqfd_notifier_gsi(mshv_state, n, rn, virq,
                                                  true);
}

int mshv_irqchip_remove_irqfd_notifier_gsi(EventNotifier *n, int virq)
{
    return mshv_irqchip_update_irqfd_notifier_gsi(mshv_state, n, NULL, virq,
                                                  false);
}
