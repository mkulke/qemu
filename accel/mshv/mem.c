#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "sysemu/mshv.h"
#include <stdint.h>
#include <sys/ioctl.h>

/* #include "hw/pci/pci.h" */
/* #include "sysemu/dma.h" */
 
static GHashTable *dirty_log_slots_mgns;
static QemuMutex dirty_log_slots_mutex_mgns;
static MemManagerMgns *mem_manager_mgns;
static QemuMutex mem_manager_mutex_mgns;

void init_mem_manager_mgns(void)
{
	qemu_mutex_init(&mem_manager_mutex_mgns);
	mem_manager_mgns = g_new0(MemManagerMgns, 1);
	mem_manager_mgns->mem_entries = NULL;
}

void init_dirty_log_slots_mgns(void)
{
    qemu_mutex_init(&dirty_log_slots_mutex_mgns);
	dirty_log_slots_mgns = g_hash_table_new(g_direct_hash, g_direct_equal);
}

int set_dirty_log_slot_mgns(uint64_t guest_pfn, uint64_t memory_size)
{
	struct DirtyLogSlotMgns *slot;

	WITH_QEMU_LOCK_GUARD(&dirty_log_slots_mutex_mgns) {
		slot = g_new0(struct DirtyLogSlotMgns, 1);
		if (!slot) {
			perror("failed to allocate memory for DirtyLogSlot");
			return -1;
		}
		slot->guest_pfn = guest_pfn;
		slot->memory_size = memory_size;
		g_hash_table_insert(dirty_log_slots_mgns, GINT_TO_POINTER(guest_pfn), slot);
	}

	return 0;
}

int remove_dirty_log_slot_mgns(uint64_t guest_pfn)
{
	struct DirtyLogSlotMgns *slot;

	WITH_QEMU_LOCK_GUARD(&dirty_log_slots_mutex_mgns) {
		slot = g_hash_table_lookup(dirty_log_slots_mgns, GINT_TO_POINTER(guest_pfn));
		if (slot == NULL) {
			perror("failed to find DirtyLogSlot entry");
			return -1;
		}
		g_hash_table_remove(dirty_log_slots_mgns, GINT_TO_POINTER(guest_pfn));
		g_free(slot);
	}

	return 0;
}

static int set_guest_memory_mgns(int vm_fd, struct mshv_user_mem_region *region)
{
	printf("[mgns-qemu] set_guest_memory_mgns (enabled)\n");
	printf("[mgns-qemu]   guest_pfn:      0x%08llx\n", region->guest_pfn); 
	printf("[mgns-qemu]   size:           0x%08llx\n", region->size);
	printf("[mgns-qemu]   userspace_addr: 0x%016llx\n", region->userspace_addr);
	printf("[mgns-qemu]   rsvd:           skip\n");
	printf("[mgns-qemu]   flags:          0x%04x\n", region->flags);

	int ret;

	ret = ioctl(vm_fd, MSHV_SET_GUEST_MEMORY, region);
	if (ret < 0) {
		perror("failed to set guest memory");
		return errno;
	}

	return 0;
}

static int create_user_memory_region_mgns(int vm_fd, struct mshv_user_mem_region *region)
{
	int ret;

	/* printf("[mgns-qemu] create user memory region: %llx\n", region->guest_pfn); */

	ret = set_dirty_log_slot_mgns(region->guest_pfn, region->size);
	if (ret < 0) {
		perror("failed to set dirty log slot");
		return -1;
	}

	set_guest_memory_mgns(vm_fd, region);
	if (ret < 0) {
		perror("failed to map user memory");
		return -1;
	}
	return 0;
}

static int remove_user_memory_region_mgns(int vm_fd, struct mshv_user_mem_region *region)
{
	int ret;

	/* printf("[mgns-qemu] removing user memory region: %llx\n", region->guest_pfn); */

	ret = remove_dirty_log_slot_mgns(region->guest_pfn);
	if (ret < 0) {
		perror("failed to remove dirty log slot");
		return -1;
	}

	ret = set_guest_memory_mgns(vm_fd, region);
	if (ret < 0) {
		perror("failed to map user memory");
		return -1;
	}

	return 0;
}

static int map_or_unmap_mgns(int vm_fd, const MemoryRegionMgns *mr, bool add)
{
	struct mshv_user_mem_region region = {0};

	/* printf("[mgns-qemu] map_or_unmap_mgns: guest_phys_addr %lx, add: %u\n", mr->guest_phys_addr, add); */
	
	region.flags |= (1 << MSHV_SET_MEM_BIT_EXECUTABLE);
	if (!mr->readonly) {
		region.flags |= (1 << MSHV_SET_MEM_BIT_WRITABLE);
	}
	region.guest_pfn = mr->guest_phys_addr >> MSHV_PAGE_SHIFT;
	region.size = mr->memory_size;
	region.userspace_addr = mr->userspace_addr;

	if (add) {
		region.flags &= ~(1 << MSHV_SET_MEM_BIT_UNMAP);
		return create_user_memory_region_mgns(vm_fd, &region);
	}

	region.flags = (1 << MSHV_SET_MEM_BIT_UNMAP);
	return remove_user_memory_region_mgns(vm_fd, &region);
}


bool find_by_gpa_mgns(uint64_t addr, size_t *index)
{
	MemEntryMgns *entry;
	GList *entries;
	size_t i = 0;

	entries = mem_manager_mgns->mem_entries;
	for(GList* elem = entries; elem != NULL; elem = elem->next) {
		entry = elem->data;
		if (entry->mr.guest_phys_addr <= addr
			&& addr - entry->mr.guest_phys_addr < entry->mr.memory_size) {
			*index = i;
			return true;
		}
		i++;
	}

	return false;
}

static bool find_overlap_region_mgns(size_t gpa_idx, MemoryRegionMgns *mr, size_t *overlap_idx)
{
	MemEntryMgns *entry;
	GList *entries;
	size_t i = 0;

	entries = mem_manager_mgns->mem_entries;
	for(GList* elem = entries; elem != NULL; elem = elem->next) {
		entry = elem->data;

		if(i != gpa_idx
			&& (entry->mr.userspace_addr < mr->userspace_addr + mr->memory_size)
			&& (entry->mr.userspace_addr + entry->mr.memory_size > mr->userspace_addr)
			&& entry->mapped) {
			*overlap_idx = i;
			return true;
		}
		i++;
	}

	return false;
}

bool map_overlapped_region_mgns(int vm_fd, uint64_t gpa)
{
	size_t gpa_idx, overlap_idx;
	MemEntryMgns *gpa_entry, *overlap_entry;
	int ret;

	WITH_QEMU_LOCK_GUARD(&mem_manager_mutex_mgns) {
		if (!find_by_gpa_mgns(gpa, &gpa_idx)) {
			return false;
		}
		gpa_entry = g_list_nth_data(mem_manager_mgns->mem_entries, gpa_idx);
		if (!gpa_entry) {
			perror("unexpected error. failed to find mem entry");
			abort();
		}

		if (!find_overlap_region_mgns(gpa_idx, &gpa_entry->mr, &overlap_idx)) {
			return false;
		}
		if (gpa_idx == overlap_idx) {
			perror("unexpected error. gpa_idx == overlap_idx");
			abort();
		}

		// unmap overlap
		overlap_entry = g_list_nth_data(mem_manager_mgns->mem_entries, overlap_idx);
		ret = map_or_unmap_mgns(vm_fd, &overlap_entry->mr, false);
		if (ret < 0) {
			perror("failed to unmap overlap region");
			abort();
		}
		overlap_entry->mapped = false;

		// map gpa
		ret = map_or_unmap_mgns(vm_fd, &gpa_entry->mr, true);
		if (ret < 0) {
			perror("failed to map gpa region");
			abort();
		}
		gpa_entry->mapped = true;
	}

	return true;
}

static inline MemEntryMgns *find_mem_entry_mgns(GList *entries,
												const MemoryRegionMgns *mr_1)
{
	MemEntryMgns *item;
	MemoryRegionMgns *mr_2;

	for(GList* elem = entries; elem != NULL; elem = elem->next) {
		item = elem->data;
		/* the list is corrupt if we have a NULL entry */
		assert(item != NULL);
		mr_2 = &item->mr;
		if (memcmp(mr_1, mr_2, sizeof(MemoryRegionMgns)) == 0) {
			return item;
		}
	}

	return NULL;
}

/* this is a port of mem_manager->add_del_mem. We have to see how we can consolidate
 * this. 
 * We can probably combine mshv_add_del_mem() + mem_manager->add_del_mem()
 * mem_memanager is protected is wholly guarded by a mutex in the rust code
 * We are doing the same with mem_entries
 * */
static int add_del_mem_mgns(int vm_fd, const MemoryRegionMgns *mr, bool add)
{
	MemEntryMgns *entry;
	GList *entries;
	int ret;

	/* printf("[mgns-qemu] === add_del_mem_mgns(): =========================\n"); */
	
	WITH_QEMU_LOCK_GUARD(&mem_manager_mutex_mgns) {
		entries = mem_manager_mgns->mem_entries;
		entry = find_mem_entry_mgns(entries, mr);

		if (!entry) {
			/* delete */
			if (!add) {
				perror("mem entry selected for removal does not exist\n");
				return -1;
			}

			/* printf("[mgns-qemu] mem entry does not exist, adding entry and mapping\n"); */
			/* add */
			ret = map_or_unmap_mgns(vm_fd, mr, true);

			entry = g_new0(MemEntryMgns, 1);
			entry->mr = *mr;
			/* set depending on success */
			entry->mapped = (ret == 0);
			mem_manager_mgns->mem_entries = g_list_append(entries, entry);
			return ret;
		}

		/* entry exists */

		/* delete */
		if (!add) {
			/* printf("[mgns-qemu] mem entry exists, removing entry and unmapping\n"); */
			ret = 0;
			if (entry->mapped) {
				ret = map_or_unmap_mgns(vm_fd, mr, false);
			}
			mem_manager_mgns->mem_entries = g_list_remove(entries, entry);
			g_free(entry);
			return ret;
		}

		/* add */
		/* printf("[mgns-qemu] mem entry exists, mapping\n"); */
		ret = map_or_unmap_mgns(vm_fd, mr, true);
		/* set depending on success */
		entry->mapped = (ret == 0);
		return ret;
	}
	return 0;
}

int add_mem_mgns(int vm_fd, const MemoryRegionMgns *mr)
{
	return add_del_mem_mgns(vm_fd, mr, true);
}

int remove_mem_mgns(int vm_fd, const MemoryRegionMgns *mr)
{
	return add_del_mem_mgns(vm_fd, mr, false);
}
