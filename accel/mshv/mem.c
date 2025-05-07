/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors:
 *  Magnus Kulke      <magnuskulke@microsoft.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/error-report.h"
#include "hw/hyperv/linux-mshv.h"
#include "system/address-spaces.h"
#include "system/mshv.h"
#include "exec/memattrs.h"
#include <stdint.h>
#include <sys/ioctl.h>
#include "trace.h"

static MshvMemManager *mem_manager;

void mshv_init_mem_manager(void)
{
    mem_manager = g_new0(MshvMemManager, 1);
    qemu_mutex_init(&mem_manager->mutex);
    mem_manager->mem_entries = NULL;
}

static int set_guest_memory(int vm_fd, const mshv_user_mem_region *region)
{
    int ret;
    GList *entries;
    uint64_t addr;

    ret = ioctl(vm_fd, MSHV_SET_GUEST_MEMORY, region);
    if (ret < 0) {
        addr = region->userspace_addr;
        entries = mem_manager->mem_entries;
        if (mshv_find_entry_by_userspace_addr(entries, addr)) {
            return -MSHV_USERSPACE_ADDR_REMAP_ERROR;
        }

        error_report("failed to set guest memory");
        return -errno;
    }

    return 0;
}

static int map_or_unmap(int vm_fd, const MshvMemoryRegion *mr, bool add)
{
    struct mshv_user_mem_region region = {0};

    region.guest_pfn = mr->guest_phys_addr >> MSHV_PAGE_SHIFT;
    region.size = mr->memory_size;
    region.userspace_addr = mr->userspace_addr;

    if (!add) {
        region.flags |= (1 << MSHV_SET_MEM_BIT_UNMAP);
        return set_guest_memory(vm_fd, &region);
    }

    region.flags = (1 << MSHV_SET_MEM_BIT_EXECUTABLE);
    if (!mr->readonly) {
        region.flags |= (1 << MSHV_SET_MEM_BIT_WRITABLE);
    }

    return set_guest_memory(vm_fd, &region);
}

bool mshv_find_entry_idx_by_gpa(uint64_t addr, size_t *index)
{
    GList *entries;

    assert(mem_manager);

    entries = mem_manager->mem_entries;
    return mshv_find_idx_by_gpa_in_entries(entries, addr, index);
}

static bool find_overlap_userspace_region(size_t gpa_idx,
                                          const MshvMemoryRegion *mr,
                                          size_t *overlap_idx)
{
    MshvMemoryEntry *entry;
    GList *entries;
    size_t i = 0;
    uint64_t mr_start, mr_end, entry_start, entry_end;

    entries = mem_manager->mem_entries;
    for (const GList *elem = entries; elem != NULL; elem = elem->next) {
        entry = elem->data;

        mr_start = mr->userspace_addr;
        mr_end = mr_start + mr->memory_size;
        entry_start = entry->mr.userspace_addr;
        entry_end = entry_start + entry->mr.memory_size;

        if (i != gpa_idx &&
            entry->mapped &&
            entry_start < mr_end &&
            entry_end > mr_start) {
                *overlap_idx = i;
                return true;
        }
        i++;
    }

    return false;
}

static MshvMemoryEntry *find_mem_entry(const GList *entries,
                                       const MshvMemoryRegion *mr_1)
{
    MshvMemoryEntry *item;
    MshvMemoryRegion *mr_2;
    const GList *elem;

    for (elem = entries; elem != NULL; elem = elem->next) {
        item = elem->data;
        /* the list is corrupt if we have a NULL entry */
        assert(item != NULL);
        mr_2 = &item->mr;
        if (memcmp(mr_1, mr_2, sizeof(MshvMemoryRegion)) == 0) {
            return item;
        }
    }

    return NULL;
}

static inline int add_del_mem(int vm_fd, const MshvMemoryRegion *mr, bool add)
{
    MshvMemoryEntry *entry;
    GList *entries;
    int ret;

    assert(mem_manager);

    WITH_QEMU_LOCK_GUARD(&mem_manager->mutex) {
        entries = mem_manager->mem_entries;
        entry = find_mem_entry(entries, mr);

        if (!entry) {
            /* delete */
            if (!add) {
                error_report("mem entry selected for removal does not exist");
                return -1;
            }

            /* add */
            ret = map_or_unmap(vm_fd, mr, true);
            entry = g_new0(MshvMemoryEntry, 1);
            entry->mr = *mr;
            /* set depending on success */
            entry->mapped = (ret == 0);
            mem_manager->mem_entries = g_list_append(entries, entry);

            if (ret == -MSHV_USERSPACE_ADDR_REMAP_ERROR) {
                warn_report(
                    "ignoring failed remapping of userspace_addr: 0x%016lx "
                    "to gpa 0x%08lx-0x%08lx", mr->userspace_addr,
                    mr->guest_phys_addr, mr->guest_phys_addr + mr->memory_size);
                ret = 0;
            }

            return ret;
        }

        /* entry exists */

        /* delete */
        if (!add) {
            ret = 0;
            if (entry->mapped) {
                ret = map_or_unmap(vm_fd, mr, false);
            }
            mem_manager->mem_entries = g_list_remove(entries, entry);
            g_free(entry);
            return ret;
        }

        /* add */
        ret = map_or_unmap(vm_fd, mr, true);

        /* set depending on success */
        entry->mapped = (ret == 0);
        return ret;
    }
    return 0;
}

bool mshv_remap_overlapped_region(int vm_fd, uint64_t gpa)
{
    size_t gpa_idx, overlap_idx;
    MshvMemoryEntry *gpa_entry, *overlap_entry;
    int ret;
    assert(mem_manager);

    WITH_QEMU_LOCK_GUARD(&mem_manager->mutex) {
        if (!mshv_find_entry_idx_by_gpa(gpa, &gpa_idx)) {
            return false;
        }
        gpa_entry = g_list_nth_data(mem_manager->mem_entries, gpa_idx);
        if (!gpa_entry) {
            error_report("unexpected error. failed to find mem entry");
            abort();
        }

        if (!find_overlap_userspace_region(gpa_idx, &gpa_entry->mr,
                                           &overlap_idx)) {
            return false;
        }
        if (gpa_idx == overlap_idx) {
            error_report("unexpected error. gpa_idx == overlap_idx");
            abort();
        }

        /* unmap overlap */
        overlap_entry = g_list_nth_data(mem_manager->mem_entries, overlap_idx);
        ret = map_or_unmap(vm_fd, &overlap_entry->mr, false);
        if (ret < 0) {
            error_report("failed to unmap overlap region");
            abort();
        }
        overlap_entry->mapped = false;

        /* map gpa */
        ret = map_or_unmap(vm_fd, &gpa_entry->mr, true);
        if (ret < 0) {
            error_report("failed to map gpa region");
            abort();
        }
    }

    return true;
}

int mshv_add_mem(int vm_fd, const MshvMemoryRegion *mr)
{
    return add_del_mem(vm_fd, mr, true);
}

int mshv_remove_mem(int vm_fd, const MshvMemoryRegion *mr)
{
    return add_del_mem(vm_fd, mr, false);
}

static inline MemTxAttrs get_mem_attrs(bool is_secure_mode)
{
    MemTxAttrs memattr = {0};
    memattr.secure = is_secure_mode;
    return memattr;
}

static int handle_unmapped_mmio_region_read(uint64_t gpa, uint64_t size,
                                            uint8_t *data)
{
    warn_report("read from unmapped mmio region gpa=0x%lx size=%lu", gpa, size);

    if (size == 0 || size > 8) {
        error_report("invalid size %lu for reading from unmapped mmio region",
                     size);
        return -1;
    }

    memset(data, 0xFF, size);

    return 0;
}

int mshv_guest_mem_read(uint64_t gpa, uint8_t *data, uintptr_t size,
                        bool is_secure_mode, bool instruction_fetch)
{
    int ret;
    MemTxAttrs memattr = get_mem_attrs(is_secure_mode);

    if (instruction_fetch) {
        trace_mshv_insn_fetch(gpa, size);
    } else {
        trace_mshv_mem_read(gpa, size);
    }

    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, false);
    if (ret == MEMTX_OK) {
        return 0;
    }

    if (ret == MEMTX_DECODE_ERROR) {
        return handle_unmapped_mmio_region_read(gpa, size, data);
    }

    error_report("failed to read guest memory at 0x%lx", gpa);
    return -1;
}

int mshv_guest_mem_write(uint64_t gpa, const uint8_t *data, uintptr_t size,
                         bool is_secure_mode)
{
    int ret;

    trace_mshv_mem_write(gpa, size);
    MemTxAttrs memattr = get_mem_attrs(is_secure_mode);
    ret = address_space_rw(&address_space_memory, gpa, memattr, (void *)data,
                           size, true);
    if (ret == MEMTX_OK) {
        return 0;
    }

    if (ret == MEMTX_DECODE_ERROR) {
        warn_report("write to unmapped mmio region gpa=0x%lx size=%lu", gpa,
                    size);
        return 0;
    }

    error_report("Failed to write guest memory");
    return -1;
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

    /*
     * works in page size chunks, but the function may be called
     * with sub-page size and unaligned start address. Pad the start
     * address to next and truncate size to previous page boundary.
     */
    aligned = ROUND_UP(section->offset_within_address_space,
                       qemu_real_host_page_size());
    delta = aligned - section->offset_within_address_space;
    *start = aligned;
    if (delta > size) {
        return 0;
    }

    return (size - delta) & qemu_real_host_page_mask();
}

void mshv_set_phys_mem(MshvMemoryListener *mml, MemoryRegionSection *section,
                       bool add)
{
    int ret = 0;
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    hwaddr start_addr, mr_offset, size;
    void *ram;
    MshvMemoryRegion tmp, *mshv_mr = &tmp;

    if (!memory_region_is_ram(area)) {
        if (writable) {
            return;
        }
    }

    size = align_section(section, &start_addr);
    if (!size) {
        return;
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
    if (ret < 0) {
        error_report("Failed to set memory region");
        abort();
    }
}

