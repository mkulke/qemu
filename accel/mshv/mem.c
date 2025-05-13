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
#include "qemu/rcu.h"
#include "hw/hyperv/linux-mshv.h"
#include "system/address-spaces.h"
#include "system/mshv.h"
#include "exec/memattrs.h"
#include <stdint.h>
#include <sys/ioctl.h>
#include "trace.h"

static GList *mem_entries;

/* We need this, because call_rcu1 won't operate on empty lists (NULL) */
typedef struct {
    struct rcu_head rcu;
    GList *list;
} FreeMemEntriesJob;

static inline void free_mem_entries(struct rcu_head *rh)
{
    FreeMemEntriesJob *job = container_of(rh, FreeMemEntriesJob, rcu);
    g_list_free(job->list);
    g_free(job);
}

static void add_mem_entry(MshvMemoryEntry *entry)
{
    GList *old = qatomic_rcu_read(&mem_entries);
    GList *new = g_list_copy(old);
    new = g_list_prepend(new, entry);

    qatomic_rcu_set(&mem_entries, new);

    /* defer freeing of an obsolete snapshot */
    FreeMemEntriesJob *job = g_new(FreeMemEntriesJob, 1);
    job->list = old;
    call_rcu1(&job->rcu, free_mem_entries);
}

static void remove_mem_entry(MshvMemoryEntry *entry)
{
    GList *old = qatomic_rcu_read(&mem_entries);
    GList *new = g_list_copy(old);
    new = g_list_remove(new, entry);

    qatomic_rcu_set(&mem_entries, new);

    /* Defer freeing of an obsolete snapshot */
    FreeMemEntriesJob *job = g_new(FreeMemEntriesJob, 1);
    job->list = old;
    call_rcu1((struct rcu_head *)old, free_mem_entries);
}

/* Find _currently mapped_ memory entry, that is overlapping in userspace */
static MshvMemoryEntry *find_overlap_mem_entry(const MshvMemoryEntry *entry_1)
{
    uint64_t start_1 = entry_1->mr.userspace_addr, start_2;
    size_t len_1 = entry_1->mr.memory_size, len_2;

    WITH_RCU_READ_LOCK_GUARD() {
        GList *entries = qatomic_rcu_read(&mem_entries);
        bool overlaps;
        MshvMemoryEntry *entry_2;

        for (GList *l = entries; l != NULL; l = l->next) {
            entry_2 = l->data;
            assert(entry_2);
            start_2 = entry_2->mr.userspace_addr;
            len_2 = entry_2->mr.memory_size;

            overlaps = ranges_overlap(start_1, len_1, start_2, len_2);
            if (entry_2->mapped && overlaps) {
                return entry_2;
            }
        }
    }

    return NULL;
}

void mshv_init_mem_manager(void)
{
    mem_entries = NULL;
}

static int set_guest_memory(int vm_fd, const mshv_user_mem_region *region)
{
    int ret;
    MshvMemoryEntry *overlap_entry, entry = { .mr = { 0 }, .mapped = false };

    ret = ioctl(vm_fd, MSHV_SET_GUEST_MEMORY, region);
    if (ret < 0) {
        entry.mr.userspace_addr = region->userspace_addr;
        entry.mr.memory_size = region->size;

        overlap_entry = find_overlap_mem_entry(&entry);
        if (overlap_entry != NULL) {
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

static MshvMemoryEntry *find_mem_entry_by_region(const MshvMemoryRegion *mr)
{
    WITH_RCU_READ_LOCK_GUARD() {
        GList *entries = qatomic_rcu_read(&mem_entries);
        MshvMemoryEntry *entry;

        for (GList *l = entries; l != NULL; l = l->next) {
            entry = l->data;
            assert(entry);
            if (memcmp(mr, &entry->mr, sizeof(MshvMemoryRegion)) == 0) {
                return entry;
            }
        }
    }

    return NULL;
}

static inline int add_del_mem(int vm_fd, const MshvMemoryRegion *mr, bool add)
{
    MshvMemoryEntry *entry;
    int ret;

    entry = find_mem_entry_by_region(mr);

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
        add_mem_entry(entry);

        if (ret == -MSHV_USERSPACE_ADDR_REMAP_ERROR) {
            warn_report(
                "ignoring failed remapping userspace_addr=0x%016lx "
                "gpa=0x%08lx size=0x%lx", mr->userspace_addr,
                mr->guest_phys_addr, mr->memory_size);
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
        remove_mem_entry(entry);
        g_free(entry);
        return ret;
    }

    /* add */
    ret = map_or_unmap(vm_fd, mr, true);

    /* set depending on success */
    entry->mapped = (ret == 0);
    return ret;
}

static MshvMemoryEntry* find_mem_entry_by_gpa(uint64_t gpa)
{
    WITH_RCU_READ_LOCK_GUARD() {
        GList *entries = qatomic_rcu_read(&mem_entries);
        MshvMemoryEntry *entry;
        uint64_t gpa_offset;

        for (GList *l = entries; l != NULL; l = l->next) {
            entry = l->data;
            assert(entry);
            gpa_offset = gpa - entry->mr.guest_phys_addr;
            if (entry->mr.guest_phys_addr <= gpa
                && gpa_offset < entry->mr.memory_size) {
                return entry;
            }
        }
    }

    return NULL;
}

MshvRemapResult mshv_remap_overlapped_region(int vm_fd, uint64_t gpa)
{
    MshvMemoryEntry *gpa_entry, *overlap_entry;
    int ret;

    /* return early if no entry is found */
    gpa_entry = find_mem_entry_by_gpa(gpa);
    if (gpa_entry == NULL) {
        return MshvRemapNoMapping;
    }

    overlap_entry = find_overlap_mem_entry(gpa_entry);
    if (overlap_entry == NULL) {
        return MshvRemapNoOverlap;
    }

    /* unmap overlapping region */
    ret = map_or_unmap(vm_fd, &overlap_entry->mr, false);
    if (ret < 0) {
        error_report("failed to unmap overlap region");
        abort();
    }
    overlap_entry->mapped = false;
    warn_report("mapped out userspace_addr=0x%016lx gpa=0x%010lx size=0x%lx",
                overlap_entry->mr.userspace_addr,
                overlap_entry->mr.guest_phys_addr,
                overlap_entry->mr.memory_size);

    /* map region for gpa */
    ret = map_or_unmap(vm_fd, &gpa_entry->mr, true);
    if (ret < 0) {
        error_report("failed to map new region");
        abort();
    }
    gpa_entry->mapped = true;
    warn_report("mapped in  userspace_addr=0x%016lx gpa=0x%010lx size=0x%lx",
                gpa_entry->mr.userspace_addr,
                gpa_entry->mr.guest_phys_addr,
                gpa_entry->mr.memory_size);

    return MshvRemapOk;
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

