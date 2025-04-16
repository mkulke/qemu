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
#include "system/mshv.h"

bool mshv_find_idx_by_gpa_in_entries(const GList *entries, uint64_t addr,
                                     size_t *index)
{
    MshvMemoryEntry *entry;
    size_t i = 0;
    uint64_t gpa_offset;

    for (const GList* elem = entries; elem != NULL; elem = elem->next) {
        entry = elem->data;
        gpa_offset = addr - entry->mr.guest_phys_addr;
        if (entry->mr.guest_phys_addr <= addr
            && gpa_offset < entry->mr.memory_size) {
            if (index != NULL) {
                *index = i;
            }
            return true;
        }
        i++;
    }

    return false;
}

MshvMemoryEntry *mshv_find_entry_by_userspace_addr(const GList *entries,
                                                   uint64_t addr)
{
    MshvMemoryEntry *entry;

    for (const GList* elem = entries; elem != NULL; elem = elem->next) {
        entry = elem->data;
        /* Check whether addr falls into the range of an already mapped
         * region */
        if (entry->mr.userspace_addr <= addr
            && addr - entry->mr.userspace_addr < entry->mr.memory_size
            && entry->mapped) {
            return entry;
        }
    }

    return NULL;
}
