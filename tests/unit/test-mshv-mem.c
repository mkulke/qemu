#include "qemu/osdep.h"
#include "system/mshv.h"
#include <assert.h>
#include <stdio.h>

static void test_find_entry_by_userspace_addr(void)
{
    GList *entries = NULL;
    MshvMemoryEntry *entry1, *entry2, *found;
    uint64_t base1 = 0x10000000;
    uint64_t base2 = 0x20000000;

    entry1 = g_new0(MshvMemoryEntry, 1);
    entry1->mr.userspace_addr = base1;
    entry1->mr.memory_size = 0x100000;
    entry1->mapped = true;

    entry2 = g_new0(MshvMemoryEntry, 1);
    entry2->mr.userspace_addr = base2;
    entry2->mr.memory_size = 0x200000;
    entry2->mapped = true;

    entries = g_list_append(entries, entry1);
    entries = g_list_append(entries, entry2);

    /* Test address within entry1 */
    found = mshv_find_entry_by_userspace_addr(entries, base1 + 0x8000);
    g_assert(found == entry1);

    /* Test address within entry2 */
    found = mshv_find_entry_by_userspace_addr(entries, base2 + 0x100000);
    g_assert(found == entry2);

    /* Test address outside any range */
    found = mshv_find_entry_by_userspace_addr(entries, 0xdeadbeef);
    g_assert(found == NULL);
}

static void test_mshv_find_entry_idx_by_gpa(void)
{
    GList *entries = NULL;
    MshvMemoryEntry *entry1, *entry2;
    size_t index;
    bool found;
    uint64_t base1 = 0x40000000;
    uint64_t base2 = 0x50000000;

    entry1 = g_new0(MshvMemoryEntry, 1);
    entry1->mr.guest_phys_addr = base1;
    entry1->mr.memory_size = 0x100000;
    entry1->mapped = true;

    entry2 = g_new0(MshvMemoryEntry, 1);
    entry2->mr.guest_phys_addr = base2;
    entry2->mr.memory_size = 0x200000;
    entry2->mapped = true;

    entries = g_list_append(entries, entry1);
    entries = g_list_append(entries, entry2);

    /* Test within entry1 */
    found = mshv_find_idx_by_gpa_in_entries(entries, base1 + 0x4000, &index);
    g_assert(found);
    g_assert(index == 0);

    /* Test within entry2 */
    found = mshv_find_idx_by_gpa_in_entries(entries, base2 + 0x100000, &index);
    g_assert(found);
    g_assert(index == 1);

    /* Test not found */
    found = mshv_find_idx_by_gpa_in_entries(entries, 0xdeadbeef, &index);
    g_assert(!found);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/accel/mshv/mem-util/find_entry_by_userspace_addr",
                    test_find_entry_by_userspace_addr);
    g_test_add_func("/accel/mshv/mem-util/find_entry_idx_by_gpa",
                    test_mshv_find_entry_idx_by_gpa);
    return g_test_run();
}
