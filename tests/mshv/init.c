/*
 * Minimal init for migration testing.
 *
 * Runs as PID 1 inside a tiny initramfs. Writes to a memory range in a
 * loop to generate dirty pages, and periodically outputs to the console
 * so the test harness can verify the guest is alive after migration.
 *
 * Build: gcc -static -o init init.c
 *
 * Copyright Microsoft, Corp. 2025
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define TEST_MEM_SIZE (32 * 1024 * 1024)  /* 32 MB */
#define PAGE_SIZE     4096
#define LOOPS_PER_MSG 64

int main(void)
{
    uint8_t *mem;
    int fd, pass = 0;

    fd = open("/dev/console", O_WRONLY);
    if (fd < 0) {
        fd = STDOUT_FILENO;
    }

    write(fd, "A", 1);

    mem = malloc(TEST_MEM_SIZE);
    if (!mem) {
        write(fd, "E", 1);
        for (;;) {
            pause();
        }
    }
    memset(mem, 0, TEST_MEM_SIZE);

    /* dirty pages in a loop, like the bootblock a-b test */
    for (;;) {
        uint8_t *p;
        for (p = mem; p < mem + TEST_MEM_SIZE; p += PAGE_SIZE) {
            (*p)++;
        }
        if (++pass % LOOPS_PER_MSG == 0) {
            write(fd, "B", 1);
        }
    }

    return 0;
}
