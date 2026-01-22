/*
 * QEMU MSHV APIC support
 *
 * Copyright Microsoft, Corp. 2026
 *
 * Authors: Magnus Kulke  <magnuskulke@microsoft.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/memalign.h"
#include "qemu/error-report.h"

#include "system/mshv.h"
#include "system/mshv_int.h"

#include "linux/mshv.h"
#include "hw/hyperv/hvgdk.h"
#include "hw/hyperv/hvhdk_mini.h"
#include "hw/hyperv/hvgdk_mini.h"

#include <sys/ioctl.h>

static int get_vp_state(int cpu_fd, struct mshv_get_set_vp_state *state)
{
    int ret;

    ret = ioctl(cpu_fd, MSHV_GET_VP_STATE, state);
    if (ret < 0) {
        error_report("failed to get partition state: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int mshv_get_lapic(int cpu_fd,
                   struct hv_local_interrupt_controller_state *state)
{
    int ret;
    size_t size = 4096;
    /* buffer aligned to 4k, as *state requires that */
    void *buffer = qemu_memalign(size, size);
    struct mshv_get_set_vp_state mshv_state = { 0 };

    mshv_state.buf_ptr = (uint64_t) buffer;
    mshv_state.buf_sz = size;
    mshv_state.type = MSHV_VP_STATE_LAPIC;

    ret = get_vp_state(cpu_fd, &mshv_state);
    if (ret == 0) {
        memcpy(state, buffer, sizeof(*state));
    }
    qemu_vfree(buffer);
    if (ret < 0) {
        error_report("failed to get lapic");
        return -1;
    }

    return 0;
}

static int set_vp_state(int cpu_fd, const struct mshv_get_set_vp_state *state)
{
    int ret;

    ret = ioctl(cpu_fd, MSHV_SET_VP_STATE, state);
    if (ret < 0) {
        error_report("failed to set partition state: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int mshv_set_lapic(int cpu_fd,
                   const struct hv_local_interrupt_controller_state *state)
{
    int ret;
    size_t size = 4096;
    /* buffer aligned to 4k, as *state requires that */
    void *buffer = qemu_memalign(size, size);
    struct mshv_get_set_vp_state mshv_state = { 0 };

    if (!state) {
        error_report("lapic state is NULL");
        return -1;
    }
    memcpy(buffer, state, sizeof(*state));

    mshv_state.buf_ptr = (uint64_t) buffer;
    mshv_state.buf_sz = size;
    mshv_state.type = MSHV_VP_STATE_LAPIC;

    ret = set_vp_state(cpu_fd, &mshv_state);
    qemu_vfree(buffer);
    if (ret < 0) {
        error_report("failed to set lapic: %s", strerror(errno));
        return -1;
    }

    return 0;
}
