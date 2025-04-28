/*
 * Type definitions for the mshv guest interface.
 *
 * Copyright Microsoft, Corp. 2025
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _HVGDK_H
#define _HVGDK_H

#define HVGDK_H_VERSION         (25125)

enum hv_unimplemented_msr_action {
    HV_UNIMPLEMENTED_MSR_ACTION_FAULT = 0,
    HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO = 1,
    HV_UNIMPLEMENTED_MSR_ACTION_COUNT = 2,
};

#endif /* _HVGDK_H */
