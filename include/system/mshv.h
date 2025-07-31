/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors: Magnus Kulke <magnuskulke@microsoft.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef QEMU_MSHV_H
#define QEMU_MSHV_H

#include "qemu/accel.h"

#ifdef COMPILING_PER_TARGET
#ifdef CONFIG_MSHV
#define CONFIG_MSHV_IS_POSSIBLE
#endif
#else
#define CONFIG_MSHV_IS_POSSIBLE
#endif

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

typedef struct MshvState MshvState;
DECLARE_INSTANCE_CHECKER(MshvState, MSHV_STATE, TYPE_MSHV_ACCEL)

#ifdef CONFIG_MSHV_IS_POSSIBLE
extern bool mshv_allowed;
#define mshv_enabled() (mshv_allowed)

#else /* CONFIG_MSHV_IS_POSSIBLE */
#define mshv_enabled() false
#endif /* CONFIG_MSHV_IS_POSSIBLE */

#define mshv_msi_via_irqfd_enabled() (mshv_allowed)

int mshv_irqchip_add_msi_route(int vector, PCIDevice *dev);
int mshv_irqchip_update_msi_route(int virq, MSIMessage msg, PCIDevice *dev);
void mshv_irqchip_commit_routes(void);
void mshv_irqchip_release_virq(int virq);
int mshv_irqchip_add_irqfd_notifier_gsi(const EventNotifier *n,
                                        const EventNotifier *rn, int virq);
int mshv_irqchip_remove_irqfd_notifier_gsi(const EventNotifier *n, int virq);
int mshv_request_interrupt(uint32_t interrupt_type, uint32_t vector,
                           uint32_t vp_index, bool logical_dest_mode,
                           bool level_triggered);

#endif /* QEMU_MSHV_H */
