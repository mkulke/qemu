/*
 * QEMU MSHV support
 *
 * Copyright Microsoft, Corp. 2025
 *
 * Authors:
 *  Ziqiao Zhou       <ziqiaozhou@microsoft.com>
 *  Magnus Kulke      <magnuskulke@microsoft.com>
 *  Jinank Jain       <jinankjain@microsoft.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MSHV_INT_H
#define QEMU_MSHV_INT_H

#ifdef COMPILING_PER_TARGET
#ifdef CONFIG_MSHV
#define CONFIG_MSHV_IS_POSSIBLE
#endif
#else
#define CONFIG_MSHV_IS_POSSIBLE
#endif

/* cpu */
/* EFER (technically not a register) bits */
#define EFER_LMA   ((uint64_t)0x400)
#define EFER_LME   ((uint64_t)0x100)

#endif
