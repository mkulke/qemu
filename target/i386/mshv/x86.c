/*
 * Copyright (C) 2025 Microsoft Corp.,
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"

#include "cpu.h"
#include "emulate/x86_decode.h"
#include "emulate/x86_emu.h"
#include "qemu/typedefs.h"
#include "qemu/error-report.h"
#include "system/mshv.h"

/* RW or Exec segment */
static uint8_t RWRX_SEGMENT_TYPE = 0x2;
static uint8_t CODE_SEGMENT_TYPE = 0x8;
static uint8_t EXPAND_DOWN_SEGMENT_TYPE = 0x4;

enum Mode {
	REAL_MODE,
	PROTECTED_MODE,
	LONG_MODE,
};

static void set_seg(struct SegmentRegister *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type_ = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = !lhs->present;
    lhs->padding = 0;
}

static enum Mode cpu_mode(CPUState *cpu)
{
	enum Mode m = REAL_MODE;

	if (x86_is_protected(cpu)) {
		m = PROTECTED_MODE;

		if (x86_is_long_mode(cpu)) {
			m = LONG_MODE;
		}
	}

	return m;
}

static bool segment_type_ro(const SegmentCache *seg)
{
	SegmentRegister mshv_seg = {0};
	set_seg(&mshv_seg, seg);

    return (mshv_seg.type_ & (~RWRX_SEGMENT_TYPE)) == 0;
}

static bool segment_type_code(const SegmentCache *seg)
{
	SegmentRegister mshv_seg = {0};
	set_seg(&mshv_seg, seg);

    return (mshv_seg.type_ & CODE_SEGMENT_TYPE) != 0;
}

static bool segment_expands_down(const SegmentCache *seg)
{
	SegmentRegister mshv_seg = {0};

	if (segment_type_code(seg)) {
		return false;
	}

	set_seg(&mshv_seg, seg);
	return (mshv_seg.type_ & EXPAND_DOWN_SEGMENT_TYPE) != 0;
}

static uint32_t segment_limit(const SegmentCache *seg)
{
	SegmentRegister mshv_seg = {0};
	set_seg(&mshv_seg, seg);
	uint32_t limit = mshv_seg.limit;
	uint8_t granularity = mshv_seg.g;

	if (granularity != 0) {
		limit = (limit << 12) | 0xFFF;
	}

	return limit;
}

static uint8_t segment_db(const SegmentCache *seg)
{
	SegmentRegister mshv_seg = {0};
	set_seg(&mshv_seg, seg);

	return mshv_seg.db;
}

static int linearize(CPUState *cpu,
					 target_ulong logical_addr, target_ulong *linear_addr,
					 X86Seg seg_idx)
{
	enum Mode mode;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	SegmentCache *seg = &env->segs[seg_idx];
	target_ulong base = seg->base;
	target_ulong logical_addr_32b;
	uint32_t limit;
	/* TODO: the emulator will not pass us "write" indicator yet */
	bool write = false;

	mode = cpu_mode(cpu);

	switch (mode) {
	case LONG_MODE:
		if (__builtin_add_overflow(logical_addr, base, linear_addr)) {
			perror("address overflow");
			return -1;
		}
		break;
	case PROTECTED_MODE:
	case REAL_MODE:
		if (segment_type_ro(seg) && write) {
			perror("cannot write to read-only segment");
			return -1;
		}

		logical_addr_32b = logical_addr & 0xFFFFFFFF;
		limit = segment_limit(seg);

		if (segment_expands_down(seg)) {
			if (logical_addr_32b >= limit) {
				perror("address exceeds limit (expands down)");
				return -1;
			}

			if (segment_db(seg) != 0) {
				limit = 0xFFFFFFFF;
			} else {
				limit = 0xFFFF;
			}
		}

		if (logical_addr_32b > limit) {
			error_report("address exceeds limit %u", limit);
			return -1;
		}
		*linear_addr = logical_addr_32b + base;
		break;
	default:
		perror("unknown cpu mode");
		return -1;
	}

	return 0;
}

bool x86_read_segment_descriptor(CPUState *cpu,
                                 struct x86_segment_descriptor *desc,
                                 x86_segment_selector sel)
{
    target_ulong base;
    uint32_t limit;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	target_ulong gva;
	/* int ret; */

    memset(desc, 0, sizeof(*desc));

    /* valid gdt descriptors start from index 1 */
    if (!sel.index && GDT_SEL == sel.ti) {
        return false;
    }

    if (GDT_SEL == sel.ti) {
		base = env->gdt.base;
		limit = env->gdt.limit;
    } else {
		base = env->ldt.base;
		limit = env->ldt.limit;
    }

    if (sel.index * 8 >= limit) {
        return false;
    }

	gva = base + sel.index * 8;
	emul_ops->read_mem(cpu, desc, gva, sizeof(*desc));
    /* void (*read_mem)(CPUState *cpu, void *data, target_ulong addr, int bytes); */
    /* ret = guest_mem_read_mgns(cpu, gva, (void *)desc, sizeof(*desc)); */
	/* if (ret < 0) { */
	/* 	perror("failed to read segment descriptor"); */
	/* 	return false; */
	/* } */
	return true;
}

bool x86_write_segment_descriptor(CPUState *cpu,
                                  struct x86_segment_descriptor *desc,
                                  x86_segment_selector sel)
{
    target_ulong base;
    uint32_t limit;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	/* int ret; */
	target_ulong gva;

    if (GDT_SEL == sel.ti) {
		base = env->gdt.base;
		limit = env->gdt.limit;
    } else {
		base = env->ldt.base;
		limit = env->ldt.limit;
    }

    if (sel.index * 8 >= limit) {
        return false;
    }

	gva = base + sel.index * 8;
	emul_ops->write_mem(cpu, desc, gva, sizeof(*desc));
    /* void (*write_mem)(CPUState *cpu, void *data, target_ulong addr, int bytes); */

	/* ret = guest_mem_write_mgns(cpu, gva, (void*) desc, sizeof(*desc)); */
	/* if (ret < 0) { */
	/* 	perror("failed to write segment descriptor"); */
	/* 	return false; */
	/* } */

	return true;
}

bool x86_read_call_gate(CPUState *cpu, struct x86_call_gate *idt_desc,
                        int gate)
{
	target_ulong base;
	uint32_t limit;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	/* int ret; */
	int gva;

	base = env->idt.base;
	limit = env->idt.limit;

    memset(idt_desc, 0, sizeof(*idt_desc));
    if (gate * 8 >= limit) {
		perror("call gate exceeds idt limit");
        return false;
    }

	gva = base + gate * 8;
	/* ret = guest_mem_read_mgns(cpu, gva, (void*)idt_desc, sizeof(*idt_desc)); */
	emul_ops->read_mem(cpu, idt_desc, gva, sizeof(*idt_desc));
	/* void (*read_mem)(CPUState *cpu, void *data, target_ulong addr, int bytes); */
	/* if (ret < 0) { */
	/* 	perror("failed to read call gate"); */
	/* 	return false; */
	/* } */
	return true;
}

bool x86_is_protected(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	uint64_t cr0 = env->cr[0];

	if (cr0 & CR0_PE_MASK) {
		return true;
	}

	return false;
}

bool x86_is_real(CPUState *cpu)
{
    return !x86_is_protected(cpu);
}

bool x86_is_v8086(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    return x86_is_protected(cpu) && (env->eflags & VM_MASK);
}

bool x86_is_long_mode(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	uint64_t efer = env->efer;

	return ((efer & (EFER_LME | EFER_LMA)) == (EFER_LME | EFER_LMA));
}

bool x86_is_long64_mode(CPUState *cpu)
{
	perror("unimplemented: is_long64_mode()");
	abort();
}

bool x86_is_paging_mode(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	uint64_t cr0 = env->cr[0];

	return cr0 & CR0_PG_MASK;
}

bool x86_is_pae_enabled(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
	uint64_t cr4 = env->cr[4];

	return cr4 & CR4_PAE_MASK;
}

target_ulong linear_addr(CPUState *cpu, target_ulong addr, X86Seg seg)
{
	int ret;
	target_ulong linear_addr;

    /* return vmx_read_segment_base(cpu, seg) + addr; */
	ret = linearize(cpu, addr, &linear_addr, seg);
	if (ret < 0) {
		error_report("failed to linearize address");
		abort();
	}

	return linear_addr;
}

target_ulong linear_addr_size(CPUState *cpu, target_ulong addr, int size,
                              X86Seg seg)
{
    switch (size) {
    case 2:
        addr = (uint16_t)addr;
        break;
    case 4:
        addr = (uint32_t)addr;
        break;
    default:
        break;
    }
    return linear_addr(cpu, addr, seg);
}

target_ulong linear_rip(CPUState *cpu, target_ulong rip)
{
    return linear_addr(cpu, rip, R_CS);
}
