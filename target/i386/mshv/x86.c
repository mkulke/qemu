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

bool x86_read_segment_descriptor(CPUState *cpu,
                                 struct x86_segment_descriptor *desc,
                                 x86_segment_selector sel)
{
    /* target_ulong base; */
    /* uint32_t limit; */

    /* memset(desc, 0, sizeof(*desc)); */

    /* /1* valid gdt descriptors start from index 1 *1/ */
    /* if (!sel.index && GDT_SEL == sel.ti) { */
    /*     return false; */
    /* } */

    /* if (GDT_SEL == sel.ti) { */
    /*     base  = rvmcs(cpu->accel->fd, VMCS_GUEST_GDTR_BASE); */
    /*     limit = rvmcs(cpu->accel->fd, VMCS_GUEST_GDTR_LIMIT); */
    /* } else { */
    /*     base  = rvmcs(cpu->accel->fd, VMCS_GUEST_LDTR_BASE); */
    /*     limit = rvmcs(cpu->accel->fd, VMCS_GUEST_LDTR_LIMIT); */
    /* } */

    /* if (sel.index * 8 >= limit) { */
    /*     return false; */
    /* } */

    /* vmx_read_mem(cpu, desc, base + sel.index * 8, sizeof(*desc)); */
	perror("unimplemented: read_segment_descriptor()");
	abort();
}

bool x86_write_segment_descriptor(CPUState *cpu,
                                  struct x86_segment_descriptor *desc,
                                  x86_segment_selector sel)
{
    /* target_ulong base; */
    /* uint32_t limit; */
    
    /* if (GDT_SEL == sel.ti) { */
    /*     base  = rvmcs(cpu->accel->fd, VMCS_GUEST_GDTR_BASE); */
    /*     limit = rvmcs(cpu->accel->fd, VMCS_GUEST_GDTR_LIMIT); */
    /* } else { */
    /*     base  = rvmcs(cpu->accel->fd, VMCS_GUEST_LDTR_BASE); */
    /*     limit = rvmcs(cpu->accel->fd, VMCS_GUEST_LDTR_LIMIT); */
    /* } */
    
    /* if (sel.index * 8 >= limit) { */
    /*     printf("%s: gdt limit\n", __func__); */
    /*     return false; */
    /* } */
    /* vmx_write_mem(cpu, base + sel.index * 8, desc, sizeof(*desc)); */
	perror("unimplemented: write_segment_descriptor()");
	abort();
}

bool x86_read_call_gate(CPUState *cpu, struct x86_call_gate *idt_desc,
                        int gate)
{
    /* target_ulong base  = rvmcs(cpu->accel->fd, VMCS_GUEST_IDTR_BASE); */
    /* uint32_t limit = rvmcs(cpu->accel->fd, VMCS_GUEST_IDTR_LIMIT); */

    /* memset(idt_desc, 0, sizeof(*idt_desc)); */
    /* if (gate * 8 >= limit) { */
    /*     printf("%s: idt limit\n", __func__); */
    /*     return false; */
    /* } */

    /* vmx_read_mem(cpu, idt_desc, base + gate * 8, sizeof(*idt_desc)); */
	perror("unimplemented: read_call_gate()");
	abort();
}

bool x86_is_protected(CPUState *cpu)
{
    /* uint64_t cr0 = rvmcs(cpu->accel->fd, VMCS_GUEST_CR0); */
    /* return cr0 & CR0_PE_MASK; */
	perror("unimplemented: is_protected()");
	abort();
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
    /* return rvmcs(cpu->accel->fd, VMCS_GUEST_IA32_EFER) & MSR_EFER_LMA; */
	perror("unimplemented: is_long_mode()");
	abort();
}

bool x86_is_long64_mode(CPUState *cpu)
{
    /* /1* struct vmx_segment desc; *1/ */
    /* /1* vmx_read_segment_descriptor(cpu, &desc, R_CS); *1/ */

    /* return x86_is_long_mode(cpu) && ((desc.ar >> 13) & 1); */
	perror("unimplemented: is_long64_mode()");
	abort();
}

bool x86_is_paging_mode(CPUState *cpu)
{
    /* uint64_t cr0 = rvmcs(cpu->accel->fd, VMCS_GUEST_CR0); */
    /* return cr0 & CR0_PG_MASK; */
	perror("unimplemented: is_paging_mode()");
	abort();
}

bool x86_is_pae_enabled(CPUState *cpu)
{
    /* uint64_t cr4 = rvmcs(cpu->accel->fd, VMCS_GUEST_CR4); */
    /* return cr4 & CR4_PAE_MASK; */
	perror("unimplemented: is_pae_enabled()");
	abort();
}

target_ulong linear_addr(CPUState *cpu, target_ulong addr, X86Seg seg)
{
    /* return vmx_read_segment_base(cpu, seg) + addr; */
	perror("unimplemented: read_segment_descriptor()");
	abort();
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
