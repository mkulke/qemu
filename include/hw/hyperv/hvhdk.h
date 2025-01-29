#ifndef HW_HYPERV_HVHDK_H
#define HW_HYPERV_HVHDK_H

#define HV_PARTITION_SYNTHETIC_PROCESSOR_FEATURES_BANKS 1

union hv_partition_synthetic_processor_features {
	__u64 as_uint64[HV_PARTITION_SYNTHETIC_PROCESSOR_FEATURES_BANKS];

	struct {
		/* Report a hypervisor is present. CPUID leaves
		 * 0x40000000 and 0x40000001 are supported.
		 */
		__u64 hypervisor_present:1;

		/*
		 * Features associated with HV#1:
		 */

		/* Report support for Hv1 (CPUID leaves 0x40000000 - 0x40000006). */
		__u64 hv1:1;

		/* Access to HV_X64_MSR_VP_RUNTIME.
		 * Corresponds to access_vp_run_time_reg privilege.
		 */
		__u64 access_vp_run_time_reg:1;

		/* Access to HV_X64_MSR_TIME_REF_COUNT.
		 * Corresponds to access_partition_reference_counter privilege.
		 */
		__u64 access_partition_reference_counter:1;

		/* Access to SINT-related registers (HV_X64_MSR_SCONTROL through
		 * HV_X64_MSR_EOM and HV_X64_MSR_SINT0 through HV_X64_MSR_SINT15).
		 * Corresponds to access_synic_regs privilege.
		 */
		__u64 access_synic_regs:1;

		/* Access to synthetic timers and associated MSRs
		 * (HV_X64_MSR_STIMER0_CONFIG through HV_X64_MSR_STIMER3_COUNT).
		 * Corresponds to access_synthetic_timer_regs privilege.
		 */
		__u64 access_synthetic_timer_regs:1;

		/* Access to APIC MSRs (HV_X64_MSR_EOI, HV_X64_MSR_ICR and HV_X64_MSR_TPR)
		 * as well as the VP assist page.
		 * Corresponds to access_intr_ctrl_regs privilege.
		 */
		__u64 access_intr_ctrl_regs:1;

		/* Access to registers associated with hypercalls (HV_X64_MSR_GUEST_OS_ID
		 * and HV_X64_MSR_HYPERCALL).
		 * Corresponds to access_hypercall_msrs privilege.
		 */
		__u64 access_hypercall_regs:1;

		/* VP index can be queried. corresponds to access_vp_index privilege. */
		__u64 access_vp_index:1;

		/* Access to the reference TSC. Corresponds to access_partition_reference_tsc
		 * privilege.
		 */
		__u64 access_partition_reference_tsc:1;

#if defined(__x86_64__)

		/* Partition has access to the guest idle reg. Corresponds to
		 * access_guest_idle_reg privilege.
		 */
		__u64 access_guest_idle_reg:1;
#else
		__u64 reserved_z10:1;
#endif

		/* Partition has access to frequency regs. corresponds to access_frequency_regs
		 * privilege.
		 */
		__u64 access_frequency_regs:1;

		__u64 reserved_z12:1; /* Reserved for access_reenlightenment_controls. */
		__u64 reserved_z13:1; /* Reserved for access_root_scheduler_reg. */
		__u64 reserved_z14:1; /* Reserved for access_tsc_invariant_controls. */

#if defined(__x86_64__)

		/* Extended GVA ranges for HvCallFlushVirtualAddressList hypercall.
		 * Corresponds to privilege.
		 */
		__u64 enable_extended_gva_ranges_for_flush_virtual_address_list:1;
#else
		__u64 reserved_z15:1;
#endif

		__u64 reserved_z16:1; /* Reserved for access_vsm. */
		__u64 reserved_z17:1; /* Reserved for access_vp_registers. */

		/* Use fast hypercall output. Corresponds to privilege. */
		__u64 fast_hypercall_output:1;

		__u64 reserved_z19:1; /* Reserved for enable_extended_hypercalls. */

		/*
		 * HvStartVirtualProcessor can be used to start virtual processors.
		 * Corresponds to privilege.
		 */
		__u64 start_virtual_processor:1;

		__u64 reserved_z21:1; /* Reserved for Isolation. */

		/* Synthetic timers in direct mode. */
		__u64 direct_synthetic_timers:1;

		__u64 reserved_z23:1; /* Reserved for synthetic time unhalted timer */

		/* Use extended processor masks. */
		__u64 extended_processor_masks:1;

		/* HvCallFlushVirtualAddressSpace / HvCallFlushVirtualAddressList are supported. */
		__u64 tb_flush_hypercalls:1;

		/* HvCallSendSyntheticClusterIpi is supported. */
		__u64 synthetic_cluster_ipi:1;

		/* HvCallNotifyLongSpinWait is supported. */
		__u64 notify_long_spin_wait:1;

		/* HvCallQueryNumaDistance is supported. */
		__u64 query_numa_distance:1;

		/* HvCallSignalEvent is supported. Corresponds to privilege. */
		__u64 signal_events:1;

		/* HvCallRetargetDeviceInterrupt is supported. */
		__u64 retarget_device_interrupt:1;

#if defined(__x86_64__)
		/* HvCallRestorePartitionTime is supported. */
		__u64 restore_time:1;

		/* EnlightenedVmcs nested enlightenment is supported. */
		__u64 enlightened_vmcs:1;
#else
		__u64 reserved_z31:1;
		__u64 reserved_z32:1;
#endif

		__u64 reserved:30;
	};
};

#endif
