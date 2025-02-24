#include "hw/hyperv/linux-mshv.h"
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "sysemu/mshv.h"
#include <stdint.h>
#include <sys/ioctl.h>

static GHashTable *cpu_db_mgns;
static QemuMutex cpu_db_mutex_mgns;

void init_cpu_db_mgns(void)
{
	cpu_db_mgns = g_hash_table_new(g_direct_hash, g_direct_equal);
	qemu_mutex_init(&cpu_db_mutex_mgns);
}

static int create_vcpu_mgns(int vm_fd, uint8_t vp_index)
{
	/* int ret; */
	/* struct mshv_create_vp vp_arg = { */
	/* 	.vp_index = vp_index, */
	/* }; */
	/* ret = ioctl(vm_fd, MSHV_CREATE_VP, &vp_arg); */
	/* if (ret < 0) { */
	/* 	perror("failed to create vcpu"); */
	/* 	return -errno; */
	/* } */

	/* return ret; */
	printf("[mgns-qemu] skipped create_vcpu_mgns %d\n", vp_index);
	return 0;
}

void remove_vcpu_mgns(int vcpu_fd)
{
	WITH_QEMU_LOCK_GUARD(&cpu_db_mutex_mgns) {
		g_hash_table_remove(cpu_db_mgns, GUINT_TO_POINTER(vcpu_fd));
	}
}

int new_vcpu_mgns(int mshv_fd, uint8_t vp_index, MshvOps *ops)
{
	int ret, vcpu_fd;
	
	ret = create_vcpu_mgns(mshv_fd, vp_index);
	if (ret < 0) {
		return ret;
	}
	vcpu_fd = ret;

	PerCpuInfoMgns *info = g_new0(PerCpuInfoMgns, 1);
	info->vp_index = vp_index;
	info->ops = ops;
	info->vp_fd = vcpu_fd;

	WITH_QEMU_LOCK_GUARD(&cpu_db_mutex_mgns) {
		g_hash_table_insert(cpu_db_mgns, GUINT_TO_POINTER(vcpu_fd), info);
	}

	return 0;
}
