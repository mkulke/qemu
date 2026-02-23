#!/usr/bin/env python3
#
# MSHV live migration test with a full Ubuntu cloud image.
#
# Boots an Ubuntu guest on the source, verifies SSH access, migrates
# to a destination, then verifies SSH access again on the destination.
# Uses tap networking on a bridge so the guest IP survives migration.
#
# Requires:
#   - Ubuntu cloud image (qcow2)
#   - cloud-init ISO with SSH key
#   - SSH private key
#   - Two tap devices on a bridge (set up by the caller)
#
# Copyright Microsoft, Corp. 2025
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import subprocess
import sys
import tempfile
import time

sys.stdout.reconfigure(line_buffering=True)

qemu_python = os.path.join(os.path.dirname(__file__), '..', '..', 'python')
sys.path.insert(0, qemu_python)

from qemu.machine import QEMUMachine  # noqa: E402

MIGRATION_TIMEOUT = 120
BOOT_TIMEOUT = 120
SSH_RETRY_INTERVAL = 5


def wait_for_migration(vm, timeout=MIGRATION_TIMEOUT):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = vm.cmd('query-migrate')['status']
        if status in ('completed', 'failed'):
            return status
        time.sleep(0.5)
    return 'timeout'


def get_migration_stats(vm):
    """Return key migration statistics from QMP as a dict."""
    info = vm.cmd('query-migrate')
    ram = info.get('ram', {})
    return {
        'total_ms': info.get('total-time', 0),
        'downtime_ms': info.get('downtime', 0),
        'setup_ms': info.get('setup-time', 0),
        'transferred': ram.get('transferred', 0),
        'total_ram': ram.get('total', 0),
        'normal': ram.get('normal', 0),
        'zero': ram.get('duplicate', 0),
        'dirty_syncs': ram.get('dirty-sync-count', 0),
        'mbps': ram.get('mbps', 0),
    }


def print_migration_stats(vm):
    """Print key migration statistics from QMP."""
    s = get_migration_stats(vm)
    print('  migration stats:')
    print('    total=%dms  setup=%dms  downtime=%dms' %
          (s['total_ms'], s['setup_ms'], s['downtime_ms']))
    print('    transferred=%dMiB / %dMiB  throughput=%.0fMbps' %
          (s['transferred'] // (1024 * 1024),
           s['total_ram'] // (1024 * 1024), s['mbps']))
    print('    pages: normal=%d  zero=%d  dirty_syncs=%d' %
          (s['normal'], s['zero'], s['dirty_syncs']))


def do_migrate(src, dst, migrate_uri):
    """Migrate src->dst and verify completion. Returns total migration time in seconds."""
    src.qmp('migrate', uri=migrate_uri)

    src_mig = wait_for_migration(src)
    assert src_mig == 'completed', \
        'source migration failed: %s' % src_mig

    dst_mig = wait_for_migration(dst)
    assert dst_mig == 'completed', \
        'destination migration failed: %s' % dst_mig

    dst_status = dst.cmd('query-status')['status']
    assert dst_status == 'running', \
        'destination not running after migration: %s' % dst_status
    src_status = src.cmd('query-status')['status']
    assert src_status == 'postmigrate', \
        'source not in postmigrate state: %s' % src_status
    stats = get_migration_stats(src)
    print_migration_stats(src)
    return stats['total_ms'] / 1000.0


GUEST_MAC = '00:10:20:30:40:50'

SSH_COMMON_OPTS = [
    '-o', 'PasswordAuthentication=no',
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null',
]


def ssh_cmd(host, key_file, command, timeout=10, control_path=None):
    """Run a command over SSH, return (returncode, stdout)."""
    opts = list(SSH_COMMON_OPTS)
    if control_path:
        opts += ['-o', 'ControlPath=%s' % control_path]
    else:
        opts += ['-o', 'ConnectTimeout=%d' % timeout]
    result = subprocess.run(
        ['ssh', '-i', key_file] + opts +
        ['cloud@%s' % host, command],
        capture_output=True, text=True, timeout=timeout + 5)
    return result.returncode, result.stdout.strip()


def wait_for_ssh(host, key_file, timeout=BOOT_TIMEOUT):
    """Poll SSH until it responds or timeout."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            rc, out = ssh_cmd(host, key_file, 'whoami')
            if rc == 0 and 'cloud' in out:
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(SSH_RETRY_INTERVAL)
    return False


def ssh_control_open(host, key_file, control_path):
    """Open a persistent SSH ControlMaster connection."""
    proc = subprocess.Popen(
        ['ssh', '-i', key_file] + SSH_COMMON_OPTS + [
         '-o', 'ControlMaster=yes',
         '-o', 'ControlPath=%s' % control_path,
         '-o', 'ControlPersist=yes',
         '-N',
         'cloud@%s' % host],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    # wait for control socket to appear
    for _ in range(20):
        if os.path.exists(control_path):
            return proc
        time.sleep(0.5)
    proc.kill()
    raise RuntimeError('SSH ControlMaster socket never appeared')


def ssh_control_close(control_path):
    """Tear down an SSH ControlMaster connection."""
    subprocess.run(
        ['ssh', '-o', 'ControlPath=%s' % control_path, '-O', 'exit', 'dummy'],
        capture_output=True, timeout=5)


def scp_to_guest(host, key_file, local_path, remote_path, control_path=None):
    """Copy a file to the guest via SCP."""
    opts = list(SSH_COMMON_OPTS)
    if control_path:
        opts += ['-o', 'ControlPath=%s' % control_path]
    result = subprocess.run(
        ['scp'] + opts + ['-i', key_file,
         local_path, 'cloud@%s:%s' % (host, remote_path)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, \
        'scp failed: %s' % result.stderr


def make_vm(qemu_bin, name, tmpdir, extra_args=None, incoming=None):
    args = [
        '-accel', 'mshv',
        '-nodefaults',
        '-serial', 'file:%s/%s-serial.log' % (tmpdir, name),
        '-rtc', 'clock=vm',
    ]
    if incoming:
        args += ['-incoming', incoming]
    if extra_args:
        args += extra_args

    vm = QEMUMachine(qemu_bin, args=args, name=name,
                     base_temp_dir=tmpdir, qmp_timer=60)
    return vm


def run_test(qemu_bin, disk_img, ci_img, ssh_key,
             guest_ip, src_tap, dst_tap,
             machine='q35', memory='2048M', smp='2', stress=False,
             cpu=None, avx2=False):
    with tempfile.TemporaryDirectory(prefix='mshv_mig_ubuntu_') as tmpdir:
        sock_path = os.path.join(tmpdir, 'migrate.sock')
        migrate_uri = 'unix:%s' % sock_path
        ctl_path = os.path.join(tmpdir, 'ssh_ctl')

        def vm_args(tap):
            args = [
                '-machine', machine,
                '-m', memory,
                '-smp', smp,
                '-drive', 'file=%s,format=qcow2,if=none,id=osdisk,snapshot=on'
                          % disk_img,
                '-device', 'virtio-blk-pci,drive=osdisk',
                '-drive', 'file=%s,format=raw,if=none,id=cidata' % ci_img,
                '-device', 'virtio-blk-pci,drive=cidata',
                '-netdev', 'tap,id=net0,ifname=%s,'
                           'script=no,downscript=no' % tap,
                '-device', 'virtio-net,mac=%s,'
                           'netdev=net0' % GUEST_MAC,
            ]
            if cpu:
                args += ['-cpu', cpu]
            return args

        # launch destination (waiting for incoming migration)
        dst = make_vm(qemu_bin, 'dst', tmpdir,
                      extra_args=vm_args(dst_tap),
                      incoming=migrate_uri)
        dst.launch()
        print('  destination launched')

        # launch source
        src = make_vm(qemu_bin, 'src', tmpdir,
                      extra_args=vm_args(src_tap))
        src.launch()
        print('  source launched')

        # verify accelerator
        for label, vm in [('source', src), ('destination', dst)]:
            accel = vm.cmd('query-accelerators')['enabled']
            assert accel == 'mshv', \
                '%s using %s, expected mshv' % (label, accel)
        print('  both VMs confirmed using mshv accelerator')

        # wait for guest to boot and SSH to become available
        print('  waiting for SSH on source (%s)...' % guest_ip)
        assert wait_for_ssh(guest_ip, ssh_key), \
            'SSH not available on source after %ds' % BOOT_TIMEOUT
        print('  SSH available on source')

        # open persistent SSH connection
        ctl_proc = ssh_control_open(guest_ip, ssh_key, ctl_path)
        print('  persistent SSH connection established')

        # verify guest is functional via the persistent connection
        rc, out = ssh_cmd(guest_ip, ssh_key, 'uname -r',
                          control_path=ctl_path)
        assert rc == 0, 'uname failed on source'
        kernel_before = out
        print('  source kernel: %s' % kernel_before)

        # record guest time before migration
        rc, time_before = ssh_cmd(guest_ip, ssh_key,
                                  'date +%s.%N',
                                  timeout=30, control_path=ctl_path)
        assert rc == 0, 'date failed on source'
        host_before = time.time()

        # optionally start stress-ng to dirty RAM and exercise disk
        if stress:
            rc, _ = ssh_cmd(guest_ip, ssh_key,
                            'sudo apt-get update -qq && '
                            'sudo apt-get install -y -qq stress-ng',
                            timeout=60, control_path=ctl_path)
            assert rc == 0, 'failed to install stress-ng'
            print('  stress-ng installed')
            rc, _ = ssh_cmd(guest_ip, ssh_key,
                            'nohup stress-ng --vm 2 --vm-bytes 256M --hdd 1 '
                            '--cpu %s --timeout 120 >/dev/null 2>&1 &' % smp,
                            timeout=10, control_path=ctl_path)
            assert rc == 0, 'failed to start stress-ng'
            time.sleep(2)
            rc, out = ssh_cmd(guest_ip, ssh_key, 'pgrep -c stress-ng',
                              timeout=30, control_path=ctl_path)
            assert rc == 0 and int(out) > 0, 'stress-ng not running'
            print('  stress-ng running (%s processes)' % out.strip())

        # migrate under load
        print('  migrating source -> destination')
        mig_time_s = do_migrate(src, dst, migrate_uri)
        print('  migration completed')

        # verify SSH still works over the SAME persistent connection
        rc, out = ssh_cmd(guest_ip, ssh_key, 'uname -r', timeout=30,
                          control_path=ctl_path)
        assert rc == 0, 'uname failed on destination over persistent SSH'
        kernel_after = out
        print('  destination kernel (same connection): %s' % kernel_after)
        assert kernel_before == kernel_after, \
            'kernel mismatch: %s vs %s' % (kernel_before, kernel_after)

        # verify guest clock hasn't drifted excessively
        # with -rtc clock=vm, guest time stops for the migration duration
        rc, time_after = ssh_cmd(guest_ip, ssh_key,
                                 'date +%s.%N',
                                 timeout=30, control_path=ctl_path)
        assert rc == 0, 'date failed on destination'
        host_after = time.time()
        guest_elapsed = float(time_after) - float(time_before)
        host_elapsed = host_after - host_before
        drift = abs(guest_elapsed - (host_elapsed - mig_time_s))
        print('  clock drift: %.2fs (guest=%.2fs host=%.2fs mig=%.2fs)' %
              (drift, guest_elapsed, host_elapsed, mig_time_s))
        assert drift < 3.0, \
            'guest clock drifted %.2fs from host (adjusted for migration)' % drift

        # verify stress-ng survived migration (tests APIC/IPI state on SMP)
        if stress:
            rc, out = ssh_cmd(guest_ip, ssh_key, 'pgrep -c stress-ng',
                              timeout=30, control_path=ctl_path)
            assert rc == 0 and int(out) > 0, \
                'stress-ng not running after migration'
            print('  stress-ng still running (%s processes)' % out.strip())

        # verify AVX2/XSAVE state survived migration
        if avx2:
            test_dir = os.path.dirname(os.path.abspath(__file__))
            avx2_bin = os.path.join(test_dir, 'test-avx2')
            assert os.path.isfile(avx2_bin), \
                'AVX2 test binary not found: %s' % avx2_bin
            scp_to_guest(guest_ip, ssh_key, avx2_bin, '/tmp/test-avx2',
                         control_path=ctl_path)
            rc, out = ssh_cmd(guest_ip, ssh_key,
                              'chmod +x /tmp/test-avx2 && /tmp/test-avx2',
                              timeout=10, control_path=ctl_path)
            assert rc == 0, \
                'AVX2 test failed on destination: %s' % out
            print('  AVX2/XSAVE test passed on destination')

        # clean up
        ssh_control_close(ctl_path)
        ctl_proc.wait(timeout=5)
        dst.kill()
        src.kill()
        print('  VMs shut down')


def main():
    parser = argparse.ArgumentParser(
        description='MSHV Ubuntu live migration test')
    parser.add_argument('qemu_bin',
                        help='path to qemu-system-x86_64 binary')
    parser.add_argument('--disk', required=True,
                        help='path to Ubuntu cloud image (qcow2)')
    parser.add_argument('--ci-img', required=True,
                        help='path to cloud-init ISO')
    parser.add_argument('--ssh-key', required=True,
                        help='path to SSH private key')
    parser.add_argument('--guest-ip', default='192.168.100.2',
                        help='guest IP address (default: 192.168.100.2)')
    parser.add_argument('--src-tap', default='tap0',
                        help='source tap device (default: tap0)')
    parser.add_argument('--dst-tap', default='tap1',
                        help='destination tap device (default: tap1)')
    parser.add_argument('--machine', default='q35',
                        help='machine type (default: q35)')
    parser.add_argument('--memory', default='2048M',
                        help='guest memory (default: 2048M)')
    parser.add_argument('--smp', default='2',
                        help='number of vCPUs (default: 2)')
    parser.add_argument('--stress', action='store_true',
                        help='run stress-ng during migration')
    parser.add_argument('--cpu', default=None,
                        help='CPU model (e.g. host)')
    parser.add_argument('--avx2', action='store_true',
                        help='run AVX2/XSAVE test on destination')
    args = parser.parse_args()

    print('MSHV Ubuntu migration test')
    print('  binary: %s' % args.qemu_bin)
    print('  disk: %s' % args.disk)
    print('  machine: %s' % args.machine)
    print('  memory: %s' % args.memory)
    print('  smp: %s' % args.smp)
    print('  cpu: %s' % (args.cpu or '(default)'))
    print('  stress: %s' % args.stress)
    print('  avx2: %s' % args.avx2)
    print('  guest-ip: %s' % args.guest_ip)
    print('  taps: %s (src), %s (dst)' % (args.src_tap, args.dst_tap))
    print()

    run_test(args.qemu_bin, args.disk, args.ci_img, args.ssh_key,
             args.guest_ip, args.src_tap, args.dst_tap,
             args.machine, args.memory, args.smp, args.stress,
             args.cpu, args.avx2)
    print('PASS')


if __name__ == '__main__':
    main()
