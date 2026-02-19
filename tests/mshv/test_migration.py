#!/usr/bin/env python3
#
# MSHV live migration test
#
# Uses the same a-b bootblock from qtest migration tests: a 512-byte x86
# boot sector that repeatedly increments the first byte of every 4K page
# in a 100 MB range (1 MB – 100 MB), outputting 'A' once then 'B' on
# every 64th pass via serial.
#
# The test launches a source QEMU with the bootblock, waits for guest
# activity, migrates to a destination QEMU via unix socket, then
# verifies the destination is running.
#
# Copyright Microsoft, Corp. 2025
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import sys
import tempfile
import time

# flush stdout on every print so CI shows output immediately
sys.stdout.reconfigure(line_buffering=True)

# Allow importing qemu.machine from the source tree
qemu_python = os.path.join(os.path.dirname(__file__), '..', '..', 'python')
sys.path.insert(0, qemu_python)

from qemu.machine import QEMUMachine  # noqa: E402

# 512-byte x86 boot sector from tests/qtest/migration/i386/a-b-bootblock.h
X86_BOOTSECT = bytes([
    0xfa, 0x0f, 0x01, 0x16, 0xb8, 0x7c, 0x66, 0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0x22, 0xc0, 0x66, 0xea, 0x20, 0x7c, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x92, 0x0c, 0x02,
    0xe6, 0x92, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e, 0xd8, 0x66, 0xb8, 0x41,
    0x00, 0x66, 0xba, 0xf8, 0x03, 0xee, 0xb3, 0x00, 0xb8, 0x00, 0x00, 0x10,
    0x00, 0xc6, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00, 0x3d, 0x00, 0x00,
    0x40, 0x06, 0x7c, 0xf1, 0xb8, 0x00, 0x00, 0x10, 0x00, 0xfe, 0x00, 0x05,
    0x00, 0x10, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x40, 0x06, 0x7c, 0xf2, 0xfe,
    0xc3, 0x80, 0xe3, 0x3f, 0x75, 0xe6, 0x66, 0xb8, 0x42, 0x00, 0x66, 0xba,
    0xf8, 0x03, 0xee, 0xa1, 0xbe, 0x7c, 0x00, 0x00, 0x83, 0xf8, 0x00, 0x74,
    0xd3, 0xb8, 0x04, 0x00, 0x10, 0x00, 0x8b, 0x00, 0x83, 0xf8, 0x01, 0x74,
    0xc7, 0xb0, 0xf1, 0xe6, 0xb2, 0xb8, 0x04, 0x00, 0x10, 0x00, 0xc7, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x66, 0xb8, 0x01, 0x24, 0x66, 0xba, 0x04, 0x06,
    0x66, 0xef, 0x66, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xcf, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x92, 0xcf, 0x00, 0x27, 0x00, 0xa0, 0x7c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xaa,
])

MIGRATION_TIMEOUT = 30


def wait_for_migration(vm, timeout=MIGRATION_TIMEOUT):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = vm.cmd('query-migrate')['status']
        if status in ('completed', 'failed'):
            return status
        time.sleep(0.1)
    return 'timeout'


def make_vm(qemu_bin, name, tmpdir, extra_args=None, incoming=None):
    args = [
        '-accel', 'mshv',
        '-nodefaults',
        '-serial', 'file:%s/%s-serial.log' % (tmpdir, name),
    ]
    if incoming:
        args += ['-incoming', incoming]
    if extra_args:
        args += extra_args

    vm = QEMUMachine(qemu_bin, args=args, name=name,
                     base_temp_dir=tmpdir)
    return vm


def do_migrate(src, dst, migrate_uri):
    """Migrate src→dst and verify completion."""
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


def run_migration_test(qemu_bin, machine='q35', memory='256M',
                       smp='1', cpu_model=None, roundtrip=False):
    with tempfile.TemporaryDirectory(prefix='mshv_mig_') as tmpdir:
        # write bootblock to disk image
        bootfile = os.path.join(tmpdir, 'bootsect')
        with open(bootfile, 'wb') as f:
            f.write(X86_BOOTSECT)

        drive_args = [
            '-drive', 'if=none,id=d0,file=%s,format=raw' % bootfile,
            '-device', 'ide-hd,drive=d0,secs=1,cyls=1,heads=1',
        ]
        common_args = [
            '-machine', machine,
            '-m', memory,
            '-smp', smp,
        ]
        if cpu_model:
            common_args += ['-cpu', cpu_model]

        sock_path = os.path.join(tmpdir, 'migrate.sock')
        migrate_uri = 'unix:%s' % sock_path

        # launch destination (waiting for incoming migration)
        dst = make_vm(qemu_bin, 'dst', tmpdir,
                      extra_args=drive_args + common_args,
                      incoming=migrate_uri)
        dst.launch()
        print('  destination launched, waiting for incoming migration')

        # launch source
        src = make_vm(qemu_bin, 'src', tmpdir,
                      extra_args=drive_args + common_args)
        src.launch()
        print('  source launched')

        # verify both VMs are using the mshv accelerator
        for label, vm in [('source', src), ('destination', dst)]:
            accel = vm.cmd('query-accelerators')['enabled']
            assert accel == 'mshv', \
                '%s using %s accelerator, expected mshv' % (label, accel)
        print('  both VMs confirmed using mshv accelerator')

        # let the bootblock run a bit to generate dirty pages
        time.sleep(2)

        # verify source is running
        src_status = src.cmd('query-status')['status']
        assert src_status == 'running', \
            'source not running: %s' % src_status
        print('  source confirmed running')

        # check serial output for guest activity
        serial_log = os.path.join(tmpdir, 'src-serial.log')
        if os.path.exists(serial_log):
            with open(serial_log, 'r') as f:
                serial = f.read()
            if 'A' in serial:
                print('  guest bootblock active (serial: %r)' %
                      serial[:20])

        # migrate source → destination
        print('  migrating source -> destination')
        do_migrate(src, dst, migrate_uri)
        print('  migration completed')

        # let destination run briefly to confirm guest is alive
        time.sleep(2)
        dst_status = dst.cmd('query-status')['status']
        assert dst_status == 'running', \
            'destination stopped after migration: %s' % dst_status
        print('  destination still running after 2s')

        # check destination serial for continued guest activity
        dst_serial = os.path.join(tmpdir, 'dst-serial.log')
        if os.path.exists(dst_serial):
            with open(dst_serial, 'r') as f:
                serial = f.read()
            if 'B' in serial:
                print('  guest resumed on destination (serial: %r)' %
                      serial[:20])

        if roundtrip:
            # migrate back: destination → source
            print('  round-trip: migrating destination -> source')
            sock_path2 = os.path.join(tmpdir, 'migrate2.sock')
            migrate_uri2 = 'unix:%s' % sock_path2

            # set up source to accept incoming migration
            src.shutdown()
            src = make_vm(qemu_bin, 'src2', tmpdir,
                          extra_args=drive_args + common_args,
                          incoming=migrate_uri2)
            src.launch()

            do_migrate(dst, src, migrate_uri2)
            print('  round-trip migration completed')

            time.sleep(2)
            src_status = src.cmd('query-status')['status']
            assert src_status == 'running', \
                'source not running after round-trip: %s' % src_status
            print('  guest still running after round-trip')

            src.shutdown()
            dst.shutdown()
        else:
            dst.shutdown()
            src.shutdown()

        print('  VMs shut down')


def run_direct_boot_migration_test(qemu_bin, kernel, initrd,
                                   machine='q35', memory='256M',
                                   smp='1', cpu_model=None):
    """Migration test using Linux direct boot (-kernel/-initrd)."""
    with tempfile.TemporaryDirectory(prefix='mshv_mig_dk_') as tmpdir:
        sock_path = os.path.join(tmpdir, 'migrate.sock')
        migrate_uri = 'unix:%s' % sock_path

        common_args = [
            '-machine', machine,
            '-m', memory,
            '-smp', smp,
            '-kernel', kernel,
            '-initrd', initrd,
            '-append', 'console=ttyS0 panic=-1',
        ]
        if cpu_model:
            common_args += ['-cpu', cpu_model]

        # launch destination (waiting for incoming migration)
        dst = make_vm(qemu_bin, 'dst', tmpdir,
                      extra_args=common_args,
                      incoming=migrate_uri)
        dst.launch()
        print('  destination launched')

        # launch source
        src = make_vm(qemu_bin, 'src', tmpdir,
                      extra_args=common_args)
        src.launch()
        print('  source launched')

        # verify accelerator
        for label, vm in [('source', src), ('destination', dst)]:
            accel = vm.cmd('query-accelerators')['enabled']
            assert accel == 'mshv', \
                '%s using %s accelerator, expected mshv' % (label, accel)
        print('  both VMs confirmed using mshv accelerator')

        # let guest boot and run
        time.sleep(5)

        src_status = src.cmd('query-status')['status']
        assert src_status == 'running', \
            'source not running: %s' % src_status
        print('  source confirmed running')

        # check serial for init output
        serial_log = os.path.join(tmpdir, 'src-serial.log')
        if os.path.exists(serial_log):
            with open(serial_log, 'r') as f:
                serial = f.read()
            if 'A' in serial:
                print('  init active on source (serial: %r)' %
                      serial[-40:])

        # migrate
        print('  migrating source -> destination')
        do_migrate(src, dst, migrate_uri)
        print('  migration completed')

        # verify destination alive after migration
        time.sleep(3)
        dst_status = dst.cmd('query-status')['status']
        assert dst_status == 'running', \
            'destination not running after migration: %s' % dst_status
        print('  destination still running after 3s')

        # check destination serial for continued activity
        dst_serial = os.path.join(tmpdir, 'dst-serial.log')
        if os.path.exists(dst_serial):
            with open(dst_serial, 'r') as f:
                serial = f.read()
            if 'B' in serial:
                print('  init resumed on destination (serial: %r)' %
                      serial[-40:])

        dst.kill()
        src.kill()
        print('  VMs shut down')
def main():
    parser = argparse.ArgumentParser(
        description='MSHV live migration test')
    parser.add_argument('qemu_bin',
                        help='path to qemu-system-x86_64 binary')
    parser.add_argument('--machine', default='q35',
                        help='machine type (default: q35)')
    parser.add_argument('--memory', default='256M',
                        help='guest memory (default: 256M)')
    parser.add_argument('--smp', default='1',
                        help='number of vCPUs (default: 1)')
    parser.add_argument('--cpu', default=None,
                        help='CPU model (default: QEMU default)')
    parser.add_argument('--roundtrip', action='store_true',
                        help='migrate back to source after first migration')
    parser.add_argument('--kernel', default=None,
                        help='kernel for direct boot migration test')
    parser.add_argument('--initrd', default=None,
                        help='initrd for direct boot migration test')
    args = parser.parse_args()

    print('MSHV migration test')
    print('  binary: %s' % args.qemu_bin)
    print('  machine: %s' % args.machine)
    print('  memory: %s' % args.memory)
    print('  smp: %s' % args.smp)
    print('  cpu: %s' % (args.cpu or '(default)'))
    print('  roundtrip: %s' % args.roundtrip)

    if args.kernel:
        assert args.initrd, '--initrd required with --kernel'
        print('  kernel: %s' % args.kernel)
        print('  initrd: %s' % args.initrd)
        print()
        run_direct_boot_migration_test(
            args.qemu_bin, args.kernel, args.initrd,
            args.machine, args.memory, args.smp, args.cpu)
    else:
        print()
        run_migration_test(args.qemu_bin, args.machine, args.memory,
                           args.smp, args.cpu, args.roundtrip)
    print('PASS')


if __name__ == '__main__':
    main()
