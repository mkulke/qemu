# This file is generated by meson-buildoptions.py, do not edit!
meson_options_help() {
  printf "%s\n" '  --audio-drv-list=CHOICES Set audio driver list [default] (choices: alsa/co'
  printf "%s\n" '                           reaudio/default/dsound/jack/oss/pa/pipewire/sdl/s'
  printf "%s\n" '                           ndio)'
  printf "%s\n" '  --bindir=VALUE           Executable directory [bin]'
  printf "%s\n" '  --block-drv-ro-whitelist=VALUE'
  printf "%s\n" '                           set block driver read-only whitelist (by default'
  printf "%s\n" '                           affects only QEMU, not tools like qemu-img)'
  printf "%s\n" '  --block-drv-rw-whitelist=VALUE'
  printf "%s\n" '                           set block driver read-write whitelist (by default'
  printf "%s\n" '                           affects only QEMU, not tools like qemu-img)'
  printf "%s\n" '  --datadir=VALUE          Data file directory [share]'
  printf "%s\n" '  --disable-coroutine-pool coroutine freelist (better performance)'
  printf "%s\n" '  --disable-debug-info     Enable debug symbols and other information'
  printf "%s\n" '  --disable-hexagon-idef-parser'
  printf "%s\n" '                           use idef-parser to automatically generate TCG'
  printf "%s\n" '                           code for the Hexagon frontend'
  printf "%s\n" '  --disable-install-blobs  install provided firmware blobs'
  printf "%s\n" '  --disable-qom-cast-debug cast debugging support'
  printf "%s\n" '  --disable-relocatable    toggle relocatable install'
  printf "%s\n" '  --docdir=VALUE           Base directory for documentation installation'
  printf "%s\n" '                           (can be empty) [share/doc]'
  printf "%s\n" '  --enable-asan            enable address sanitizer'
  printf "%s\n" '  --enable-block-drv-whitelist-in-tools'
  printf "%s\n" '                           use block whitelist also in tools instead of only'
  printf "%s\n" '                           QEMU'
  printf "%s\n" '  --enable-cfi             Control-Flow Integrity (CFI)'
  printf "%s\n" '  --enable-cfi-debug       Verbose errors in case of CFI violation'
  printf "%s\n" '  --enable-debug-graph-lock'
  printf "%s\n" '                           graph lock debugging support'
  printf "%s\n" '  --enable-debug-mutex     mutex debugging support'
  printf "%s\n" '  --enable-debug-remap     syscall buffer debugging support'
  printf "%s\n" '  --enable-debug-stack-usage'
  printf "%s\n" '                           measure coroutine stack usage'
  printf "%s\n" '  --enable-debug-tcg       TCG debugging'
  printf "%s\n" '  --enable-fdt[=CHOICE]    Whether and how to find the libfdt library'
  printf "%s\n" '                           (choices: auto/disabled/enabled/internal/system)'
  printf "%s\n" '  --enable-fuzzing         build fuzzing targets'
  printf "%s\n" '  --enable-gcov            Enable coverage tracking.'
  printf "%s\n" '  --enable-lto             Use link time optimization'
  printf "%s\n" '  --enable-malloc=CHOICE   choose memory allocator to use [system] (choices:'
  printf "%s\n" '                           jemalloc/system/tcmalloc)'
  printf "%s\n" '  --enable-module-upgrades try to load modules from alternate paths for'
  printf "%s\n" '                           upgrades'
  printf "%s\n" '  --enable-rng-none        dummy RNG, avoid using /dev/(u)random and'
  printf "%s\n" '                           getrandom()'
  printf "%s\n" '  --enable-safe-stack      SafeStack Stack Smash Protection (requires'
  printf "%s\n" '                           clang/llvm and coroutine backend ucontext)'
  printf "%s\n" '  --enable-strict-rust-lints'
  printf "%s\n" '                           Enable stricter set of Rust warnings'
  printf "%s\n" '  --enable-strip           Strip targets on install'
  printf "%s\n" '  --enable-tcg-interpreter TCG with bytecode interpreter (slow)'
  printf "%s\n" '  --enable-trace-backends=CHOICES'
  printf "%s\n" '                           Set available tracing backends [log] (choices:'
  printf "%s\n" '                           dtrace/ftrace/log/nop/simple/syslog/ust)'
  printf "%s\n" '  --enable-tsan            enable thread sanitizer'
  printf "%s\n" '  --enable-ubsan           enable undefined behaviour sanitizer'
  printf "%s\n" '  --firmwarepath=VALUES    search PATH for firmware files [share/qemu-'
  printf "%s\n" '                           firmware]'
  printf "%s\n" '  --iasl=VALUE             Path to ACPI disassembler'
  printf "%s\n" '  --includedir=VALUE       Header file directory [include]'
  printf "%s\n" '  --interp-prefix=VALUE    where to find shared libraries etc., use %M for'
  printf "%s\n" '                           cpu name [/usr/gnemul/qemu-%M]'
  printf "%s\n" '  --libdir=VALUE           Library directory [system default]'
  printf "%s\n" '  --libexecdir=VALUE       Library executable directory [libexec]'
  printf "%s\n" '  --localedir=VALUE        Locale data directory [share/locale]'
  printf "%s\n" '  --localstatedir=VALUE    Localstate data directory [/var/local]'
  printf "%s\n" '  --mandir=VALUE           Manual page directory [share/man]'
  printf "%s\n" '  --prefix=VALUE           Installation prefix [/usr/local]'
  printf "%s\n" '  --qemu-ga-distro=VALUE   second path element in qemu-ga registry entries'
  printf "%s\n" '                           [Linux]'
  printf "%s\n" '  --qemu-ga-manufacturer=VALUE'
  printf "%s\n" '                           "manufacturer" name for qemu-ga registry entries'
  printf "%s\n" '                           [QEMU]'
  printf "%s\n" '  --qemu-ga-version=VALUE  version number for qemu-ga installer'
  printf "%s\n" '  --rtsig-map=VALUE        default value of QEMU_RTSIG_MAP [NULL]'
  printf "%s\n" '  --smbd=VALUE             Path to smbd for slirp networking'
  printf "%s\n" '  --sysconfdir=VALUE       Sysconf data directory [etc]'
  printf "%s\n" '  --tls-priority=VALUE     Default TLS protocol/cipher priority string'
  printf "%s\n" '                           [NORMAL]'
  printf "%s\n" '  --with-coroutine=CHOICE  coroutine backend to use (choices:'
  printf "%s\n" '                           auto/sigaltstack/ucontext/wasm/windows)'
  printf "%s\n" '  --with-pkgversion=VALUE  use specified string as sub-version of the'
  printf "%s\n" '                           package'
  printf "%s\n" '  --with-suffix=VALUE      Suffix for QEMU data/modules/config directories'
  printf "%s\n" '                           (can be empty) [qemu]'
  printf "%s\n" '  --with-trace-file=VALUE  Trace file prefix for simple backend [trace]'
  printf "%s\n" '  --x86-version=CHOICE     tweak required x86_64 architecture version beyond'
  printf "%s\n" '                           compiler default [1] (choices: 0/1/2/3/4)'
  printf "%s\n" ''
  printf "%s\n" 'Optional features, enabled with --enable-FEATURE and'
  printf "%s\n" 'disabled with --disable-FEATURE, default is enabled if available'
  printf "%s\n" '(unless built with --without-default-features):'
  printf "%s\n" ''
  printf "%s\n" '  af-xdp          AF_XDP network backend support'
  printf "%s\n" '  alsa            ALSA sound support'
  printf "%s\n" '  attr            attr/xattr support'
  printf "%s\n" '  auth-pam        PAM access control'
  printf "%s\n" '  blkio           libblkio block device driver'
  printf "%s\n" '  bochs           bochs image format support'
  printf "%s\n" '  bpf             eBPF support'
  printf "%s\n" '  brlapi          brlapi character device driver'
  printf "%s\n" '  bzip2           bzip2 support for DMG images'
  printf "%s\n" '  canokey         CanoKey support'
  printf "%s\n" '  cap-ng          cap_ng support'
  printf "%s\n" '  capstone        Whether and how to find the capstone library'
  printf "%s\n" '  cloop           cloop image format support'
  printf "%s\n" '  cocoa           Cocoa user interface (macOS only)'
  printf "%s\n" '  colo-proxy      colo-proxy support'
  printf "%s\n" '  coreaudio       CoreAudio sound support'
  printf "%s\n" '  crypto-afalg    Linux AF_ALG crypto backend driver'
  printf "%s\n" '  curl            CURL block device driver'
  printf "%s\n" '  curses          curses UI'
  printf "%s\n" '  dbus-display    -display dbus support'
  printf "%s\n" '  dmg             dmg image format support'
  printf "%s\n" '  docs            Documentations build support'
  printf "%s\n" '  dsound          DirectSound sound support'
  printf "%s\n" '  fuse            FUSE block device export'
  printf "%s\n" '  fuse-lseek      SEEK_HOLE/SEEK_DATA support for FUSE exports'
  printf "%s\n" '  gcrypt          libgcrypt cryptography support'
  printf "%s\n" '  gettext         Localization of the GTK+ user interface'
  printf "%s\n" '  gio             use libgio for D-Bus support'
  printf "%s\n" '  glusterfs       Glusterfs block device driver'
  printf "%s\n" '  gnutls          GNUTLS cryptography support'
  printf "%s\n" '  gnutls-bug1717-workaround'
  printf "%s\n" '                  GNUTLS workaround for'
  printf "%s\n" '                  https://gitlab.com/gnutls/gnutls/-/issues/1717'
  printf "%s\n" '  gtk             GTK+ user interface'
  printf "%s\n" '  gtk-clipboard   clipboard support for the gtk UI (EXPERIMENTAL, MAY HANG)'
  printf "%s\n" '  guest-agent     Build QEMU Guest Agent'
  printf "%s\n" '  guest-agent-msi Build MSI package for the QEMU Guest Agent'
  printf "%s\n" '  hv-balloon      hv-balloon driver (requires Glib 2.68+ GTree API)'
  printf "%s\n" '  hvf             HVF acceleration support'
  printf "%s\n" '  iconv           Font glyph conversion support'
  printf "%s\n" '  igvm            Independent Guest Virtual Machine (IGVM) file support'
  printf "%s\n" '  jack            JACK sound support'
  printf "%s\n" '  keyring         Linux keyring support'
  printf "%s\n" '  kvm             KVM acceleration support'
  printf "%s\n" '  l2tpv3          l2tpv3 network backend support'
  printf "%s\n" '  libcbor         libcbor support'
  printf "%s\n" '  libdaxctl       libdaxctl support'
  printf "%s\n" '  libdw           debuginfo support'
  printf "%s\n" '  libiscsi        libiscsi userspace initiator'
  printf "%s\n" '  libkeyutils     Linux keyutils support'
  printf "%s\n" '  libnfs          libnfs block device driver'
  printf "%s\n" '  libpmem         libpmem support'
  printf "%s\n" '  libssh          ssh block device support'
  printf "%s\n" '  libudev         Use libudev to enumerate host devices'
  printf "%s\n" '  libusb          libusb support for USB passthrough'
  printf "%s\n" '  libvduse        build VDUSE Library'
  printf "%s\n" '  linux-aio       Linux AIO support'
  printf "%s\n" '  linux-io-uring  Linux io_uring support'
  printf "%s\n" '  lzfse           lzfse support for DMG images'
  printf "%s\n" '  lzo             lzo compression support'
  printf "%s\n" '  malloc-trim     enable libc malloc_trim() for memory optimization'
  printf "%s\n" '  membarrier      membarrier system call (for Linux 4.14+ or Windows'
  printf "%s\n" '  modules         modules support (non Windows)'
  printf "%s\n" '  mpath           Multipath persistent reservation passthrough'
  printf "%s\n" '  mshv            MSHV acceleration support'
  printf "%s\n" '  multiprocess    Out of process device emulation support'
  printf "%s\n" '  netmap          netmap network backend support'
  printf "%s\n" '  nettle          nettle cryptography support'
  printf "%s\n" '  numa            libnuma support'
  printf "%s\n" '  nvmm            NVMM acceleration support'
  printf "%s\n" '  opengl          OpenGL support'
  printf "%s\n" '  oss             OSS sound support'
  printf "%s\n" '  pa              PulseAudio sound support'
  printf "%s\n" '  parallels       parallels image format support'
  printf "%s\n" '  passt           passt network backend support'
  printf "%s\n" '  pipewire        PipeWire sound support'
  printf "%s\n" '  pixman          pixman support'
  printf "%s\n" '  plugins         TCG plugins via shared library loading'
  printf "%s\n" '  png             PNG support with libpng'
  printf "%s\n" '  pvg             macOS paravirtualized graphics support'
  printf "%s\n" '  qatzip          QATzip compression support'
  printf "%s\n" '  qcow1           qcow1 image format support'
  printf "%s\n" '  qed             qed image format support'
  printf "%s\n" '  qga-vss         build QGA VSS support (broken with MinGW)'
  printf "%s\n" '  qpl             Query Processing Library support'
  printf "%s\n" '  rbd             Ceph block device driver'
  printf "%s\n" '  rdma            Enable RDMA-based migration'
  printf "%s\n" '  replication     replication support'
  printf "%s\n" '  rust            Rust support'
  printf "%s\n" '  rutabaga-gfx    rutabaga_gfx support'
  printf "%s\n" '  sdl             SDL user interface'
  printf "%s\n" '  sdl-image       SDL Image support for icons'
  printf "%s\n" '  seccomp         seccomp support'
  printf "%s\n" '  selinux         SELinux support in qemu-nbd'
  printf "%s\n" '  slirp           libslirp user mode network backend support'
  printf "%s\n" '  slirp-smbd      use smbd (at path --smbd=*) in slirp networking'
  printf "%s\n" '  smartcard       CA smartcard emulation support'
  printf "%s\n" '  snappy          snappy compression support'
  printf "%s\n" '  sndio           sndio sound support'
  printf "%s\n" '  sparse          sparse checker'
  printf "%s\n" '  spice           Spice server support'
  printf "%s\n" '  spice-protocol  Spice protocol support'
  printf "%s\n" '  stack-protector compiler-provided stack protection'
  printf "%s\n" '  tcg             TCG support'
  printf "%s\n" '  tools           build support utilities that come with QEMU'
  printf "%s\n" '  tpm             TPM support'
  printf "%s\n" '  u2f             U2F emulation support'
  printf "%s\n" '  uadk            UADK Library support'
  printf "%s\n" '  usb-redir       libusbredir support'
  printf "%s\n" '  valgrind        valgrind debug support for coroutine stacks'
  printf "%s\n" '  vde             vde network backend support'
  printf "%s\n" '  vdi             vdi image format support'
  printf "%s\n" '  vduse-blk-export'
  printf "%s\n" '                  VDUSE block export support'
  printf "%s\n" '  vfio-user-server'
  printf "%s\n" '                  vfio-user server support'
  printf "%s\n" '  vhdx            vhdx image format support'
  printf "%s\n" '  vhost-crypto    vhost-user crypto backend support'
  printf "%s\n" '  vhost-kernel    vhost kernel backend support'
  printf "%s\n" '  vhost-net       vhost-net kernel acceleration support'
  printf "%s\n" '  vhost-user      vhost-user backend support'
  printf "%s\n" '  vhost-user-blk-server'
  printf "%s\n" '                  build vhost-user-blk server'
  printf "%s\n" '  vhost-vdpa      vhost-vdpa kernel backend support'
  printf "%s\n" '  virglrenderer   virgl rendering support'
  printf "%s\n" '  virtfs          virtio-9p support'
  printf "%s\n" '  vmdk            vmdk image format support'
  printf "%s\n" '  vmnet           vmnet.framework network backend support'
  printf "%s\n" '  vnc             VNC server'
  printf "%s\n" '  vnc-jpeg        JPEG lossy compression for VNC server'
  printf "%s\n" '  vnc-sasl        SASL authentication for VNC server'
  printf "%s\n" '  vpc             vpc image format support'
  printf "%s\n" '  vte             vte support for the gtk UI'
  printf "%s\n" '  vvfat           vvfat image format support'
  printf "%s\n" '  werror          Treat warnings as errors'
  printf "%s\n" '  whpx            WHPX acceleration support'
  printf "%s\n" '  xen             Xen backend support'
  printf "%s\n" '  xen-pci-passthrough'
  printf "%s\n" '                  Xen PCI passthrough support'
  printf "%s\n" '  xkbcommon       xkbcommon support'
  printf "%s\n" '  zstd            zstd compression support'
}
_meson_option_parse() {
  case $1 in
    --enable-af-xdp) printf "%s" -Daf_xdp=enabled ;;
    --disable-af-xdp) printf "%s" -Daf_xdp=disabled ;;
    --enable-alsa) printf "%s" -Dalsa=enabled ;;
    --disable-alsa) printf "%s" -Dalsa=disabled ;;
    --enable-asan) printf "%s" -Dasan=true ;;
    --disable-asan) printf "%s" -Dasan=false ;;
    --enable-attr) printf "%s" -Dattr=enabled ;;
    --disable-attr) printf "%s" -Dattr=disabled ;;
    --audio-drv-list=*) quote_sh "-Daudio_drv_list=$2" ;;
    --enable-auth-pam) printf "%s" -Dauth_pam=enabled ;;
    --disable-auth-pam) printf "%s" -Dauth_pam=disabled ;;
    --enable-gcov) printf "%s" -Db_coverage=true ;;
    --disable-gcov) printf "%s" -Db_coverage=false ;;
    --enable-lto) printf "%s" -Db_lto=true ;;
    --disable-lto) printf "%s" -Db_lto=false ;;
    --bindir=*) quote_sh "-Dbindir=$2" ;;
    --enable-blkio) printf "%s" -Dblkio=enabled ;;
    --disable-blkio) printf "%s" -Dblkio=disabled ;;
    --block-drv-ro-whitelist=*) quote_sh "-Dblock_drv_ro_whitelist=$2" ;;
    --block-drv-rw-whitelist=*) quote_sh "-Dblock_drv_rw_whitelist=$2" ;;
    --enable-block-drv-whitelist-in-tools) printf "%s" -Dblock_drv_whitelist_in_tools=true ;;
    --disable-block-drv-whitelist-in-tools) printf "%s" -Dblock_drv_whitelist_in_tools=false ;;
    --enable-bochs) printf "%s" -Dbochs=enabled ;;
    --disable-bochs) printf "%s" -Dbochs=disabled ;;
    --enable-bpf) printf "%s" -Dbpf=enabled ;;
    --disable-bpf) printf "%s" -Dbpf=disabled ;;
    --enable-brlapi) printf "%s" -Dbrlapi=enabled ;;
    --disable-brlapi) printf "%s" -Dbrlapi=disabled ;;
    --enable-bzip2) printf "%s" -Dbzip2=enabled ;;
    --disable-bzip2) printf "%s" -Dbzip2=disabled ;;
    --enable-canokey) printf "%s" -Dcanokey=enabled ;;
    --disable-canokey) printf "%s" -Dcanokey=disabled ;;
    --enable-cap-ng) printf "%s" -Dcap_ng=enabled ;;
    --disable-cap-ng) printf "%s" -Dcap_ng=disabled ;;
    --enable-capstone) printf "%s" -Dcapstone=enabled ;;
    --disable-capstone) printf "%s" -Dcapstone=disabled ;;
    --enable-cfi) printf "%s" -Dcfi=true ;;
    --disable-cfi) printf "%s" -Dcfi=false ;;
    --enable-cfi-debug) printf "%s" -Dcfi_debug=true ;;
    --disable-cfi-debug) printf "%s" -Dcfi_debug=false ;;
    --enable-cloop) printf "%s" -Dcloop=enabled ;;
    --disable-cloop) printf "%s" -Dcloop=disabled ;;
    --enable-cocoa) printf "%s" -Dcocoa=enabled ;;
    --disable-cocoa) printf "%s" -Dcocoa=disabled ;;
    --enable-colo-proxy) printf "%s" -Dcolo_proxy=enabled ;;
    --disable-colo-proxy) printf "%s" -Dcolo_proxy=disabled ;;
    --enable-coreaudio) printf "%s" -Dcoreaudio=enabled ;;
    --disable-coreaudio) printf "%s" -Dcoreaudio=disabled ;;
    --with-coroutine=*) quote_sh "-Dcoroutine_backend=$2" ;;
    --enable-coroutine-pool) printf "%s" -Dcoroutine_pool=true ;;
    --disable-coroutine-pool) printf "%s" -Dcoroutine_pool=false ;;
    --enable-crypto-afalg) printf "%s" -Dcrypto_afalg=enabled ;;
    --disable-crypto-afalg) printf "%s" -Dcrypto_afalg=disabled ;;
    --enable-curl) printf "%s" -Dcurl=enabled ;;
    --disable-curl) printf "%s" -Dcurl=disabled ;;
    --enable-curses) printf "%s" -Dcurses=enabled ;;
    --disable-curses) printf "%s" -Dcurses=disabled ;;
    --datadir=*) quote_sh "-Ddatadir=$2" ;;
    --enable-dbus-display) printf "%s" -Ddbus_display=enabled ;;
    --disable-dbus-display) printf "%s" -Ddbus_display=disabled ;;
    --enable-debug-info) printf "%s" -Ddebug=true ;;
    --disable-debug-info) printf "%s" -Ddebug=false ;;
    --enable-debug-graph-lock) printf "%s" -Ddebug_graph_lock=true ;;
    --disable-debug-graph-lock) printf "%s" -Ddebug_graph_lock=false ;;
    --enable-debug-mutex) printf "%s" -Ddebug_mutex=true ;;
    --disable-debug-mutex) printf "%s" -Ddebug_mutex=false ;;
    --enable-debug-remap) printf "%s" -Ddebug_remap=true ;;
    --disable-debug-remap) printf "%s" -Ddebug_remap=false ;;
    --enable-debug-stack-usage) printf "%s" -Ddebug_stack_usage=true ;;
    --disable-debug-stack-usage) printf "%s" -Ddebug_stack_usage=false ;;
    --enable-debug-tcg) printf "%s" -Ddebug_tcg=true ;;
    --disable-debug-tcg) printf "%s" -Ddebug_tcg=false ;;
    --enable-dmg) printf "%s" -Ddmg=enabled ;;
    --disable-dmg) printf "%s" -Ddmg=disabled ;;
    --docdir=*) quote_sh "-Ddocdir=$2" ;;
    --enable-docs) printf "%s" -Ddocs=enabled ;;
    --disable-docs) printf "%s" -Ddocs=disabled ;;
    --enable-dsound) printf "%s" -Ddsound=enabled ;;
    --disable-dsound) printf "%s" -Ddsound=disabled ;;
    --enable-fdt) printf "%s" -Dfdt=enabled ;;
    --disable-fdt) printf "%s" -Dfdt=disabled ;;
    --enable-fdt=*) quote_sh "-Dfdt=$2" ;;
    --enable-fuse) printf "%s" -Dfuse=enabled ;;
    --disable-fuse) printf "%s" -Dfuse=disabled ;;
    --enable-fuse-lseek) printf "%s" -Dfuse_lseek=enabled ;;
    --disable-fuse-lseek) printf "%s" -Dfuse_lseek=disabled ;;
    --enable-fuzzing) printf "%s" -Dfuzzing=true ;;
    --disable-fuzzing) printf "%s" -Dfuzzing=false ;;
    --enable-gcrypt) printf "%s" -Dgcrypt=enabled ;;
    --disable-gcrypt) printf "%s" -Dgcrypt=disabled ;;
    --enable-gettext) printf "%s" -Dgettext=enabled ;;
    --disable-gettext) printf "%s" -Dgettext=disabled ;;
    --enable-gio) printf "%s" -Dgio=enabled ;;
    --disable-gio) printf "%s" -Dgio=disabled ;;
    --enable-glusterfs) printf "%s" -Dglusterfs=enabled ;;
    --disable-glusterfs) printf "%s" -Dglusterfs=disabled ;;
    --enable-gnutls) printf "%s" -Dgnutls=enabled ;;
    --disable-gnutls) printf "%s" -Dgnutls=disabled ;;
    --enable-gnutls-bug1717-workaround) printf "%s" -Dgnutls-bug1717-workaround=enabled ;;
    --disable-gnutls-bug1717-workaround) printf "%s" -Dgnutls-bug1717-workaround=disabled ;;
    --enable-gtk) printf "%s" -Dgtk=enabled ;;
    --disable-gtk) printf "%s" -Dgtk=disabled ;;
    --enable-gtk-clipboard) printf "%s" -Dgtk_clipboard=enabled ;;
    --disable-gtk-clipboard) printf "%s" -Dgtk_clipboard=disabled ;;
    --enable-guest-agent) printf "%s" -Dguest_agent=enabled ;;
    --disable-guest-agent) printf "%s" -Dguest_agent=disabled ;;
    --enable-guest-agent-msi) printf "%s" -Dguest_agent_msi=enabled ;;
    --disable-guest-agent-msi) printf "%s" -Dguest_agent_msi=disabled ;;
    --enable-hexagon-idef-parser) printf "%s" -Dhexagon_idef_parser=true ;;
    --disable-hexagon-idef-parser) printf "%s" -Dhexagon_idef_parser=false ;;
    --enable-hv-balloon) printf "%s" -Dhv_balloon=enabled ;;
    --disable-hv-balloon) printf "%s" -Dhv_balloon=disabled ;;
    --enable-hvf) printf "%s" -Dhvf=enabled ;;
    --disable-hvf) printf "%s" -Dhvf=disabled ;;
    --iasl=*) quote_sh "-Diasl=$2" ;;
    --enable-iconv) printf "%s" -Diconv=enabled ;;
    --disable-iconv) printf "%s" -Diconv=disabled ;;
    --enable-igvm) printf "%s" -Digvm=enabled ;;
    --disable-igvm) printf "%s" -Digvm=disabled ;;
    --includedir=*) quote_sh "-Dincludedir=$2" ;;
    --enable-install-blobs) printf "%s" -Dinstall_blobs=true ;;
    --disable-install-blobs) printf "%s" -Dinstall_blobs=false ;;
    --interp-prefix=*) quote_sh "-Dinterp_prefix=$2" ;;
    --enable-jack) printf "%s" -Djack=enabled ;;
    --disable-jack) printf "%s" -Djack=disabled ;;
    --enable-keyring) printf "%s" -Dkeyring=enabled ;;
    --disable-keyring) printf "%s" -Dkeyring=disabled ;;
    --enable-kvm) printf "%s" -Dkvm=enabled ;;
    --disable-kvm) printf "%s" -Dkvm=disabled ;;
    --enable-l2tpv3) printf "%s" -Dl2tpv3=enabled ;;
    --disable-l2tpv3) printf "%s" -Dl2tpv3=disabled ;;
    --enable-libcbor) printf "%s" -Dlibcbor=enabled ;;
    --disable-libcbor) printf "%s" -Dlibcbor=disabled ;;
    --enable-libdaxctl) printf "%s" -Dlibdaxctl=enabled ;;
    --disable-libdaxctl) printf "%s" -Dlibdaxctl=disabled ;;
    --libdir=*) quote_sh "-Dlibdir=$2" ;;
    --enable-libdw) printf "%s" -Dlibdw=enabled ;;
    --disable-libdw) printf "%s" -Dlibdw=disabled ;;
    --libexecdir=*) quote_sh "-Dlibexecdir=$2" ;;
    --enable-libiscsi) printf "%s" -Dlibiscsi=enabled ;;
    --disable-libiscsi) printf "%s" -Dlibiscsi=disabled ;;
    --enable-libkeyutils) printf "%s" -Dlibkeyutils=enabled ;;
    --disable-libkeyutils) printf "%s" -Dlibkeyutils=disabled ;;
    --enable-libnfs) printf "%s" -Dlibnfs=enabled ;;
    --disable-libnfs) printf "%s" -Dlibnfs=disabled ;;
    --enable-libpmem) printf "%s" -Dlibpmem=enabled ;;
    --disable-libpmem) printf "%s" -Dlibpmem=disabled ;;
    --enable-libssh) printf "%s" -Dlibssh=enabled ;;
    --disable-libssh) printf "%s" -Dlibssh=disabled ;;
    --enable-libudev) printf "%s" -Dlibudev=enabled ;;
    --disable-libudev) printf "%s" -Dlibudev=disabled ;;
    --enable-libusb) printf "%s" -Dlibusb=enabled ;;
    --disable-libusb) printf "%s" -Dlibusb=disabled ;;
    --enable-libvduse) printf "%s" -Dlibvduse=enabled ;;
    --disable-libvduse) printf "%s" -Dlibvduse=disabled ;;
    --enable-linux-aio) printf "%s" -Dlinux_aio=enabled ;;
    --disable-linux-aio) printf "%s" -Dlinux_aio=disabled ;;
    --enable-linux-io-uring) printf "%s" -Dlinux_io_uring=enabled ;;
    --disable-linux-io-uring) printf "%s" -Dlinux_io_uring=disabled ;;
    --localedir=*) quote_sh "-Dlocaledir=$2" ;;
    --localstatedir=*) quote_sh "-Dlocalstatedir=$2" ;;
    --enable-lzfse) printf "%s" -Dlzfse=enabled ;;
    --disable-lzfse) printf "%s" -Dlzfse=disabled ;;
    --enable-lzo) printf "%s" -Dlzo=enabled ;;
    --disable-lzo) printf "%s" -Dlzo=disabled ;;
    --enable-malloc=*) quote_sh "-Dmalloc=$2" ;;
    --enable-malloc-trim) printf "%s" -Dmalloc_trim=enabled ;;
    --disable-malloc-trim) printf "%s" -Dmalloc_trim=disabled ;;
    --mandir=*) quote_sh "-Dmandir=$2" ;;
    --enable-membarrier) printf "%s" -Dmembarrier=enabled ;;
    --disable-membarrier) printf "%s" -Dmembarrier=disabled ;;
    --enable-module-upgrades) printf "%s" -Dmodule_upgrades=true ;;
    --disable-module-upgrades) printf "%s" -Dmodule_upgrades=false ;;
    --enable-modules) printf "%s" -Dmodules=enabled ;;
    --disable-modules) printf "%s" -Dmodules=disabled ;;
    --enable-mpath) printf "%s" -Dmpath=enabled ;;
    --disable-mpath) printf "%s" -Dmpath=disabled ;;
    --enable-mshv) printf "%s" -Dmshv=enabled ;;
    --disable-mshv) printf "%s" -Dmshv=disabled ;;
    --enable-multiprocess) printf "%s" -Dmultiprocess=enabled ;;
    --disable-multiprocess) printf "%s" -Dmultiprocess=disabled ;;
    --enable-netmap) printf "%s" -Dnetmap=enabled ;;
    --disable-netmap) printf "%s" -Dnetmap=disabled ;;
    --enable-nettle) printf "%s" -Dnettle=enabled ;;
    --disable-nettle) printf "%s" -Dnettle=disabled ;;
    --enable-numa) printf "%s" -Dnuma=enabled ;;
    --disable-numa) printf "%s" -Dnuma=disabled ;;
    --enable-nvmm) printf "%s" -Dnvmm=enabled ;;
    --disable-nvmm) printf "%s" -Dnvmm=disabled ;;
    --enable-opengl) printf "%s" -Dopengl=enabled ;;
    --disable-opengl) printf "%s" -Dopengl=disabled ;;
    --enable-oss) printf "%s" -Doss=enabled ;;
    --disable-oss) printf "%s" -Doss=disabled ;;
    --enable-pa) printf "%s" -Dpa=enabled ;;
    --disable-pa) printf "%s" -Dpa=disabled ;;
    --enable-parallels) printf "%s" -Dparallels=enabled ;;
    --disable-parallels) printf "%s" -Dparallels=disabled ;;
    --enable-passt) printf "%s" -Dpasst=enabled ;;
    --disable-passt) printf "%s" -Dpasst=disabled ;;
    --enable-pipewire) printf "%s" -Dpipewire=enabled ;;
    --disable-pipewire) printf "%s" -Dpipewire=disabled ;;
    --enable-pixman) printf "%s" -Dpixman=enabled ;;
    --disable-pixman) printf "%s" -Dpixman=disabled ;;
    --with-pkgversion=*) quote_sh "-Dpkgversion=$2" ;;
    --enable-plugins) printf "%s" -Dplugins=true ;;
    --disable-plugins) printf "%s" -Dplugins=false ;;
    --enable-png) printf "%s" -Dpng=enabled ;;
    --disable-png) printf "%s" -Dpng=disabled ;;
    --prefix=*) quote_sh "-Dprefix=$2" ;;
    --enable-pvg) printf "%s" -Dpvg=enabled ;;
    --disable-pvg) printf "%s" -Dpvg=disabled ;;
    --enable-qatzip) printf "%s" -Dqatzip=enabled ;;
    --disable-qatzip) printf "%s" -Dqatzip=disabled ;;
    --enable-qcow1) printf "%s" -Dqcow1=enabled ;;
    --disable-qcow1) printf "%s" -Dqcow1=disabled ;;
    --enable-qed) printf "%s" -Dqed=enabled ;;
    --disable-qed) printf "%s" -Dqed=disabled ;;
    --firmwarepath=*) quote_sh "-Dqemu_firmwarepath=$(meson_option_build_array $2)" ;;
    --qemu-ga-distro=*) quote_sh "-Dqemu_ga_distro=$2" ;;
    --qemu-ga-manufacturer=*) quote_sh "-Dqemu_ga_manufacturer=$2" ;;
    --qemu-ga-version=*) quote_sh "-Dqemu_ga_version=$2" ;;
    --with-suffix=*) quote_sh "-Dqemu_suffix=$2" ;;
    --enable-qga-vss) printf "%s" -Dqga_vss=enabled ;;
    --disable-qga-vss) printf "%s" -Dqga_vss=disabled ;;
    --enable-qom-cast-debug) printf "%s" -Dqom_cast_debug=true ;;
    --disable-qom-cast-debug) printf "%s" -Dqom_cast_debug=false ;;
    --enable-qpl) printf "%s" -Dqpl=enabled ;;
    --disable-qpl) printf "%s" -Dqpl=disabled ;;
    --enable-rbd) printf "%s" -Drbd=enabled ;;
    --disable-rbd) printf "%s" -Drbd=disabled ;;
    --enable-rdma) printf "%s" -Drdma=enabled ;;
    --disable-rdma) printf "%s" -Drdma=disabled ;;
    --enable-relocatable) printf "%s" -Drelocatable=true ;;
    --disable-relocatable) printf "%s" -Drelocatable=false ;;
    --enable-replication) printf "%s" -Dreplication=enabled ;;
    --disable-replication) printf "%s" -Dreplication=disabled ;;
    --enable-rng-none) printf "%s" -Drng_none=true ;;
    --disable-rng-none) printf "%s" -Drng_none=false ;;
    --rtsig-map=*) quote_sh "-Drtsig_map=$2" ;;
    --enable-rust) printf "%s" -Drust=enabled ;;
    --disable-rust) printf "%s" -Drust=disabled ;;
    --enable-rutabaga-gfx) printf "%s" -Drutabaga_gfx=enabled ;;
    --disable-rutabaga-gfx) printf "%s" -Drutabaga_gfx=disabled ;;
    --enable-safe-stack) printf "%s" -Dsafe_stack=true ;;
    --disable-safe-stack) printf "%s" -Dsafe_stack=false ;;
    --enable-sdl) printf "%s" -Dsdl=enabled ;;
    --disable-sdl) printf "%s" -Dsdl=disabled ;;
    --enable-sdl-image) printf "%s" -Dsdl_image=enabled ;;
    --disable-sdl-image) printf "%s" -Dsdl_image=disabled ;;
    --enable-seccomp) printf "%s" -Dseccomp=enabled ;;
    --disable-seccomp) printf "%s" -Dseccomp=disabled ;;
    --enable-selinux) printf "%s" -Dselinux=enabled ;;
    --disable-selinux) printf "%s" -Dselinux=disabled ;;
    --enable-slirp) printf "%s" -Dslirp=enabled ;;
    --disable-slirp) printf "%s" -Dslirp=disabled ;;
    --enable-slirp-smbd) printf "%s" -Dslirp_smbd=enabled ;;
    --disable-slirp-smbd) printf "%s" -Dslirp_smbd=disabled ;;
    --enable-smartcard) printf "%s" -Dsmartcard=enabled ;;
    --disable-smartcard) printf "%s" -Dsmartcard=disabled ;;
    --smbd=*) quote_sh "-Dsmbd=$2" ;;
    --enable-snappy) printf "%s" -Dsnappy=enabled ;;
    --disable-snappy) printf "%s" -Dsnappy=disabled ;;
    --enable-sndio) printf "%s" -Dsndio=enabled ;;
    --disable-sndio) printf "%s" -Dsndio=disabled ;;
    --enable-sparse) printf "%s" -Dsparse=enabled ;;
    --disable-sparse) printf "%s" -Dsparse=disabled ;;
    --enable-spice) printf "%s" -Dspice=enabled ;;
    --disable-spice) printf "%s" -Dspice=disabled ;;
    --enable-spice-protocol) printf "%s" -Dspice_protocol=enabled ;;
    --disable-spice-protocol) printf "%s" -Dspice_protocol=disabled ;;
    --enable-stack-protector) printf "%s" -Dstack_protector=enabled ;;
    --disable-stack-protector) printf "%s" -Dstack_protector=disabled ;;
    --enable-strict-rust-lints) printf "%s" -Dstrict_rust_lints=true ;;
    --disable-strict-rust-lints) printf "%s" -Dstrict_rust_lints=false ;;
    --enable-strip) printf "%s" -Dstrip=true ;;
    --disable-strip) printf "%s" -Dstrip=false ;;
    --sysconfdir=*) quote_sh "-Dsysconfdir=$2" ;;
    --enable-tcg) printf "%s" -Dtcg=enabled ;;
    --disable-tcg) printf "%s" -Dtcg=disabled ;;
    --enable-tcg-interpreter) printf "%s" -Dtcg_interpreter=true ;;
    --disable-tcg-interpreter) printf "%s" -Dtcg_interpreter=false ;;
    --tls-priority=*) quote_sh "-Dtls_priority=$2" ;;
    --enable-tools) printf "%s" -Dtools=enabled ;;
    --disable-tools) printf "%s" -Dtools=disabled ;;
    --enable-tpm) printf "%s" -Dtpm=enabled ;;
    --disable-tpm) printf "%s" -Dtpm=disabled ;;
    --enable-trace-backends=*) quote_sh "-Dtrace_backends=$2" ;;
    --with-trace-file=*) quote_sh "-Dtrace_file=$2" ;;
    --enable-tsan) printf "%s" -Dtsan=true ;;
    --disable-tsan) printf "%s" -Dtsan=false ;;
    --enable-u2f) printf "%s" -Du2f=enabled ;;
    --disable-u2f) printf "%s" -Du2f=disabled ;;
    --enable-uadk) printf "%s" -Duadk=enabled ;;
    --disable-uadk) printf "%s" -Duadk=disabled ;;
    --enable-ubsan) printf "%s" -Dubsan=true ;;
    --disable-ubsan) printf "%s" -Dubsan=false ;;
    --enable-usb-redir) printf "%s" -Dusb_redir=enabled ;;
    --disable-usb-redir) printf "%s" -Dusb_redir=disabled ;;
    --enable-valgrind) printf "%s" -Dvalgrind=enabled ;;
    --disable-valgrind) printf "%s" -Dvalgrind=disabled ;;
    --enable-vde) printf "%s" -Dvde=enabled ;;
    --disable-vde) printf "%s" -Dvde=disabled ;;
    --enable-vdi) printf "%s" -Dvdi=enabled ;;
    --disable-vdi) printf "%s" -Dvdi=disabled ;;
    --enable-vduse-blk-export) printf "%s" -Dvduse_blk_export=enabled ;;
    --disable-vduse-blk-export) printf "%s" -Dvduse_blk_export=disabled ;;
    --enable-vfio-user-server) printf "%s" -Dvfio_user_server=enabled ;;
    --disable-vfio-user-server) printf "%s" -Dvfio_user_server=disabled ;;
    --enable-vhdx) printf "%s" -Dvhdx=enabled ;;
    --disable-vhdx) printf "%s" -Dvhdx=disabled ;;
    --enable-vhost-crypto) printf "%s" -Dvhost_crypto=enabled ;;
    --disable-vhost-crypto) printf "%s" -Dvhost_crypto=disabled ;;
    --enable-vhost-kernel) printf "%s" -Dvhost_kernel=enabled ;;
    --disable-vhost-kernel) printf "%s" -Dvhost_kernel=disabled ;;
    --enable-vhost-net) printf "%s" -Dvhost_net=enabled ;;
    --disable-vhost-net) printf "%s" -Dvhost_net=disabled ;;
    --enable-vhost-user) printf "%s" -Dvhost_user=enabled ;;
    --disable-vhost-user) printf "%s" -Dvhost_user=disabled ;;
    --enable-vhost-user-blk-server) printf "%s" -Dvhost_user_blk_server=enabled ;;
    --disable-vhost-user-blk-server) printf "%s" -Dvhost_user_blk_server=disabled ;;
    --enable-vhost-vdpa) printf "%s" -Dvhost_vdpa=enabled ;;
    --disable-vhost-vdpa) printf "%s" -Dvhost_vdpa=disabled ;;
    --enable-virglrenderer) printf "%s" -Dvirglrenderer=enabled ;;
    --disable-virglrenderer) printf "%s" -Dvirglrenderer=disabled ;;
    --enable-virtfs) printf "%s" -Dvirtfs=enabled ;;
    --disable-virtfs) printf "%s" -Dvirtfs=disabled ;;
    --enable-vmdk) printf "%s" -Dvmdk=enabled ;;
    --disable-vmdk) printf "%s" -Dvmdk=disabled ;;
    --enable-vmnet) printf "%s" -Dvmnet=enabled ;;
    --disable-vmnet) printf "%s" -Dvmnet=disabled ;;
    --enable-vnc) printf "%s" -Dvnc=enabled ;;
    --disable-vnc) printf "%s" -Dvnc=disabled ;;
    --enable-vnc-jpeg) printf "%s" -Dvnc_jpeg=enabled ;;
    --disable-vnc-jpeg) printf "%s" -Dvnc_jpeg=disabled ;;
    --enable-vnc-sasl) printf "%s" -Dvnc_sasl=enabled ;;
    --disable-vnc-sasl) printf "%s" -Dvnc_sasl=disabled ;;
    --enable-vpc) printf "%s" -Dvpc=enabled ;;
    --disable-vpc) printf "%s" -Dvpc=disabled ;;
    --enable-vte) printf "%s" -Dvte=enabled ;;
    --disable-vte) printf "%s" -Dvte=disabled ;;
    --enable-vvfat) printf "%s" -Dvvfat=enabled ;;
    --disable-vvfat) printf "%s" -Dvvfat=disabled ;;
    --enable-werror) printf "%s" -Dwerror=true ;;
    --disable-werror) printf "%s" -Dwerror=false ;;
    --enable-whpx) printf "%s" -Dwhpx=enabled ;;
    --disable-whpx) printf "%s" -Dwhpx=disabled ;;
    --x86-version=*) quote_sh "-Dx86_version=$2" ;;
    --enable-xen) printf "%s" -Dxen=enabled ;;
    --disable-xen) printf "%s" -Dxen=disabled ;;
    --enable-xen-pci-passthrough) printf "%s" -Dxen_pci_passthrough=enabled ;;
    --disable-xen-pci-passthrough) printf "%s" -Dxen_pci_passthrough=disabled ;;
    --enable-xkbcommon) printf "%s" -Dxkbcommon=enabled ;;
    --disable-xkbcommon) printf "%s" -Dxkbcommon=disabled ;;
    --enable-zstd) printf "%s" -Dzstd=enabled ;;
    --disable-zstd) printf "%s" -Dzstd=disabled ;;
    *) return 1 ;;
  esac
}
