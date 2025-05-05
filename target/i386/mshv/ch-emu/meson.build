rust_ch_emulator_ss = ss.source_set()
target_dir = meson.current_build_dir()
cargo_config = meson.current_source_dir() + '/Cargo.toml'

debug_build= get_option('debug')
cargo_profile = debug_build ? 'debug' : 'release'
output_dir = target_dir + '/' + cargo_profile
lib_path = output_dir + '/libch_emulator.a'
hdr_path = output_dir + '/ch-emulator.h'
build_cmd = debug_build ? 'cargo build' : 'cargo build --release'

cargo_args = ['cargo', 'build', '--manifest-path', cargo_config, '--target-dir',
              target_dir]

if not debug_build
  cargo_args += '--release'
endif

build_ch_emulator = custom_target('libch-emulator-build',
  command: cargo_args,
  output: cargo_profile,  # This is the expected output from cargo
  depend_files: ['src/lib.rs'],  # Dependencies for rebuild (e.g., source files)
)

libch_emulator_rs = custom_target('libch-emulator',
  command : ['cp', lib_path, target_dir + '/libch_emulator.a'],
  output : 'libch_emulator.a',
  depends : [build_ch_emulator]
)

ch_emulator_generated_h = custom_target('rust_to_c_header',
  command : ['cp', hdr_path, target_dir + '/../../../../ch-emulator.h'],
  output : 'ch-emulator.h',
  depends : [build_ch_emulator]
)
genh += ch_emulator_generated_h

rust_ch_emulator_ss.add(declare_dependency(
  link_whole: [libch_emulator_rs],
))

specific_ss.add_all(rust_ch_emulator_ss)
