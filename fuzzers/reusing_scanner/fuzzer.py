# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Integration code for the reusing scanner.

Not a fuzzer: a trial scans its seed corpus once with taint_scan and ends.
The scan cache -- value_pool.dict, unsolved_condition and one .dtaint per
seed -- is what a reusing fuzzer later reads with -r. It is written to
  {EXPERIMENT_FILESTORE}/{EXPERIMENT}/taint_scan/{BENCHMARK}/trial-{TRIAL_ID}
and not to the output corpus, which the runner snapshots and measures.

The .dtaint keys are the seed filenames the runner hands the trial: the custom
corpus renamed to each file's sha1 (runner._clean_seed_corpus), which a later
fuzzing trial over the same corpus sees identically.

Run with trials: 1. The scan opts into the runner's dry-run protocol and never
reports it finished, so no fuzzing cycles are counted and max_cycles cannot
cut it short; max_total_time still bounds it.
"""

import os
import shutil
import subprocess
from pathlib import Path

from fuzzers import utils
# The per-benchmark uninstrumented-symbol tables found for the angora builds
# apply unchanged: same LLVM 11 DFSan, same benchmarks.
from fuzzers.angora import fuzzer as angora_fuzzer

SCANNER_BIN = '/reusing-scanner/bin'
SCANNER_TOOLS = '/reusing-scanner/tools'
ABILIST_PATH = '/tmp/reusing_scanner_abilist.txt'

# Libraries already covered by Angora's built-in abilists.
_ABILIST_SKIP = {
    'libgcc_s.so', 'libstdc++.so', 'libc.so', 'libm.so', 'libpthread.so',
    'libdl.so', 'librt.so', 'ld-linux-x86-64.so'
}


def _linked_libraries(binary):
    """Shared libraries |binary| loads at run time, from ldd."""
    result = subprocess.run(['ldd', binary],
                            capture_output=True,
                            text=True,
                            check=False)
    libs = []
    for line in result.stdout.splitlines():
        # "libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x...)"
        parts = line.split('=>')
        if len(parts) != 2:
            continue
        path = parts[1].split('(')[0].strip()
        if not path or not os.path.isfile(path):
            continue
        base = os.path.basename(path).split('.so')[0] + '.so'
        if base not in _ABILIST_SKIP:
            libs.append(path)
    return libs


def generate_abilist(fast_binary):
    """DFSan abilist for the taint build.

    Discard for every shared library the fast build actually loads -- those
    stay uninstrumented, so their symbols must not be renamed to dfs$*. Only
    the loaded ones: a system copy of a library the benchmark also builds from
    source (zlib, libxml2, ...) must not mark the instrumented copy's symbols
    uninstrumented. Then the angora tables for what links statically from
    system packages or assembly.
    """
    gen_script = os.path.join(SCANNER_TOOLS, 'gen_library_abilist.sh')
    benchmark = os.environ['BENCHMARK']
    libs = _linked_libraries(fast_binary)

    with open(ABILIST_PATH, 'w') as out_f:
        for lib in libs:
            result = subprocess.run([gen_script, lib, 'discard'],
                                    capture_output=True,
                                    text=True,
                                    timeout=60,
                                    check=False)
            out_f.write(f'# {lib}\n{result.stdout}\n')

        for abilist_path in angora_fuzzer.BENCHMARK_TO_ABILISTS.get(
                benchmark, []):
            if not abilist_path.exists():
                print(f'[reusing-scanner] WARNING: {abilist_path} listed for '
                      f'{benchmark} does not exist; skipped.')
                continue
            out_f.write(f'# {abilist_path}\n{abilist_path.read_text()}\n')

        inline = angora_fuzzer._append_inline_abilist(out_f, benchmark)  # pylint: disable=protected-access

    print(f'[reusing-scanner] abilist {ABILIST_PATH}: discard for '
          f'{len(libs)} linked libs {libs}, {inline} inline symbols')
    return ABILIST_PATH


def build():
    """Build the benchmark twice with the scanner's angora-clang: fast, then
    taint."""
    fuzz_target = utils.get_config_value('fuzz_target')
    out = os.environ['OUT']

    base_env = os.environ.copy()
    base_env['CC'] = f'{SCANNER_BIN}/angora-clang'
    base_env['CXX'] = f'{SCANNER_BIN}/angora-clang++'
    base_env['LD'] = f'{SCANNER_BIN}/angora-clang'
    # Let angora-clang manage its own flags; clear FuzzBench defaults.
    base_env['CFLAGS'] = ''
    base_env['CXXFLAGS'] = ''
    base_env['ANGORA_PASS_LOG_DIR'] = out

    # --- fast binary ---
    fast_env = base_env.copy()
    fast_env['USE_FAST'] = '1'
    fast_env['FUZZER_LIB'] = '/libfuzzer-harness-fast.a'
    print('[build] Building fast binary')
    out_before = set(os.listdir(out))
    with utils.restore_directory(os.environ['SRC']):
        utils.build_benchmark(fast_env)
    fast_binary = os.path.join(out, fuzz_target + '.fast')
    shutil.move(os.path.join(out, fuzz_target), fast_binary)

    # Remove what the first build added to $OUT so the second build.sh does
    # not trip on already-existing paths (e.g. mkdir /out/seeds/).
    for item in os.listdir(out):
        if item in out_before or item in (fuzz_target + '.fast',
                                          'cmpid_fast.txt', 'cmpid_fast.map'):
            continue
        item_path = os.path.join(out, item)
        if os.path.isdir(item_path):
            shutil.rmtree(item_path)
        else:
            os.remove(item_path)

    # --- taint binary ---
    taint_env = base_env.copy()
    taint_env['USE_TRACK'] = '1'
    taint_env['FUZZER_LIB'] = '/libfuzzer-harness-taint.a'
    taint_env['ANGORA_TAINT_RULE_LIST'] = generate_abilist(fast_binary)
    print('[build] Building taint binary')
    # The builder image's /usr/local/lib/libc++{,abi}.a conflict with the
    # DFSan-instrumented libc++ the track link brings; hide them meanwhile.
    conflicting_libs = ['/usr/local/lib/libc++.a', '/usr/local/lib/libc++abi.a']
    renamed = []
    for lib in conflicting_libs:
        if os.path.exists(lib):
            os.rename(lib, lib + '.bak')
            renamed.append(lib)
    try:
        utils.build_benchmark(taint_env)
    finally:
        for lib in renamed:
            os.rename(lib + '.bak', lib)
    shutil.move(os.path.join(out, fuzz_target),
                os.path.join(out, fuzz_target + '.taint'))
    # The pass's cmpid -> source map of the taint build, where taint_scan
    # looks for it (beside the track binary) to write the scan's
    # cmpid_map.tsv.
    shutil.move(os.path.join(out, 'cmpid_track.map'),
                os.path.join(out, fuzz_target + '.taint.cmpid.map'))

    shutil.copy(f'{SCANNER_BIN}/taint_scan', os.path.join(out, 'taint_scan'))
    shutil.copy(ABILIST_PATH, os.path.join(out, 'reusing_scanner_abilist.txt'))

    # The runner finds the target under its canonical name; fuzz() derives
    # .fast/.taint from it.
    shutil.copy(fast_binary, os.path.join(out, fuzz_target))


def _scan_output_dir():
    filestore = os.environ['EXPERIMENT_FILESTORE']
    experiment = os.environ['EXPERIMENT']
    benchmark = os.environ['BENCHMARK']
    trial_id = os.environ['TRIAL_ID']
    return Path(filestore) / experiment / 'taint_scan' / benchmark / \
        f'trial-{trial_id}'


def fuzz(input_corpus, output_corpus, target_binary):
    """Scan |input_corpus| once. |output_corpus| keeps the seeds the runner
    copied in, so the measured corpus is the scanned one."""
    del output_corpus  # The scan writes to the filestore instead.
    out = os.environ['OUT']
    scan_dir = _scan_output_dir()
    scan_dir.mkdir(parents=True, exist_ok=True)

    for name in ('cmpid_fast.txt', 'cmpid_track.txt',
                 'reusing_scanner_abilist.txt'):
        if os.path.exists(os.path.join(out, name)):
            shutil.copy(os.path.join(out, name), scan_dir / name)

    # Opt into the runner's dry-run wait and never post its sentinel: the
    # runner then counts no cycles while the scan runs, and moves straight to
    # its final sync and runner_done once this returns.
    dry_run_opt_in_path, _ = angora_fuzzer._get_dry_run_paths()  # pylint: disable=protected-access
    Path(dry_run_opt_in_path).touch()

    command = [
        os.path.join(out, 'taint_scan'),
        '-i', input_corpus,
        '-o', str(scan_dir),
        '-t', target_binary + '.taint',
        '--',
        target_binary + '.fast', '@@',
    ]  # yapf: disable
    print(f'[reusing-scanner] Seeds: {input_corpus} '
          f'({len(os.listdir(input_corpus))} files)')
    print(f'[reusing-scanner] Output: {scan_dir}')
    print(f'[reusing-scanner] Running: {" ".join(command)}')
    env = os.environ.copy()
    env['RUST_LOG'] = env.get('RUST_LOG', 'info')
    result = subprocess.run(command, env=env, check=False)
    print(f'[reusing-scanner] taint_scan exited with {result.returncode}; '
          f'{len(list(scan_dir.glob("*.dtaint")))} .dtaint written')
