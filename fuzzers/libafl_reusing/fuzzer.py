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
#
"""Integration code for LibAFL with the reusing stage (in-process).

libafl_stats plus the reusing stage. It reads the taint scan a reusing_scanner
experiment wrote over the same seed corpus, named by the experiment config's
reusing_scan_experiment:
  {EXPERIMENT_FILESTORE}/{REUSING_SCAN_EXPERIMENT}/taint_scan/{BENCHMARK}/trial-*
The .dtaint keys are the runner's sha1 seed names, which this trial sees
identically.
"""

import os
import subprocess
import threading
from pathlib import Path

from fuzzers import utils
from fuzzers.libafl_stats import fuzzer as libafl_stats_fuzzer

LIBAFL_DIR = '/libafl-reusing'
FUZZER_DIR = f'{LIBAFL_DIR}/fuzzers/reusing_fuzzbench_in_process'

# None, 'random-pos' or 'random-val'; an ablation arm is a fuzzer that
# overrides this.
ABLATION = None


def get_stats(output_corpus, fuzzer_log):
    """Gets fuzzer stats for LibAFL."""
    return libafl_stats_fuzzer.get_stats(output_corpus, fuzzer_log)


def build():
    """Build benchmark."""
    new_env = os.environ.copy()
    new_env['CC'] = f'{FUZZER_DIR}/target/release-fuzzbench/libafl_cc'
    new_env['CXX'] = f'{FUZZER_DIR}/target/release-fuzzbench/libafl_cxx'

    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)

    new_env['FUZZER_LIB'] = f'{LIBAFL_DIR}/stub_rt.a'
    utils.build_benchmark(new_env)


def get_scan_dir():
    """The one scan of this benchmark in the reusing_scan_experiment.

    Fails loudly: a trial that fuzzes without its pool is indistinguishable
    from the baseline afterwards.
    """
    scan_experiment = os.environ.get('REUSING_SCAN_EXPERIMENT')
    if not scan_experiment:
        raise RuntimeError('REUSING_SCAN_EXPERIMENT is not set; put '
                           'reusing_scan_experiment in the experiment config.')
    benchmark_dir = Path(os.environ['EXPERIMENT_FILESTORE']) / \
        scan_experiment / 'taint_scan' / os.environ['BENCHMARK']
    # Trial ids are database ids, so the scan's is not known up front; the
    # scan experiment runs one trial per benchmark.
    scans = sorted(benchmark_dir.glob('trial-*'))
    if len(scans) != 1:
        raise RuntimeError(f'Expected exactly one scan under {benchmark_dir}, '
                           f'found {[str(s) for s in scans]}.')
    if not (scans[0] / 'value_pool.dict').exists():
        raise RuntimeError(f'{scans[0]} has no value_pool.dict; the scan did '
                           'not finish.')
    return scans[0]


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    libafl_stats_fuzzer.prepare_fuzz_environment(input_corpus)
    scan_dir = get_scan_dir()

    dictionary_path = utils.get_dictionary_path(target_binary)
    command = [target_binary]
    if dictionary_path:
        command += (['-x', dictionary_path])
    command += (['-o', output_corpus, '-i', input_corpus, '-r', str(scan_dir)])
    if ABLATION:
        command += (['--reusing-ablation', ABLATION])
    # The reusing stage's periodic counters go to the logfile; keep it out of
    # the measured corpus but in the filestore, next to the runner logs.
    log_dir = Path(os.environ['EXPERIMENT_FILESTORE']) / \
        os.environ['EXPERIMENT'] / 'reusing_log' / os.environ['BENCHMARK']
    log_dir.mkdir(parents=True, exist_ok=True)
    command += (['-l', str(log_dir / f'trial-{os.environ["TRIAL_ID"]}.log')])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)

    dry_run_opt_in_path, dry_run_sentinel_path = \
        libafl_stats_fuzzer._get_dry_run_paths()  # pylint: disable=protected-access
    Path(dry_run_opt_in_path).touch()
    print(f'[DRY_RUN] LibAFL dry run opt-in marker created: '
          f'{dry_run_opt_in_path}')

    watcher_stop = threading.Event()
    watcher = threading.Thread(
        target=libafl_stats_fuzzer._watch_libafl_dry_run,  # pylint: disable=protected-access
        args=(output_corpus, dry_run_sentinel_path, watcher_stop),
        daemon=True,
    )
    watcher.start()

    try:
        subprocess.check_call(command, cwd=os.environ['OUT'], env=fuzzer_env)
    finally:
        watcher_stop.set()
        watcher.join(timeout=5)
