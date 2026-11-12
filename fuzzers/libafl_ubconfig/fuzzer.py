# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""unibench's forkserver_libafl, in-process and without AutoTokens. Built as
libafl_stats builds; run as unibench runs it: -t 5000, no dictionary, no
jemalloc."""
import os
import subprocess
import threading
from pathlib import Path

from fuzzers import utils
from fuzzers.libafl_stats import fuzzer as libafl_stats_fuzzer

LIBAFL = '/libafl-ubconfig'


def get_stats(output_corpus, fuzzer_log):
    """Gets fuzzer stats for LibAFL."""
    return libafl_stats_fuzzer.get_stats(output_corpus, fuzzer_log)


def build():
    """Build benchmark."""
    new_env = os.environ.copy()
    new_env['CC'] = (f'{LIBAFL}/fuzzers/fuzzbench/target/release-fuzzbench/'
                     'libafl_cc')
    new_env['CXX'] = (f'{LIBAFL}/fuzzers/fuzzbench/target/release-fuzzbench/'
                      'libafl_cxx')

    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)

    new_env['FUZZER_LIB'] = f'{LIBAFL}/stub_rt.a'
    utils.build_benchmark(new_env)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    libafl_stats_fuzzer.prepare_fuzz_environment(input_corpus)

    # unibench's forkserver_libafl run.sh: -t 5000 -o OUTPUT ... SEED_DIR
    command = [target_binary, '-t', '5000', '-o', output_corpus, input_corpus]
    print(command)

    # Dry run: the fuzzer writes queue/signal/dryrun_finish, as libafl_stats's
    dry_run_opt_in_path, dry_run_sentinel_path = \
        libafl_stats_fuzzer._get_dry_run_paths()  # pylint: disable=protected-access
    Path(dry_run_opt_in_path).touch()
    watcher_stop = threading.Event()
    watcher = threading.Thread(
        target=libafl_stats_fuzzer._watch_libafl_dry_run,  # pylint: disable=protected-access
        args=(output_corpus, dry_run_sentinel_path, watcher_stop),
        daemon=True,
    )
    watcher.start()

    try:
        subprocess.check_call(command, cwd=os.environ['OUT'])
    finally:
        watcher_stop.set()
        watcher.join(timeout=5)
