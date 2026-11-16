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

# The reusing scanner (lysgoup/Reusing_scanner): the same LLVM 11 Angora
# toolchain as fuzzers/angora, but what it ships is taint_scan, a one-shot
# scan of the seed corpus, instead of the Angora fuzzer.

ARG parent_image

# ---------------------------------------------------------------------------
# Stage 1: build the scanner and its angora-clang
# ---------------------------------------------------------------------------
FROM ubuntu:20.04 AS scanner_builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git build-essential wget cmake curl \
    zlib1g-dev libstdc++-9-dev \
    python-is-python3

# LLVM 11.1.0, as in fuzzers/angora
RUN wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    tar -C / -xf clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    mv /clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04 /clang+llvm && \
    rm clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz

ENV PATH="/clang+llvm/bin:$PATH"
# No trailing ":" when unset: an empty entry is the cwd, and clang would
# load the instrumented libz.so.1 a zlib build just wrote there.
ENV LD_LIBRARY_PATH="/clang+llvm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
ENV CC=clang
ENV CXX=clang++

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --no-modify-path
ENV PATH="/root/.cargo/bin:$PATH"

# Pinned: the scan output must come from a known scanner, the way the
# unibench workdirs name theirs (..._scanner-90986c8_...).
ARG SCANNER_COMMIT=5c3e6da0ba0b5b88931c51b7419d4e4601489085
RUN git clone https://github.com/lysgoup/Reusing_scanner.git /scanner_src && \
    git -C /scanner_src checkout ${SCANNER_COMMIT}

# -> /reusing-scanner/bin/{taint_scan,angora-clang,angora-clang++,pass,rules,lib}
RUN cd /scanner_src && PREFIX=/reusing-scanner/bin ./build/build.sh

# ---------------------------------------------------------------------------
# Stage 2: benchmark builder with the scanner toolchain
# ---------------------------------------------------------------------------
FROM $parent_image

ENV DEBIAN_FRONTEND=noninteractive

# angora-clang invokes this clang at benchmark compile time
COPY --from=scanner_builder /clang+llvm/ /clang+llvm/
COPY --from=scanner_builder /reusing-scanner/bin/ /reusing-scanner/bin/
# gen_library_abilist.sh, used at benchmark build time
COPY --from=scanner_builder /scanner_src/tools/ /reusing-scanner/tools/

ENV PATH="/clang+llvm/bin:/reusing-scanner/bin:$PATH"
# No trailing ":" when unset: an empty entry is the cwd, and clang would
# load the instrumented libz.so.1 a zlib build just wrote there.
ENV LD_LIBRARY_PATH="/clang+llvm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# File-input main around LLVMFuzzerTestOneInput, once per instrumentation:
# the scanner drives the fast build through a forkserver and runs the taint
# build once per seed, both with the seed as argv[1].
COPY libfuzz-harness-proxy.c /

RUN USE_FAST=1 /reusing-scanner/bin/angora-clang \
        -c /libfuzz-harness-proxy.c -o /libfuzzer-harness-fast.o && \
    ar r /libfuzzer-harness-fast.a /libfuzzer-harness-fast.o

RUN USE_TRACK=1 /reusing-scanner/bin/angora-clang \
        -c /libfuzz-harness-proxy.c -o /libfuzzer-harness-taint.o && \
    ar r /libfuzzer-harness-taint.a /libfuzzer-harness-taint.o
