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

# The LibAFL fuzzer unibench's forkserver_libafl arm runs, changed from
# forkserver to in-process and without the AutoTokens pass
# (libafl_ubconfig.patch). Same LibAFL commit and
# unibench patches; built in fuzzers/fuzzbench, the crate whose staticlib a
# libFuzzer-style benchmark links, with the Cargo.lock of unibench's build.

ARG parent_image

FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd AS fuzzer_builder
RUN apt-get update && \
    apt-get upgrade -yq

SHELL [ "/bin/bash", "-c" ]
# Install dependencies.
RUN apt-get update && \
    apt-get remove -y llvm-10 && \
    apt-get install -y \
        build-essential \
        lsb-release wget software-properties-common gnupg && \
    apt-get install -y wget libstdc++5 libtool-bin automake flex bison \
        libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
        apt-utils apt-transport-https ca-certificates joe curl && \
    wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 17

RUN wget https://gist.githubusercontent.com/tokatoka/26f4ba95991c6e33139999976332aa8e/raw/698ac2087d58ce5c7a6ad59adce58dbfdc32bd46/createAliases.sh && chmod u+x ./createAliases.sh && ./createAliases.sh

# Uninstall old Rust & Install the latest one.
RUN if which rustup; then rustup self uninstall -y; fi && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /rustup.sh && \
    sh /rustup.sh --default-toolchain 1.90.0 -y && \
    rm /rustup.sh

# unibench's forkserver_libafl: the same LibAFL commit and its four patches to
# fuzzers/forkserver_libafl_cc (verbatim copies from
# Reusing-unibench_build/forkserver_libafl/).
RUN git clone https://github.com/aflplusplus/LibAFL.git /libafl-ubconfig && \
    cd /libafl-ubconfig && \
    git checkout bb579e624e907b6488f019a6f0bb0634aa0f81da
COPY forkserver_libafl_baseline.patch forkserver_toml_monitor.patch \
     forkserver_libafl_dryrun.patch forkserver_libafl_sigint.patch /
RUN cd /libafl-ubconfig && \
    git apply /forkserver_libafl_baseline.patch && \
    git apply /forkserver_toml_monitor.patch && \
    git apply /forkserver_libafl_dryrun.patch && \
    git apply /forkserver_libafl_sigint.patch

# That fuzzer becomes fuzzers/fuzzbench's library, then goes in-process.
COPY libafl_ubconfig.patch Cargo.lock /
RUN cd /libafl-ubconfig && \
    cp fuzzers/forkserver_libafl_cc/src/main.rs fuzzers/fuzzbench/src/lib.rs && \
    git apply /libafl_ubconfig.patch && \
    cp /Cargo.lock fuzzers/fuzzbench/Cargo.lock

# Compile libafl, as libafl_stats does.
RUN cd /libafl-ubconfig/fuzzers/fuzzbench && \
    unset CFLAGS CXXFLAGS && \
    export LIBAFL_EDGES_MAP_SIZE_MAX=4194304 && \
    PATH="/root/.cargo/bin/:$PATH" cargo build --profile release-fuzzbench --features no_link_main

# Auxiliary weak references.
RUN cd /libafl-ubconfig/fuzzers/fuzzbench && \
    clang -c stub_rt.c && \
    ar r /libafl-ubconfig/stub_rt.a stub_rt.o


FROM $parent_image

RUN apt-get update && \
    apt-get upgrade -yq

RUN apt-get update && \
    apt-get install -y \
    file 					\
	lsb-release \
    wget \
    software-properties-common \
    gnupg \
    libz3-dev


# Get LLVM 17
RUN wget https://apt.llvm.org/llvm.sh && \
    bash llvm.sh 17

RUN wget https://gist.githubusercontent.com/tokatoka/26f4ba95991c6e33139999976332aa8e/raw/698ac2087d58ce5c7a6ad59adce58dbfdc32bd46/createAliases.sh && \
    chmod u+x ./createAliases.sh && \
    ./createAliases.sh

COPY --from=fuzzer_builder /libafl-ubconfig/ /libafl-ubconfig/
