#!/bin/bash -xe

# llvm-cov has to match the LLVM version of Rust, using it directly from it.
LLVM_COV=~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov
TARGET_DIR=./target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/
TARGETS="boot_info_v1_1 boot_info_v1_2 interface_v1_1 interface_v1_2 mem_relinquish_desc mem_transaction_desc notification_info_get32 notification_info_get64 partition_info success_args32 success_args64"

gen_cov() {
    cargo +nightly fuzz coverage $1
    ${LLVM_COV} export ${TARGET_DIR}/$1 --format=lcov -instr-profile=fuzz/coverage/$1/coverage.profdata > ${1}_lcov.info
}

for target in ${TARGETS}; do
    gen_cov $target
done

LCOV_ARGS="-a ${TARGETS// /_lcov.info -a }_lcov.info"
lcov $LCOV_ARGS -o merged.info
lcov -e merged.info "*arm-ffa*" --rc lcov_branch_coverage=1  -o filtered.info

genhtml filtered.info --output-directory=coverage

# The generated coverage report is at coverage/index.html
