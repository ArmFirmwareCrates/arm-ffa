#!/bin/sh

RUNS=10000000

cargo +nightly fuzz run boot_info_v1_1 -- -max_len=4096 -runs=${RUNS} &
cargo +nightly fuzz run boot_info_v1_2 -- -max_len=4096 -runs=${RUNS} &
cargo +nightly fuzz run interface_v1_1 -- -max_len=64 -runs=${RUNS} &
cargo +nightly fuzz run interface_v1_2 -- -max_len=144 -runs=${RUNS} &
cargo +nightly fuzz run mem_relinquish_desc -- -max_len=4096 -runs=${RUNS} &
cargo +nightly fuzz run mem_transaction_desc -- -max_len=4096 -runs=${RUNS} &
cargo +nightly fuzz run partition_info -- -max_len=4096 -runs=${RUNS}
