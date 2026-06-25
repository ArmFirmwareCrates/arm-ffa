// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory partition info descriptors from the test data, packs them and then checks if the
//! output matches the input.

#![no_main]

use arm_ffa::partition_info::PartitionInfo;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > PartitionInfo::DESC_SIZE {
        return;
    }

    let Ok(info) = PartitionInfo::unpack(data, 1) else {
        return;
    };

    let descriptors: Vec<_> = info.filter_map(|it| it.ok()).collect();

    let mut buf_out = [0; PartitionInfo::DESC_SIZE];
    PartitionInfo::pack(&descriptors, &mut buf_out);

    for (b_in, b_out) in data.iter().zip(buf_out) {
        assert_eq!(
            b_in & b_out,
            b_out,
            "Mismatching values: {:#x?}",
            descriptors
        );
    }
});
