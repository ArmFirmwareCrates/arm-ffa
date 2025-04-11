// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory partition info descriptors from the test data, packs them and then checks if the
//! output matches the input.

#![no_main]

use arm_ffa::{
    partition_info::{PartitionInfo, PartitionInfoIterator},
    Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let version = Version(1, 1);

    if let Ok(info) = PartitionInfoIterator::new(version, data, 15) {
        let mut descriptors = Vec::new();

        for descriptor in info {
            if let Ok(descriptor) = descriptor {
                descriptors.push(descriptor);
            } else {
                return;
            }
        }

        let mut buf_out = [0; 4096];
        PartitionInfo::pack(version, &descriptors, &mut buf_out, true);

        for (byte_in, byte_out) in data.iter().zip(buf_out) {
            if (*byte_in & byte_out) != byte_out {
                panic!("Mismatching values {:#x?}", descriptors);
            }
        }
    }
});
