// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory relinquish descriptors from the test data.

#![no_main]

use arm_ffa::memory_management::MemRelinquishDesc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((desc, iterator)) = MemRelinquishDesc::unpack(data) {
        let mut buf = [0; 4096];
        let mut endpoints = Vec::new();

        for endpoint in iterator {
            endpoints.push(endpoint);
        }

        let _len = desc.pack(&endpoints, &mut buf);
    }
});
