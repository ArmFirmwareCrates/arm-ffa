// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks boot info descriptors from the test data then packs them as defined in FF-A v1.1.

#![no_main]

use arm_ffa::{boot_info::{BootInfo, BootInfoIterator}, Version};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let version = Version(1, 1);

    if let Ok(iterator) = BootInfoIterator::new(version, data) {
        let mut descriptors = Vec::new();
        for descriptor in iterator {
            if let Ok(descriptor) = descriptor {
                descriptors.push(descriptor);
            } else {
                return;
            }
        }

        let mut buf_out = [0; 4096];
        BootInfo::pack(version, &descriptors, &mut buf_out, None);
    }
});
