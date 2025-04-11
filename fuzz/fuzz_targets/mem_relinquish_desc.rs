// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory relinquish descriptors from the test data.

#![no_main]

use arm_ffa::memory_management::MemRelinquishDesc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(_desc) = MemRelinquishDesc::try_from(data) {
        // TODO: pack
    }
});
