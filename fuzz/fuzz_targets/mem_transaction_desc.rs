// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory descriptors from the test data then packs them.

#![no_main]

use arm_ffa::memory_management::MemTransactionDesc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((transation, perms, regions)) = MemTransactionDesc::unpack(data) {
        let mut buf = [0; 4096];

        let mut access_descriptors = Vec::new();
        for perm in perms {
            if let Ok(perm) = perm {
                access_descriptors.push(perm);
            } else {
                return;
            }
        }

        let mut constituents = Vec::new();
        if let Some(regions) = regions {
            for region in regions {
                if let Ok(region) = region {
                    constituents.push(region);
                } else {
                    return;
                }
            }
        }

        let _data = transation.pack(&constituents, &access_descriptors, &mut buf);
    }
});
