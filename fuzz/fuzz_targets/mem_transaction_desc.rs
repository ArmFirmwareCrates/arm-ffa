// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory descriptors from the test data then packs them.

#![no_main]

use arm_ffa::memory_management::MemTransactionDesc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((transaction, perms, regions)) = MemTransactionDesc::unpack(data) else {
        return;
    };

    // try to roundtrip as many entries as possible
    let constituents: Vec<_> = regions.map_or(vec![], |v| v.collect());
    let access_descriptors: Vec<_> = perms.filter_map(|it| it.ok()).collect();

    let mut buf = vec![0; data.len() * 3];
    let _len = transaction.pack(&constituents, &access_descriptors, &mut buf);
});
