// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks boot info descriptors from the test data then packs them.

#![no_main]

use arm_ffa::boot_info::BootInfo;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = BootInfo::get_blob_size(data);

    let Ok(iterator) = BootInfo::unpack(data) else {
        return;
    };

    let descriptors: Vec<_> = iterator.filter_map(|it| it.ok()).collect();

    let mut buf_out = vec![0; data.len() * 2];
    BootInfo::pack(&descriptors, &mut buf_out, None);
});
