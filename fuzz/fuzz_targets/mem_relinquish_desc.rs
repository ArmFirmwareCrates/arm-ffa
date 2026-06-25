// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks memory relinquish descriptors from the test data.

#![no_main]

use arm_ffa::memory_management::MemRelinquishDesc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(desc) = MemRelinquishDesc::unpack(data) else {
        return;
    };

    let mut buf = vec![0; data.len()];
    let _len = desc.pack(&mut buf);

    for (b_in, b_out) in data.iter().zip(buf) {
        assert_eq!(b_in & b_out, b_out, "Mismatching values: {:?}", desc);
    }
});
