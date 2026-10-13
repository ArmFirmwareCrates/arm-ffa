// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parses SPMC manifest from the test data.

#![no_main]

use arm_ffa::manifest::SpmcManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SpmcManifest::new_from_fdt(data);
});
