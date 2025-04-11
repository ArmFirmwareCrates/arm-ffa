// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converting from 18 registers to an `Interface` then back to 18 register as defined in v1.2 spec.
//! Check if original and the processed register values match.

#![no_main]

use arm_ffa::{Interface, Version};
use libfuzzer_sys::fuzz_target;
use zerocopy::transmute;

fuzz_target!(|data: &[u8]| {
    const REG_COUNT: usize = 18;
    const SIZE: usize = core::mem::size_of::<u64>() * REG_COUNT;

    if data.len() < SIZE {
        return;
    }

    let version = Version(1, 2);

    let data_bytes: [u8; SIZE] = data[0..SIZE].try_into().unwrap();
    let mut regs_in: [u64; REG_COUNT] = transmute!(data_bytes);

    // Mask function ID to 32 bits
    regs_in[0] &= 0x0000_0000_ffff_ffff;

    // Unpack interface from registers
    if let Ok(interface) = Interface::from_regs(version, &regs_in) {
        // Pack parsed interface back to registers
        let mut regs_out = [0; REG_COUNT];
        interface.to_regs(version, &mut regs_out);

        // Comparate the original register contents with the ones after a round of
        // unpacking-packing. Ignore bits that were set in the original call but are cleared in the
        // new set of registers. This is necessary, because unpack ignores SBZ bits but pack we set
        // them to zero.
        for (reg_in, reg_out) in regs_in.iter().zip(regs_out) {
            if *reg_in & reg_out != reg_out {
                panic!(
                    "Register values are not matching: {:?}\n in: {:#x?}\nout{:#x?}\n",
                    interface, regs_in, regs_out
                );
            }
        }
    }
});
