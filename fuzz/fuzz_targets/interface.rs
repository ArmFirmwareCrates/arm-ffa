// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converting from 18 registers to an `Interface` then back to 18 register as defined in v1.2 spec.
//! Check if original and the processed register values match.

#![no_main]

use arm_ffa::{
    Interface,
    interface_args::{ConsoleLogChars, LogChars},
};
use libfuzzer_sys::fuzz_target;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Checks `LogChars`' helper functions
fn test_logchars_fns<T>(chars: LogChars<T>)
where
    T: Clone + IntoBytes + FromBytes + Immutable,
{
    chars.empty();
    chars.full();
    chars.bytes();
    chars.clone().push("test".as_bytes());
}

fuzz_target!(|data: &[u8]| {
    let mut regs_in: Vec<_> = match data.as_chunks() {
        ([], _) => return,
        (chunks, []) => chunks.iter().map(|it| u64::from_ne_bytes(*it)).collect(),
        _ => return,
    };

    if regs_in.len() > 18 {
        return;
    }

    // Mask function ID to 32 bits
    regs_in[0] &= 0x0000_0000_ffff_ffff;

    // Unpack interface from registers
    let Ok(interface) = Interface::try_from(&regs_in[..]) else {
        return;
    };

    match interface {
        Interface::ConsoleLog { chars } => match chars {
            ConsoleLogChars::Chars32(chars) => test_logchars_fns(chars),
            ConsoleLogChars::Chars64(chars) => test_logchars_fns(chars),
        },
        Interface::MemPermGet { addr, .. } | Interface::MemPermSet { addr, .. } => {
            addr.address();
        }
        _ => {}
    }

    let _ver = interface.minimum_ffa_version();

    // Pack parsed interface back to registers
    let mut regs_out = [0; 18];
    interface.to_regs(&mut regs_out);

    if interface.is_32bit() {
        let mut regs_out8 = [0; 8];
        interface.to_regs(&mut regs_out8);
    }

    // Comparate the original register contents with the ones after a round of
    // unpacking-packing. Ignore bits that were set in the original call but are cleared in the
    // new set of registers. This is necessary, because unpack ignores SBZ bits but pack we set
    // them to zero.
    for (reg_in, reg_out) in regs_in.iter().zip(regs_out) {
        assert_eq!(
            reg_in & reg_out,
            reg_out,
            "Mismatching registers: {:?}",
            interface
        );
    }
});
