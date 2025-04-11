// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacks FFA_SUCCESS response of the 32-bit FFA_NOTIFICATION_INFO_GET variant.

#![no_main]

use arm_ffa::{SuccessArgs, SuccessArgsNotificationInfoGet32};
use libfuzzer_sys::fuzz_target;
use zerocopy::transmute;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    let regs_in_bytes: [u8; 24] = (data[0..24]).try_into().unwrap();
    let regs_in: [u32; 6] = transmute!(regs_in_bytes);

    let args_in = SuccessArgs::Args32(regs_in);

    if let Ok(info_in) = SuccessArgsNotificationInfoGet32::try_from(args_in) {
        let mut info_out = SuccessArgsNotificationInfoGet32::default();

        for (endpoint, list) in info_in.iter() {
            if info_out.add_list(endpoint, list).is_err() {
                return;
            }
        }

        match SuccessArgs::from(info_out) {
            SuccessArgs::Args32(regs_out) => {
                for (reg_in, reg_out) in regs_in.iter().zip(regs_out) {
                    if *reg_in & reg_out != reg_out {
                        panic!("Register mismatch");
                    }
                }
            }
            _ => panic!("Invalid success variant"),
        }
    }
});
