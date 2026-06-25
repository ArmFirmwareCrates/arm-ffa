// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converts `SuccessArgs` into FF-A call specific success arguments.

#![no_main]

use arm_ffa::{
    interface_args::{SuccessArgs, SuccessArgsFeatures, SuccessArgsIdGet, SuccessArgsSpmIdGet},
    memory_management::{SuccessArgsMemOp, SuccessArgsMemPermGet},
    notification::{
        NotificationGetFlags, SuccessArgsNotificationGet, SuccessArgsNotificationInfoGet,
        SuccessArgsNotificationInfoGet32, SuccessArgsNotificationInfoGet64,
    },
    partition_info::{
        PartitionInfoGetFlags, SuccessArgsPartitionInfoGet, SuccessArgsPartitionInfoGetRegs,
    },
};
use libfuzzer_sys::fuzz_target;
use zerocopy::transmute;

/// Checks if `SuccessArgs` was unchanged after converting to specific type then back.
fn check_roundtrip(orig: SuccessArgs, res: SuccessArgs) {
    if let (SuccessArgs::Args32(orig), SuccessArgs::Args32(res)) = (orig, res) {
        for (reg_in, reg_out) in orig.iter().zip(res) {
            assert_eq!(reg_in & reg_out, reg_out, "Mismatching registers");
        }
    } else if let (SuccessArgs::Args64(orig), SuccessArgs::Args64(res)) = (orig, res) {
        for (reg_in, reg_out) in orig.iter().zip(res) {
            assert_eq!(reg_in & reg_out, reg_out, "Mismatching registers");
        }
    } else {
        panic!("Got back different type of SuccessArgs")
    }
}

/// Checks if assembling SuccessArgsNotificationInfoGet by hand gives back the original
/// `SuccessArgs`.
fn check_notif_info_get<const N: usize>(orig: SuccessArgs, info: SuccessArgsNotificationInfoGet<N>)
where
    SuccessArgsNotificationInfoGet<N>: Into<SuccessArgs>,
{
    check_roundtrip(orig, info.into());
    let mut out = <SuccessArgsNotificationInfoGet<N>>::default();
    for (endpoint, list) in info.iter() {
        if out.add_list(endpoint, list).is_err() {
            panic!("Failed manually cloning SuccessArgsNotificationInfoGet")
        }
    }
    check_roundtrip(orig, out.into());
    if out.add_list(42, &[1, 2, 3]).is_ok() {
        let _: SuccessArgs = out.into();
    } else {
        check_roundtrip(orig, out.into());
    }
}

fuzz_target!(|data: &[u8]| {
    let args = if let Ok(data) = <[u8; 6 * 4]>::try_from(data) {
        SuccessArgs::Args32(transmute!(data))
    } else if let Ok(data) = <[u8; 16 * 8]>::try_from(data) {
        SuccessArgs::Args64(transmute!(data))
    } else {
        return;
    };

    // FFA_FEATURES
    if let Ok(features) = SuccessArgsFeatures::try_from(args) {
        check_roundtrip(args, features.into());
    }

    // FFA_ID_GET
    if let Ok(id) = SuccessArgsIdGet::try_from(args) {
        check_roundtrip(args, id.into());
    }

    // FFA_MEM_DONATE, FFA_MEM_LEND, FFA_MEM_SHARE
    if let Ok(mem_op) = SuccessArgsMemOp::try_from(args) {
        check_roundtrip(args, mem_op.into());
    }

    // FFA_MEM_PERM_GET
    if let Ok(mem_perm) = SuccessArgsMemPermGet::try_from(args) {
        check_roundtrip(args, mem_perm.into());
    }

    // FFA_NOTIFICATION_GET
    let notifications = SuccessArgsNotificationGet::try_from((
        NotificationGetFlags {
            sp_bitmap_id: true,
            vm_bitmap_id: true,
            spm_bitmap_id: true,
            hyp_bitmap_id: true,
        },
        args,
    ));
    if let Ok(notifications) = notifications {
        check_roundtrip(args, notifications.into());
    }

    // FFA_NOTIFICATION_INFO_GET_32
    if let Ok(info) = SuccessArgsNotificationInfoGet32::try_from(args) {
        check_notif_info_get(args, info);
    }

    // FFA_NOTIFICATION_INFO_GET_64
    if let Ok(info) = SuccessArgsNotificationInfoGet64::try_from(args) {
        check_notif_info_get(args, info);
    }

    // FFA_PARTITION_INFO_GET
    let part_info =
        SuccessArgsPartitionInfoGet::try_from((PartitionInfoGetFlags { count_only: false }, args));
    if let Ok(part_info) = part_info {
        check_roundtrip(args, part_info.into());
    }

    // FFA_PARTITION_INFO_GET_REGS
    if let Ok(regs) = SuccessArgsPartitionInfoGetRegs::try_from(args) {
        check_roundtrip(args, regs.into());
    }

    // FFA_SPM_ID_GET
    if let Ok(spm_id) = SuccessArgsSpmIdGet::try_from(args) {
        check_roundtrip(args, spm_id.into());
    }
});
