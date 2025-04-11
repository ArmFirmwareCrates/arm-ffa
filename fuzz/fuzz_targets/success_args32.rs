// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converts `SuccessArgs` into FF-A call specific success arguments.

#![no_main]

use arm_ffa::{
    partition_info::SuccessArgsPartitionInfoGet, NotificationGetFlags, PartitionInfoGetFlags,
    SuccessArgs, SuccessArgsFeatures, SuccessArgsIdGet, SuccessArgsNotificationGet,
    SuccessArgsSpmIdGet,
};
use libfuzzer_sys::fuzz_target;
use zerocopy::transmute;

fuzz_target!(|data: &[u8]| {
    const REG_COUNT: usize = 6;
    const SIZE: usize = core::mem::size_of::<u32>() * REG_COUNT;

    if data.len() < SIZE {
        return;
    }

    let data_bytes: [u8; SIZE] = data[0..SIZE].try_into().unwrap();
    let args = SuccessArgs::Args32(transmute!(data_bytes));

    // FFA_FEATURES
    let features = SuccessArgsFeatures::try_from(args.clone());
    if let Ok(features) = features {
        let _ = SuccessArgs::from(features);
    }

    // FFA_ID_GET
    let id = SuccessArgsIdGet::try_from(args.clone());
    if let Ok(id) = id {
        let _ = SuccessArgs::from(id);
    }

    // FFA_NOTIFICATION_GET
    let notifications = SuccessArgsNotificationGet::try_from((
        NotificationGetFlags {
            sp_bitmap_id: true,
            vm_bitmap_id: true,
            spm_bitmap_id: true,
            hyp_bitmap_id: true,
        },
        args.clone(),
    ));
    if let Ok(notifications) = notifications {
        let _ = SuccessArgs::from(notifications);
    }

    // FFA_PARTITION_INFO_GET
    let info = SuccessArgsPartitionInfoGet::try_from((
        PartitionInfoGetFlags { count_only: false },
        args.clone(),
    ));
    if let Ok(info) = info {
        let _ = SuccessArgs::from(info);
    }

    // FFA_SPM_ID_GET
    let spm_id = SuccessArgsSpmIdGet::try_from(args.clone());
    if let Ok(spm_id) = spm_id {
        let _ = SuccessArgs::from(spm_id);
    }
});
