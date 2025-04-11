#![no_main]

use arm_ffa::{partition_info::SuccessArgsPartitionInfoGetRegs, SuccessArgs};
use libfuzzer_sys::fuzz_target;
use zerocopy::transmute;

fuzz_target!(|data: &[u8]| {
    const REG_COUNT: usize = 16;
    const SIZE: usize = core::mem::size_of::<u64>() * REG_COUNT;

    if data.len() < SIZE {
        return;
    }

    let data_bytes: [u8; SIZE] = data[0..SIZE].try_into().unwrap();
    let args = SuccessArgs::Args64_2(transmute!(data_bytes));

    // FFA_PARTITION_INFO_GET_REGS
    let info_regs = SuccessArgsPartitionInfoGetRegs::try_from(args.clone());
    if let Ok(info_regs) = info_regs {
        let _ = SuccessArgs::from(info_regs);
    }
});
