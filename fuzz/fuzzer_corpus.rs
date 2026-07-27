// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

use arm_ffa::{
    FfaError, FuncId, Interface, Version,
    boot_info::{
        BootInfo, BootInfoContents, BootInfoImpdefId, BootInfoName, BootInfoStdId, BootInfoType,
    },
    interface_args::{
        ConsoleLogChars, DirectMsg2Args, DirectMsgArgs, Feature, FeatureId, LogChars, MemAddr,
        MemOpBuf, MsgSend2Flags, MsgWaitFlags, RxTxAddr, SecondaryEpRegisterAddr, SuccessArgs,
        SuccessArgsFeatures, SuccessArgsIdGet, SuccessArgsSpmIdGet, TargetInfo, VersionFlags,
        VersionQueryType, VmAvailabilityStatus, WarmBootType,
    },
    memory_management::{
        Cacheability, ConstituentMemRegion, DataAccessPerm, DataAccessPermGetSet,
        DeviceMemAttributes, Handle, InstructionAccessPermGetSet, InstuctionAccessPerm,
        MemAccessPerm, MemPermissionsGetSet, MemReclaimFlags, MemRegionAttributes,
        MemRegionSecurity, MemRelinquishDesc, MemTransactionDesc, MemTransactionFlags, MemType,
        Shareability, SuccessArgsMemOp, SuccessArgsMemPermGet,
    },
    notification::{
        NotificationBindFlags, NotificationGetFlags, NotificationSetFlags,
        SuccessArgsNotificationGet, SuccessArgsNotificationInfoGet32,
        SuccessArgsNotificationInfoGet64,
    },
    partition_info::{
        PartitionIdType, PartitionInfo, PartitionInfoGetFlags, PartitionProperties,
        SuccessArgsPartitionInfoGet, SuccessArgsPartitionInfoGetRegs,
    },
};
use std::path::PathBuf;
use uuid::uuid;
use zerocopy::transmute_ref;

/// Creates a closure that can write sequentially numbered corpus files in the provided fuzz
/// target's corpus directory.
fn make_corpus_writer(target: &str) -> impl FnMut(&[u8]) {
    let mut path = PathBuf::new();
    path.push(env!("CARGO_MANIFEST_DIR"));
    path.push("fuzz");
    path.push("corpus");
    path.push(target);
    std::fs::create_dir_all(&path).expect("Failed to create corpus dir");
    let mut index = 0;
    move |data| {
        let mut path = path.clone();
        path.push(format!("{}_{:02}.bin", target, index));
        index += 1;
        std::fs::write(path, data).expect("Failed to write corpus file");
    }
}

/// Generates seed corpus for the `boot_info` fuzz target.
#[allow(clippy::cloned_ref_to_slice_refs)]
fn boot_info() {
    let content_buf = [1, 2, 3, 4, 5, 6, 7, 8];

    let boot_info0 = BootInfo {
        name: BootInfoName::NullTermString(c"boot_info_test"),
        r#type: BootInfoType::Std(BootInfoStdId::Fdt),
        contents: BootInfoContents::Buffer {
            content_buf: &content_buf,
        },
    };

    let boot_info1 = BootInfo {
        name: BootInfoName::Uuid(uuid!("4cd5bd51-2e04-47e1-8981-3510b83e20ce")),
        r#type: BootInfoType::Impdef(BootInfoImpdefId(0x12)),
        contents: BootInfoContents::Value {
            val: 0x1234_5678,
            len: 4,
        },
    };

    let mut writer = make_corpus_writer("boot_info");
    let mut write_boot_info = |descriptors: &[BootInfo]| {
        let mut buf = [0u8; 1024];
        BootInfo::pack(descriptors, &mut buf, None);
        writer(&buf);
    };

    write_boot_info(&[boot_info0.clone()]);
    write_boot_info(&[boot_info1.clone()]);
    write_boot_info(&[boot_info0.clone(), boot_info0.clone()]);
    write_boot_info(&[boot_info0.clone(), boot_info1.clone()]);
    write_boot_info(&[boot_info1.clone(), boot_info1.clone()]);
    write_boot_info(&[boot_info1.clone(), boot_info0.clone()]);
    write_boot_info(&[boot_info0.clone(), boot_info0.clone(), boot_info1.clone()]);
}

/// Generates seed corpus for the `interface` fuzz target.
fn interface() {
    let target_info = TargetInfo {
        endpoint_id: 0x8001,
        vcpu_id: 0x1234,
    };
    let version = Version(1, 2);
    let src_id = 0x1234;
    let dst_id = 0x5678;
    let sender_id = 0x1234;
    let receiver_id = 0x5678;
    let uuid = uuid!("4cd5bd51-2e04-47e1-8981-3510b83e20ce");
    let handle = Handle(0x0123_4567_89ab_cdef);
    let total_len = 0x89ab_cdef;
    let frag_len = 0x0123_4567;
    let mut log_chars_32 = LogChars::default();
    log_chars_32.push(&[0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]);
    let mut log_chars_64 = LogChars::default();
    log_chars_64.push(&[0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]);

    let interfaces = [
        Interface::Error {
            target_info,
            error_code: FfaError::Denied,
            error_arg: 0x4567_89ab,
            is_32bit: true,
        },
        Interface::Error {
            target_info,
            error_code: FfaError::NoMemory,
            error_arg: 0x4567_89ab,
            is_32bit: false,
        },
        Interface::Success {
            target_info,
            args: SuccessArgs::Args32([0, 1, 2, 3, 4, 5]),
        },
        Interface::Success {
            target_info,
            args: SuccessArgs::Args64([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        },
        Interface::Interrupt {
            target_info,
            interrupt_id: 0x1234_5678,
            is_32bit: true,
        },
        Interface::Interrupt {
            target_info,
            interrupt_id: 0x1234_5678,
            is_32bit: false,
        },
        Interface::Version {
            input_version: version,
            flags: VersionFlags {
                query_type: VersionQueryType::QueryCompatibility,
            },
        },
        // NOTE: Interface::VersionOut has no function ID, roundtrip is not possible
        Interface::Features {
            feat_id: Feature::FuncId(FuncId::MemDonate64),
            input_properties: 0xabcd_ef01,
        },
        Interface::Features {
            feat_id: Feature::FeatureId(FeatureId::ManagedExitInterrupt),
            input_properties: 0xabcd_ef01,
        },
        Interface::RxAcquire { vm_id: 0x1234 },
        Interface::RxRelease { vm_id: 0x1234 },
        Interface::RxTxMap {
            addr: RxTxAddr::Addr32 {
                rx: 0x1234_5678,
                tx: 0x9abc_def0,
            },
            page_cnt: 16,
        },
        Interface::RxTxMap {
            addr: RxTxAddr::Addr64 {
                rx: 0x1234_5678_9abc_def0,
                tx: 0xfedc_ba98_7654_3210,
            },
            page_cnt: 8,
        },
        Interface::RxTxUnmap { id: 0x1234 },
        Interface::PartitionInfoGet {
            uuid,
            flags: PartitionInfoGetFlags { count_only: false },
        },
        Interface::PartitionInfoGet {
            uuid,
            flags: PartitionInfoGetFlags { count_only: true },
        },
        Interface::PartitionInfoGetRegs {
            uuid,
            start_index: 0x1234,
            info_tag: 0x5678,
        },
        Interface::IdGet,
        Interface::SpmIdGet,
        Interface::MsgWait {
            flags: MsgWaitFlags {
                retain_rx_buffer: false,
            },
            is_32bit: true,
        },
        Interface::MsgWait {
            flags: MsgWaitFlags {
                retain_rx_buffer: true,
            },
            is_32bit: false,
        },
        Interface::Yield { is_32bit: false },
        Interface::Yield { is_32bit: true },
        Interface::Run {
            target_info,
            is_32bit: true,
        },
        Interface::Run {
            target_info,
            is_32bit: false,
        },
        Interface::NormalWorldResume { is_32bit: false },
        Interface::NormalWorldResume { is_32bit: true },
        Interface::SecondaryEpRegister {
            entrypoint: SecondaryEpRegisterAddr::Addr32(0x1234_5678),
        },
        Interface::SecondaryEpRegister {
            entrypoint: SecondaryEpRegisterAddr::Addr64(0x1234_5678_9abc_def0),
        },
        Interface::MsgSend2 {
            sender_vm_id: 0x1234,
            flags: MsgSend2Flags {
                delay_schedule_receiver: false,
            },
        },
        Interface::MsgSend2 {
            sender_vm_id: 0x1234,
            flags: MsgSend2Flags {
                delay_schedule_receiver: true,
            },
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::Args32([1, 2, 3, 4, 5]),
        },
        Interface::MsgSendDirectResp {
            src_id,
            dst_id,
            args: DirectMsgArgs::Args64([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::VersionReq {
                version: Version(1, 2),
                flags: VersionFlags {
                    query_type: VersionQueryType::Negotiate,
                },
            },
        },
        Interface::MsgSendDirectResp {
            src_id,
            dst_id,
            args: DirectMsgArgs::VersionResp {
                version: Some(Version(1, 2)),
            },
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::PowerPsciReq32 {
                params: [2, 3, 4, 5],
            },
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::PowerPsciReq64 {
                params: [2, 3, 4, 5],
            },
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::PowerWarmBootReq {
                boot_type: WarmBootType::ExitFromLowPower,
            },
        },
        Interface::MsgSendDirectResp {
            src_id,
            dst_id,
            args: DirectMsgArgs::PowerPsciResp { psci_status: 42 },
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::VmCreated {
                handle,
                vm_id: 1234,
            },
        },
        Interface::MsgSendDirectResp {
            src_id,
            dst_id,
            args: DirectMsgArgs::VmCreatedAck {
                sp_status: VmAvailabilityStatus::Error(FfaError::Retry),
            },
        },
        Interface::MsgSendDirectReq {
            src_id,
            dst_id,
            args: DirectMsgArgs::VmDestructed {
                handle,
                vm_id: 1234,
            },
        },
        Interface::MsgSendDirectResp {
            src_id,
            dst_id,
            args: DirectMsgArgs::VmDestructedAck {
                sp_status: VmAvailabilityStatus::Success,
            },
        },
        Interface::MsgSendDirectReq2 {
            src_id,
            dst_id,
            uuid,
            args: DirectMsg2Args([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]),
        },
        Interface::MsgSendDirectResp2 {
            src_id,
            dst_id,
            args: DirectMsg2Args([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]),
        },
        Interface::MemDonate {
            total_len,
            frag_len,
            buf: None,
        },
        Interface::MemLend {
            total_len,
            frag_len,
            buf: Some(MemOpBuf::Buf32 {
                addr: 0x1234_5678,
                page_cnt: 0x89ab_cdef,
            }),
        },
        Interface::MemShare {
            total_len,
            frag_len,
            buf: None,
        },
        Interface::MemRetrieveReq {
            total_len,
            frag_len,
            buf: Some(MemOpBuf::Buf64 {
                addr: 0x1234_5678_9abc_def0,
                page_cnt: 0x0123_4567,
            }),
        },
        Interface::MemRetrieveResp {
            total_len,
            frag_len,
        },
        Interface::MemRelinquish,
        Interface::MemReclaim {
            handle,
            flags: MemReclaimFlags {
                time_slicing: false,
                zero_memory: true,
            },
        },
        Interface::MemPermGet {
            addr: MemAddr::Addr32(0x1234_5678),
            page_cnt: 1,
        },
        Interface::MemPermGet {
            addr: MemAddr::Addr64(0x1234_5678_9abc_def0),
            page_cnt: 1,
        },
        Interface::MemPermSet {
            addr: MemAddr::Addr32(0x1234_5678),
            page_cnt: 1,
            mem_perm: MemPermissionsGetSet {
                data_access: DataAccessPermGetSet::ReadWrite,
                instr_access: InstructionAccessPermGetSet::Executable,
            },
        },
        Interface::MemPermSet {
            addr: MemAddr::Addr64(0x1234_5678_9abc_def0),
            page_cnt: 1,
            mem_perm: MemPermissionsGetSet {
                data_access: DataAccessPermGetSet::ReadOnly,
                instr_access: InstructionAccessPermGetSet::NonExecutable,
            },
        },
        Interface::MemOpPause { handle },
        Interface::MemOpResume { handle },
        Interface::MemFragRx {
            handle,
            frag_offset: 0x1234_5678,
            endpoint_id: 0xabcd,
        },
        Interface::MemFragTx {
            handle,
            frag_len: 0x1234_5678,
            endpoint_id: 0xabcd,
        },
        Interface::ConsoleLog {
            chars: ConsoleLogChars::Chars32(log_chars_32),
        },
        Interface::ConsoleLog {
            chars: ConsoleLogChars::Chars64(log_chars_64),
        },
        Interface::NotificationBitmapCreate {
            vm_id: 0x1234,
            vcpu_cnt: 0x89ab_cdef,
        },
        Interface::NotificationBitmapDestroy { vm_id: 0x1234 },
        Interface::NotificationBind {
            sender_id,
            receiver_id,
            flags: NotificationBindFlags {
                per_vcpu_notification: true,
            },
            bitmap: 0x0123_4567_89ab_cdef,
        },
        Interface::NotificationUnbind {
            sender_id,
            receiver_id,
            bitmap: 0x0123_4567_89ab_cdef,
        },
        Interface::NotificationSet {
            sender_id,
            receiver_id,
            flags: NotificationSetFlags {
                delay_schedule_receiver: true,
                vcpu_id: Some(0x8001),
            },
            bitmap: 0x0123_4567_89ab_cdef,
        },
        Interface::NotificationGet {
            vcpu_id: 0x1234,
            endpoint_id: 0x5678,
            flags: NotificationGetFlags {
                sp_bitmap_id: true,
                vm_bitmap_id: false,
                spm_bitmap_id: true,
                hyp_bitmap_id: false,
            },
        },
        Interface::NotificationInfoGet { is_32bit: false },
        Interface::NotificationInfoGet { is_32bit: true },
        Interface::El3IntrHandle,
    ];

    let mut writer = make_corpus_writer("interface");
    for interface in interfaces {
        if interface.is_32bit() {
            let mut regs = [0; 8];
            interface.to_regs(&mut regs);
            writer(transmute_ref!(&regs) as &[u8; 8 * 8]);
        }

        let mut regs = [0; 18];
        interface.to_regs(&mut regs);
        writer(transmute_ref!(&regs) as &[u8; 8 * 18]);
    }
}

/// Generates seed corpus for the `mem_relinquish_desc` fuzz target.
fn mem_relinquish() {
    let mut writer = make_corpus_writer("mem_relinquish_desc");
    let mut write_mem_relinquish_desc = |endpoints: &[u16]| {
        let desc = MemRelinquishDesc {
            handle: Handle(0x1234_5678_9abc_def0),
            flags: 0x1234_5678,
            endpoints,
        };
        let mut buf = [0u8; 1024];
        desc.pack(&mut buf);
        writer(&buf);
    };

    write_mem_relinquish_desc(&[]);
    write_mem_relinquish_desc(&[1, 1, 1, 2]);

    let endpoints: [u16; 256] = core::array::from_fn(|i| i as u16);
    write_mem_relinquish_desc(&endpoints);
}

/// Generates seed corpus for the `mem_transaction_desc` fuzz target.
fn mem_transaction() {
    let desc1 = MemTransactionDesc {
        sender_id: 1234,
        mem_region_attr: MemRegionAttributes {
            security: MemRegionSecurity::NonSecure,
            mem_type: MemType::Normal {
                cacheability: Cacheability::WriteBack,
                shareability: Shareability::Outer,
            },
        },
        flags: MemTransactionFlags(5678),
        handle: Handle(0xcafebabe),
        tag: 0xdeadbeef,
    };
    let desc2 = MemTransactionDesc {
        sender_id: 1234,
        mem_region_attr: MemRegionAttributes {
            security: MemRegionSecurity::Secure,
            mem_type: MemType::Device(DeviceMemAttributes::DevnGnRE),
        },
        flags: MemTransactionFlags(5678),
        handle: Handle(0xcafebabe),
        tag: 0xdeadbeef,
    };

    let region = ConstituentMemRegion {
        address: 0x12345678,
        page_cnt: 13,
    };

    let perm1 = MemAccessPerm {
        endpoint_id: 1234,
        instr_access: InstuctionAccessPerm::NotSpecified,
        data_access: DataAccessPerm::ReadWrite,
        flags: 42,
    };
    let perm2 = MemAccessPerm {
        endpoint_id: 1234,
        instr_access: InstuctionAccessPerm::NotExecutable,
        data_access: DataAccessPerm::ReadOnly,
        flags: 42,
    };

    let mut writer = make_corpus_writer("mem_transaction_desc");
    let mut write_mem_transaction =
        |desc: &MemTransactionDesc, regions: &[ConstituentMemRegion], perms: &[MemAccessPerm]| {
            let mut buf = [0; 1024];
            let len = desc.pack(regions, perms, &mut buf);
            writer(&buf[..len]);
        };

    for desc in [&desc1, &desc2] {
        for perm in [perm1, perm2] {
            write_mem_transaction(desc, &[region], &[perm]);
        }
    }
    write_mem_transaction(&desc1, &[region, region], &[perm2]);
    write_mem_transaction(&desc1, &[], &[perm2]);
    write_mem_transaction(&desc2, &[region, region, region], &[perm1, perm2]);
    write_mem_transaction(&desc2, &[region, region], &[]);
    write_mem_transaction(&desc2, &[region; 20], &[perm1]);
}

/// Generates seed corpus for the `partition_info` fuzz target.
fn partition_info() {
    let uuid = uuid!("4cd5bd51-2e04-47e1-8981-3510b83e20ce");

    let props1 = PartitionProperties {
        support_direct_req_recv: true,
        support_direct_req_send: true,
        support_direct_req2_recv: true,
        support_direct_req2_send: true,
        support_indirect_msg: true,
        support_notif_recv: true,
        subscribe_vm_created: true,
        subscribe_vm_destroyed: true,
        is_aarch64: true,
        support_live_activation: true,
        require_cpu_rendezvous: true,
        support_smc64_cpu_cycle_mgmt: true,
    };

    let props2 = PartitionProperties {
        support_direct_req_recv: false,
        support_direct_req_send: false,
        support_direct_req2_recv: false,
        support_direct_req2_send: false,
        support_indirect_msg: false,
        support_notif_recv: false,
        subscribe_vm_created: false,
        subscribe_vm_destroyed: false,
        is_aarch64: false,
        support_live_activation: false,
        require_cpu_rendezvous: false,
        support_smc64_cpu_cycle_mgmt: false,
    };

    let partition_infos = [
        PartitionInfo {
            protocol_uuid: Some(uuid),
            image_uuid: Some(uuid),
            partition_ffa_version: Version(1, 2),
            partition_id: 1234,
            partition_id_type: PartitionIdType::PeEndpoint {
                execution_ctx_count: 123,
            },
            props: props1,
        },
        PartitionInfo {
            protocol_uuid: None,
            image_uuid: None,
            partition_ffa_version: Version(1, 1),
            partition_id: 1234,
            partition_id_type: PartitionIdType::SepidIndep,
            props: props2,
        },
        PartitionInfo {
            protocol_uuid: Some(uuid),
            image_uuid: None,
            partition_ffa_version: Version(1, 3),
            partition_id: 1234,
            partition_id_type: PartitionIdType::SepidDep {
                proxy_endpoint_id: 5678,
            },
            props: props1,
        },
        PartitionInfo {
            protocol_uuid: None,
            image_uuid: Some(uuid),
            partition_ffa_version: Version(1, 3),
            partition_id: 1234,
            partition_id_type: PartitionIdType::Aux,
            props: props2,
        },
    ];

    let mut writer = make_corpus_writer("partition_info");
    for descriptors in partition_infos {
        let mut buf = [0; PartitionInfo::DESC_SIZE];
        PartitionInfo::pack(&[descriptors], &mut buf);
        writer(&buf);
    }
}

/// Generates seed corpus for the `success_args` fuzz target.
fn success_args() {
    let args: [SuccessArgs; _] = [
        SuccessArgsFeatures {
            properties: [1234, 5678],
        }
        .into(),
        SuccessArgsIdGet { id: 1234 }.into(),
        SuccessArgsMemOp {
            handle: Handle(1234),
        }
        .into(),
        SuccessArgsMemPermGet {
            perm: MemPermissionsGetSet {
                data_access: DataAccessPermGetSet::NoAccess,
                instr_access: InstructionAccessPermGetSet::Executable,
            },
            page_cnt: 5678,
        }
        .into(),
        SuccessArgsNotificationGet {
            sp_notifications: Some(1234),
            vm_notifications: None,
            spm_notifications: Some(5678),
            hypervisor_notifications: Some(666),
        }
        .into(),
        {
            let mut info_get32 = SuccessArgsNotificationInfoGet32::default();
            info_get32.add_list(1234, &[56, 78]).unwrap();
            info_get32.add_list(1234, &[]).unwrap();
            info_get32.into()
        },
        {
            let mut info_get64 = SuccessArgsNotificationInfoGet64::default();
            info_get64.add_list(1234, &[56, 78]).unwrap();
            info_get64.add_list(1234, &[56, 78, 90]).unwrap();
            info_get64.into()
        },
        SuccessArgsPartitionInfoGet {
            count: 1234,
            size: Some(5678),
        }
        .into(),
        SuccessArgsPartitionInfoGetRegs {
            last_index: 123,
            current_index: 456,
            info_tag: 789,
            descriptor_data: [42; 120],
        }
        .into(),
        SuccessArgsSpmIdGet { id: 1234 }.into(),
    ];

    let mut writer = make_corpus_writer("success_args");
    for arg in args {
        match arg {
            SuccessArgs::Args32(a32) => writer(transmute_ref!(&a32) as &[u8; 6 * 4]),
            SuccessArgs::Args64(a64) => writer(transmute_ref!(&a64) as &[u8; 16 * 8]),
        }
    }
}

fn main() {
    boot_info();
    interface();
    mem_relinquish();
    mem_transaction();
    partition_info();
    success_args();
}
