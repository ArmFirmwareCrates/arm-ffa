// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::fmt::{self, Debug, Display, Formatter};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;
use uuid::Uuid;

pub mod boot_info;
mod ffa_v1_1;
pub mod memory_management;
pub mod partition_info;

pub const FFA_PAGE_SIZE: usize = 4096;

#[derive(PartialEq, Clone, Copy)]
pub enum Instance {
    SecurePhysical,
    SecureVirtual(u16),
}

/// FF-A v1.1, Table 12.2: Error status codes
#[derive(Clone, Copy, Debug, Eq, Error, IntoPrimitive, PartialEq, TryFromPrimitive)]
#[repr(i32)]
pub enum Error {
    #[error("Not supported")]
    NotSupported = -1,
    #[error("Invalid parameters")]
    InvalidParameters = -2,
    #[error("No memory")]
    NoMemory = -3,
    #[error("Busy")]
    Busy = -4,
    #[error("Interrupted")]
    Interrupted = -5,
    #[error("Denied")]
    Denied = -6,
    #[error("Retry")]
    Retry = -7,
    #[error("Aborted")]
    Aborted = -8,
    #[error("No data")]
    NoData = -9,
}

/// An integer couldn't be converted to a [`FuncId`] because it is not a recognised function.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Unrecognised function ID {0} for FF-A")]
pub struct UnrecognisedFunctionIdError(u32);

/// FF-A v1.1: Function IDs
#[derive(Clone, Copy, Debug, Eq, IntoPrimitive, PartialEq, TryFromPrimitive)]
#[num_enum(error_type(name = UnrecognisedFunctionIdError, constructor = UnrecognisedFunctionIdError))]
#[repr(u32)]
pub enum FuncId {
    Error = 0x84000060,
    Success32 = 0x84000061,
    Success64 = 0xc4000061,
    Interrupt = 0x84000062,
    Version = 0x84000063,
    Features = 0x84000064,
    RxAcquire = 0x84000084,
    RxRelease = 0x84000065,
    RxTxMap32 = 0x84000066,
    RxTxMap64 = 0xc4000066,
    RxTxUnmap = 0x84000067,
    PartitionInfoGet = 0x84000068,
    IdGet = 0x84000069,
    SpmIdGet = 0x84000085,
    MsgWait = 0x8400006b,
    Yield = 0x8400006c,
    Run = 0x8400006d,
    NormalWorldResume = 0x8400007c,
    MsgSend2 = 0x84000086,
    MsgSendDirectReq32 = 0x8400006f,
    MsgSendDirectReq64 = 0xc400006f,
    MsgSendDirectResp32 = 0x84000070,
    MsgSendDirectResp64 = 0xc4000070,
    MemDonate32 = 0x84000071,
    MemDonate64 = 0xc4000071,
    MemLend32 = 0x84000072,
    MemLend64 = 0xc4000072,
    MemShare32 = 0x84000073,
    MemShare64 = 0xc4000073,
    MemRetrieveReq32 = 0x84000074,
    MemRetrieveReq64 = 0xc4000074,
    MemRetrieveResp = 0x84000075,
    MemRelinquish = 0x84000076,
    MemReclaim = 0x84000077,
    MemPermGet32 = 0x84000088,
    MemPermGet64 = 0xc4000088,
    MemPermSet32 = 0x84000089,
    MemPermSet64 = 0xc4000089,
    ConsoleLog32 = 0x8400008a,
    ConsoleLog64 = 0xc400008a,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Interface {
    Error {
        target_info: u32,
        error_code: Error,
    },
    Success {
        target_info: u32,
        result_regs: [u64; 6],
        is_32bit: bool,
    },
    Interrupt {
        endpoint_id: u32,
        interrupt_id: u32,
    },
    Version {
        input_version: u32,
    },
    VersionOut {
        output_version: u32,
    },
    Features {
        feat_id: u32,
        input_properties: u32,
    },
    RxAcquire {
        vm_id: u32,
    },
    RxRelease {
        vm_id: u32,
    },
    RxTxMap {
        tx_addr: u64,
        rx_addr: u64,
        page_cnt: u32,
        is_32bit: bool,
    },
    RxTxUnmap {
        id: u32,
    },
    PartitionInfoGet {
        uuid: Uuid,
        flags: u32,
    },
    IdGet,
    SpmIdGet,
    MsgWait,
    Yield,
    Run {
        target_info: u32,
    },
    NormalWorldResume,
    MsgSend2 {
        sender_vm_id: u32,
        flags: u32,
    },
    MsgSendDirectReq {
        src_id: u16,
        dst_id: u16,
        flags: u32,
        args: [u64; 5],
        is_32bit: bool,
    },
    MsgSendDirectResp {
        src_id: u16,
        dst_id: u16,
        flags: u32,
        args: [u64; 5],
        is_32bit: bool,
    },
    MemDonate {
        total_len: u32,
        frag_len: u32,
        address: u64,
        page_cnt: u32,
        is_32bit: bool,
    },
    MemLend {
        total_len: u32,
        frag_len: u32,
        address: u64,
        page_cnt: u32,
        is_32bit: bool,
    },
    MemShare {
        total_len: u32,
        frag_len: u32,
        address: u64,
        page_cnt: u32,
        is_32bit: bool,
    },
    MemRetrieveReq {
        total_len: u32,
        frag_len: u32,
        address: u64,
        page_cnt: u32,
        is_32bit: bool,
    },
    MemRetrieveResp {
        total_len: u32,
        frag_len: u32,
    },
    MemRelinquish,
    MemReclaim {
        handle: memory_management::Handle,
        flags: u32,
    },
    MemPermGet {
        base_addr: u64,
        is_32bit: bool,
    },
    MemPermSet {
        base_addr: u64,
        page_cnt: u32,
        mem_perm: u32,
        is_32bit: bool,
    },
    ConsoleLog {
        char_cnt: u32,
        char_lists: [u64; 6],
        is_32bit: bool,
    },
}

impl TryFrom<[u64; 8]> for Interface {
    type Error = UnrecognisedFunctionIdError;

    fn try_from(regs: [u64; 8]) -> Result<Self, UnrecognisedFunctionIdError> {
        let fid = FuncId::try_from(regs[0] as u32)?;

        let msg = match fid {
            FuncId::Error => Self::Error {
                target_info: regs[1] as u32,
                error_code: Error::try_from(regs[2] as i32).unwrap(),
            },
            FuncId::Success32 | FuncId::Success64 => {
                let target_info = regs[1] as u32;
                let mut result_regs = [regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]];
                let mut is_32bit = false;

                if fid == FuncId::Success32 {
                    result_regs[0] &= u32::MAX as u64;
                    result_regs[1] &= u32::MAX as u64;
                    result_regs[2] &= u32::MAX as u64;
                    result_regs[3] &= u32::MAX as u64;
                    result_regs[4] &= u32::MAX as u64;
                    result_regs[5] &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::Success {
                    target_info,
                    result_regs,
                    is_32bit,
                }
            }
            FuncId::Interrupt => Self::Interrupt {
                endpoint_id: regs[1] as u32,
                interrupt_id: regs[2] as u32,
            },
            FuncId::Version => Self::Version {
                input_version: regs[1] as u32,
            },
            FuncId::Features => Self::Features {
                feat_id: regs[1] as u32,
                input_properties: regs[2] as u32,
            },
            FuncId::RxAcquire => Self::RxAcquire {
                vm_id: regs[1] as u32,
            },
            FuncId::RxRelease => Self::RxRelease {
                vm_id: regs[1] as u32,
            },
            FuncId::RxTxMap32 | FuncId::RxTxMap64 => {
                let mut tx_addr = regs[1];
                let mut rx_addr = regs[2];
                let page_cnt = regs[3] as u32;
                let mut is_32bit = false;

                if fid == FuncId::RxTxMap32 {
                    tx_addr &= u32::MAX as u64;
                    rx_addr &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::RxTxMap {
                    tx_addr,
                    rx_addr,
                    page_cnt,
                    is_32bit,
                }
            }
            FuncId::RxTxUnmap => Self::RxTxUnmap { id: regs[1] as u32 },
            FuncId::PartitionInfoGet => {
                let uuid_words = [
                    regs[1] as u32,
                    regs[2] as u32,
                    regs[3] as u32,
                    regs[4] as u32,
                ];
                let mut bytes: [u8; 16] = [0; 16];
                for (i, b) in uuid_words.iter().flat_map(|w| w.to_le_bytes()).enumerate() {
                    bytes[i] = b;
                }
                Self::PartitionInfoGet {
                    uuid: Uuid::from_bytes(bytes),
                    flags: regs[5] as u32,
                }
            }
            FuncId::IdGet => Self::IdGet,
            FuncId::SpmIdGet => Self::SpmIdGet,
            FuncId::MsgWait => Self::MsgWait,
            FuncId::Yield => Self::Yield,
            FuncId::Run => Self::Run {
                target_info: regs[1] as u32,
            },
            FuncId::NormalWorldResume => Self::NormalWorldResume,
            FuncId::MsgSend2 => Self::MsgSend2 {
                sender_vm_id: regs[1] as u32,
                flags: regs[2] as u32,
            },
            FuncId::MsgSendDirectReq32 | FuncId::MsgSendDirectReq64 => {
                let src_id = (regs[1] >> 16) as u16;
                let dst_id = regs[1] as u16;
                let flags = regs[2] as u32;
                let mut args = [regs[3], regs[4], regs[5], regs[6], regs[7]];
                let mut is_32bit = false;

                if fid == FuncId::MsgSendDirectReq32 {
                    args[0] &= u32::MAX as u64;
                    args[1] &= u32::MAX as u64;
                    args[2] &= u32::MAX as u64;
                    args[3] &= u32::MAX as u64;
                    args[4] &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MsgSendDirectReq {
                    src_id,
                    dst_id,
                    flags,
                    args,
                    is_32bit,
                }
            }
            FuncId::MsgSendDirectResp32 | FuncId::MsgSendDirectResp64 => {
                let src_id = (regs[1] >> 16) as u16;
                let dst_id = regs[1] as u16;
                let flags = regs[2] as u32;
                let mut args = [regs[3], regs[4], regs[5], regs[6], regs[7]];
                let mut is_32bit = false;

                if fid == FuncId::MsgSendDirectResp32 {
                    args[0] &= u32::MAX as u64;
                    args[1] &= u32::MAX as u64;
                    args[2] &= u32::MAX as u64;
                    args[3] &= u32::MAX as u64;
                    args[4] &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MsgSendDirectResp {
                    src_id,
                    dst_id,
                    flags,
                    args,
                    is_32bit,
                }
            }
            FuncId::MemDonate32 | FuncId::MemDonate64 => {
                let total_len = regs[1] as u32;
                let frag_len = regs[2] as u32;
                let mut address = regs[3];
                let page_cnt = regs[4] as u32;
                let mut is_32bit = false;

                if fid == FuncId::MemDonate32 {
                    address &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MemDonate {
                    total_len,
                    frag_len,
                    address,
                    page_cnt,
                    is_32bit,
                }
            }
            FuncId::MemLend32 | FuncId::MemLend64 => {
                let total_len = regs[1] as u32;
                let frag_len = regs[2] as u32;
                let mut address = regs[3];
                let page_cnt = regs[4] as u32;
                let mut is_32bit = false;

                if fid == FuncId::MemLend32 {
                    address &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MemLend {
                    total_len,
                    frag_len,
                    address,
                    page_cnt,
                    is_32bit,
                }
            }
            FuncId::MemShare32 | FuncId::MemShare64 => {
                let total_len = regs[1] as u32;
                let frag_len = regs[2] as u32;
                let mut address = regs[3];
                let page_cnt = regs[4] as u32;
                let mut is_32bit = false;

                if fid == FuncId::MemShare32 {
                    address &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MemShare {
                    total_len,
                    frag_len,
                    address,
                    page_cnt,
                    is_32bit,
                }
            }
            FuncId::MemRetrieveReq32 | FuncId::MemRetrieveReq64 => {
                let total_len = regs[1] as u32;
                let frag_len = regs[2] as u32;
                let mut address = regs[3];
                let page_cnt = regs[4] as u32;
                let mut is_32bit = false;

                if fid == FuncId::MemRetrieveReq32 {
                    address &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MemRetrieveReq {
                    total_len,
                    frag_len,
                    address,
                    page_cnt,
                    is_32bit,
                }
            }
            FuncId::MemRetrieveResp => Self::MemRetrieveResp {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
            },
            FuncId::MemRelinquish => Self::MemRelinquish,
            FuncId::MemReclaim => Self::MemReclaim {
                handle: memory_management::Handle::from([regs[1] as u32, regs[2] as u32]),
                flags: regs[3] as u32,
            },
            FuncId::MemPermGet32 | FuncId::MemPermGet64 => {
                let mut base_addr = regs[1];
                let mut is_32bit = false;

                if fid == FuncId::MemPermGet32 {
                    base_addr &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MemPermGet {
                    base_addr,
                    is_32bit,
                }
            }
            FuncId::MemPermSet32 | FuncId::MemPermSet64 => {
                let mut base_addr = regs[1];
                let page_cnt = regs[2] as u32;
                let mem_perm = regs[3] as u32;
                let mut is_32bit = false;

                if fid == FuncId::MemPermSet32 {
                    base_addr &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::MemPermSet {
                    base_addr,
                    page_cnt,
                    mem_perm,
                    is_32bit,
                }
            }
            FuncId::ConsoleLog32 | FuncId::ConsoleLog64 => {
                let char_cnt = regs[1] as u32;
                let mut char_lists = [regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]];
                let mut is_32bit = false;

                if fid == FuncId::ConsoleLog32 {
                    char_lists[0] &= u32::MAX as u64;
                    char_lists[1] &= u32::MAX as u64;
                    char_lists[2] &= u32::MAX as u64;
                    char_lists[3] &= u32::MAX as u64;
                    char_lists[4] &= u32::MAX as u64;
                    char_lists[5] &= u32::MAX as u64;
                    is_32bit = true;
                }

                Self::ConsoleLog {
                    char_cnt,
                    char_lists,
                    is_32bit,
                }
            }
        };

        Ok(msg)
    }
}

impl Interface {
    /// Returns the function ID for the call, if it has one.
    pub fn function_id(&self) -> Option<FuncId> {
        match self {
            Interface::Error { .. } => Some(FuncId::Error),
            Interface::Success {
                is_32bit: false, ..
            } => Some(FuncId::Success64),
            Interface::Success { is_32bit: true, .. } => Some(FuncId::Success32),
            Interface::Interrupt { .. } => Some(FuncId::Interrupt),
            Interface::Version { .. } => Some(FuncId::Version),
            Interface::VersionOut { .. } => None,
            Interface::Features { .. } => Some(FuncId::Features),
            Interface::RxAcquire { .. } => Some(FuncId::RxAcquire),
            Interface::RxRelease { .. } => Some(FuncId::RxRelease),
            Interface::RxTxMap {
                is_32bit: false, ..
            } => Some(FuncId::RxTxMap64),
            Interface::RxTxMap { is_32bit: true, .. } => Some(FuncId::RxTxMap32),
            Interface::RxTxUnmap { .. } => Some(FuncId::RxTxUnmap),
            Interface::PartitionInfoGet { .. } => Some(FuncId::PartitionInfoGet),
            Interface::IdGet => Some(FuncId::IdGet),
            Interface::SpmIdGet => Some(FuncId::SpmIdGet),
            Interface::MsgWait => Some(FuncId::MsgWait),
            Interface::Yield => Some(FuncId::Yield),
            Interface::Run { .. } => Some(FuncId::Run),
            Interface::NormalWorldResume => Some(FuncId::NormalWorldResume),
            Interface::MsgSend2 { .. } => Some(FuncId::MsgSend2),
            Interface::MsgSendDirectReq {
                is_32bit: false, ..
            } => Some(FuncId::MsgSendDirectReq64),
            Interface::MsgSendDirectReq { is_32bit: true, .. } => Some(FuncId::MsgSendDirectReq32),
            Interface::MsgSendDirectResp {
                is_32bit: false, ..
            } => Some(FuncId::MsgSendDirectResp64),
            Interface::MsgSendDirectResp { is_32bit: true, .. } => {
                Some(FuncId::MsgSendDirectResp32)
            }
            Interface::MemDonate {
                is_32bit: false, ..
            } => Some(FuncId::MemDonate64),
            Interface::MemDonate { is_32bit: true, .. } => Some(FuncId::MemDonate32),
            Interface::MemLend {
                is_32bit: false, ..
            } => Some(FuncId::MemLend64),
            Interface::MemLend { is_32bit: true, .. } => Some(FuncId::MemLend32),
            Interface::MemShare {
                is_32bit: false, ..
            } => Some(FuncId::MemShare64),
            Interface::MemShare { is_32bit: true, .. } => Some(FuncId::MemShare32),
            Interface::MemRetrieveReq {
                is_32bit: false, ..
            } => Some(FuncId::MemRetrieveReq64),
            Interface::MemRetrieveReq { is_32bit: true, .. } => Some(FuncId::MemRetrieveReq32),
            Interface::MemRetrieveResp { .. } => Some(FuncId::MemRetrieveResp),
            Interface::MemRelinquish => Some(FuncId::MemRelinquish),
            Interface::MemReclaim { .. } => Some(FuncId::MemReclaim),
            Interface::MemPermGet {
                is_32bit: false, ..
            } => Some(FuncId::MemPermGet64),
            Interface::MemPermGet { is_32bit: true, .. } => Some(FuncId::MemPermGet32),
            Interface::MemPermSet {
                is_32bit: false, ..
            } => Some(FuncId::MemPermSet64),
            Interface::MemPermSet { is_32bit: true, .. } => Some(FuncId::MemPermSet32),
            Interface::ConsoleLog {
                is_32bit: false, ..
            } => Some(FuncId::ConsoleLog64),
            Interface::ConsoleLog { is_32bit: true, .. } => Some(FuncId::ConsoleLog32),
        }
    }

    /// Returns true if this is a 32-bit call, or false if it is a 64-bit call.
    pub fn is_32bit(&self) -> bool {
        match self {
            Interface::Error { .. }
            | Interface::Interrupt { .. }
            | Interface::Version { .. }
            | Interface::VersionOut { .. }
            | Interface::Features { .. }
            | Interface::RxAcquire { .. }
            | Interface::RxRelease { .. }
            | Interface::RxTxUnmap { .. }
            | Interface::PartitionInfoGet { .. }
            | Interface::IdGet
            | Interface::SpmIdGet
            | Interface::MsgWait
            | Interface::Yield
            | Interface::Run { .. }
            | Interface::NormalWorldResume
            | Interface::MsgSend2 { .. }
            | Interface::MemRetrieveResp { .. }
            | Interface::MemRelinquish
            | Interface::MemReclaim { .. } => true,
            Interface::Success { is_32bit, .. }
            | Interface::RxTxMap { is_32bit, .. }
            | Interface::MsgSendDirectReq { is_32bit, .. }
            | Interface::MsgSendDirectResp { is_32bit, .. }
            | Interface::MemDonate { is_32bit, .. }
            | Interface::MemLend { is_32bit, .. }
            | Interface::MemShare { is_32bit, .. }
            | Interface::MemRetrieveReq { is_32bit, .. }
            | Interface::MemPermGet { is_32bit, .. }
            | Interface::MemPermSet { is_32bit, .. }
            | Interface::ConsoleLog { is_32bit, .. } => *is_32bit,
        }
    }

    pub fn copy_to_array(&self, a: &mut [u64; 8]) {
        a.fill(0);
        if let Some(function_id) = self.function_id() {
            a[0] = function_id as u64;
        }

        match *self {
            Interface::Error {
                target_info,
                error_code,
            } => {
                a[1] = target_info as u64;
                a[2] = error_code as u32 as u64;
            }
            Interface::Success {
                target_info,
                result_regs,
                is_32bit,
            } => {
                a[1] = target_info as u64;
                if is_32bit {
                    a[2] = result_regs[0] & u32::MAX as u64;
                    a[3] = result_regs[1] & u32::MAX as u64;
                    a[4] = result_regs[2] & u32::MAX as u64;
                    a[5] = result_regs[3] & u32::MAX as u64;
                    a[6] = result_regs[4] & u32::MAX as u64;
                    a[7] = result_regs[5] & u32::MAX as u64;
                } else {
                    a[2] = result_regs[0];
                    a[3] = result_regs[1];
                    a[4] = result_regs[2];
                    a[5] = result_regs[3];
                    a[6] = result_regs[4];
                    a[7] = result_regs[5];
                }
            }
            Interface::Interrupt {
                endpoint_id,
                interrupt_id,
            } => {
                a[1] = endpoint_id as u64;
                a[2] = interrupt_id as u64;
            }
            Interface::Version { input_version } => {
                a[1] = input_version as u64;
            }
            Interface::VersionOut { output_version } => {
                a[0] = output_version as u64;
            }
            Interface::Features {
                feat_id,
                input_properties,
            } => {
                a[1] = feat_id as u64;
                a[2] = input_properties as u64;
            }
            Interface::RxAcquire { vm_id } => {
                a[1] = vm_id as u64;
            }
            Interface::RxRelease { vm_id } => {
                a[1] = vm_id as u64;
            }
            Interface::RxTxMap {
                tx_addr,
                rx_addr,
                page_cnt,
                is_32bit,
            } => {
                a[3] = page_cnt as u64;
                if is_32bit {
                    a[1] = tx_addr & u32::MAX as u64;
                    a[2] = rx_addr & u32::MAX as u64;
                } else {
                    a[1] = tx_addr;
                    a[2] = rx_addr;
                }
            }
            Interface::RxTxUnmap { id } => {
                a[1] = id as u64;
            }
            Interface::PartitionInfoGet { uuid, flags } => {
                let bytes = uuid.to_bytes_le();
                a[1] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
                a[2] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64;
                a[3] = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as u64;
                a[4] = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as u64;
                a[5] = flags as u64;
            }
            Interface::IdGet | Interface::SpmIdGet | Interface::MsgWait | Interface::Yield => {}
            Interface::Run { target_info } => {
                a[1] = target_info as u64;
            }
            Interface::NormalWorldResume => {}
            Interface::MsgSend2 {
                sender_vm_id,
                flags,
            } => {
                a[1] = sender_vm_id as u64;
                a[2] = flags as u64;
            }
            Interface::MsgSendDirectReq {
                src_id,
                dst_id,
                flags,
                args,
                is_32bit,
            } => {
                a[1] = (src_id as u64) << 16 | dst_id as u64;
                a[2] = flags as u64;
                if is_32bit {
                    a[3] = args[0] & u32::MAX as u64;
                    a[4] = args[1] & u32::MAX as u64;
                    a[5] = args[2] & u32::MAX as u64;
                    a[6] = args[3] & u32::MAX as u64;
                    a[7] = args[4] & u32::MAX as u64;
                } else {
                    a[3] = args[0];
                    a[4] = args[1];
                    a[5] = args[2];
                    a[6] = args[3];
                    a[7] = args[4];
                }
            }
            Interface::MsgSendDirectResp {
                src_id,
                dst_id,
                flags,
                args,
                is_32bit,
            } => {
                a[1] = (src_id as u64) << 16 | dst_id as u64;
                a[2] = flags as u64;
                if is_32bit {
                    a[3] = args[0] & u32::MAX as u64;
                    a[4] = args[1] & u32::MAX as u64;
                    a[5] = args[2] & u32::MAX as u64;
                    a[6] = args[3] & u32::MAX as u64;
                    a[7] = args[4] & u32::MAX as u64;
                } else {
                    a[3] = args[0];
                    a[4] = args[1];
                    a[5] = args[2];
                    a[6] = args[3];
                    a[7] = args[4];
                }
            }
            Interface::MemDonate {
                total_len,
                frag_len,
                address,
                page_cnt,
                is_32bit,
            } => {
                a[1] = total_len as u64;
                a[2] = frag_len as u64;
                a[4] = page_cnt as u64;
                if is_32bit {
                    a[3] = address & u32::MAX as u64;
                } else {
                    a[3] = address;
                }
            }
            Interface::MemLend {
                total_len,
                frag_len,
                address,
                page_cnt,
                is_32bit,
            } => {
                a[1] = total_len as u64;
                a[2] = frag_len as u64;
                a[4] = page_cnt as u64;
                if is_32bit {
                    a[3] = address & u32::MAX as u64;
                } else {
                    a[3] = address;
                }
            }
            Interface::MemShare {
                total_len,
                frag_len,
                address,
                page_cnt,
                is_32bit,
            } => {
                a[1] = total_len as u64;
                a[2] = frag_len as u64;
                a[4] = page_cnt as u64;
                if is_32bit {
                    a[3] = address & u32::MAX as u64;
                } else {
                    a[3] = address;
                }
            }
            Interface::MemRetrieveReq {
                total_len,
                frag_len,
                address,
                page_cnt,
                is_32bit,
            } => {
                a[1] = total_len as u64;
                a[2] = frag_len as u64;
                a[4] = page_cnt as u64;
                if is_32bit {
                    a[3] = address & u32::MAX as u64;
                } else {
                    a[3] = address;
                }
            }
            Interface::MemRetrieveResp {
                total_len,
                frag_len,
            } => {
                a[1] = total_len as u64;
                a[2] = frag_len as u64;
            }
            Interface::MemRelinquish => {}
            Interface::MemReclaim { handle, flags } => {
                let handle_regs: [u32; 2] = handle.into();
                a[1] = handle_regs[0] as u64;
                a[2] = handle_regs[1] as u64;
                a[3] = flags as u64;
            }
            Interface::MemPermGet {
                base_addr,
                is_32bit,
            } => {
                if is_32bit {
                    a[1] = base_addr & u32::MAX as u64;
                } else {
                    a[1] = base_addr;
                }
            }
            Interface::MemPermSet {
                base_addr,
                page_cnt,
                mem_perm,
                is_32bit,
            } => {
                a[2] = page_cnt as u64;
                a[3] = mem_perm as u64;

                if is_32bit {
                    a[1] = base_addr & u32::MAX as u64;
                } else {
                    a[1] = base_addr;
                }
            }
            Interface::ConsoleLog {
                char_cnt,
                char_lists,
                is_32bit,
            } => {
                a[1] = char_cnt as u64;
                if is_32bit {
                    a[2] = char_lists[0] & u32::MAX as u64;
                    a[3] = char_lists[1] & u32::MAX as u64;
                    a[4] = char_lists[2] & u32::MAX as u64;
                    a[5] = char_lists[3] & u32::MAX as u64;
                    a[6] = char_lists[4] & u32::MAX as u64;
                    a[7] = char_lists[5] & u32::MAX as u64;
                } else {
                    a[2] = char_lists[0];
                    a[3] = char_lists[1];
                    a[4] = char_lists[2];
                    a[5] = char_lists[3];
                    a[6] = char_lists[4];
                    a[7] = char_lists[5];
                }
            }
        }
    }

    /// Helper function to create an FFA_SUCCESS interface without any arguments
    pub fn success32_noargs() -> Self {
        Self::Success {
            target_info: 0,
            result_regs: [0, 0, 0, 0, 0, 0],
            is_32bit: true,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Version(pub u16, pub u16);

impl From<u32> for Version {
    fn from(val: u32) -> Self {
        Self((val >> 16) as u16, val as u16)
    }
}

impl From<Version> for u32 {
    fn from(v: Version) -> Self {
        (v.0 as u32) << 16 | v.1 as u32
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

pub const CONSOLE_LOG_32_MAX_MSG_LEN: usize = 24;
pub const CONSOLE_LOG_64_MAX_MSG_LEN: usize = 48;

pub fn parse_console_log(
    char_cnt: u32,
    char_lists: &[u64; 6],
    is_32bit: bool,
    log_bytes: &mut [u8],
) -> Result<(), Error> {
    const CHAR_COUNT_MASK: u32 = 0xff;

    let char_count = (char_cnt & CHAR_COUNT_MASK) as usize;
    let (max_length, reg_size) = if is_32bit {
        (CONSOLE_LOG_32_MAX_MSG_LEN, 4)
    } else {
        (CONSOLE_LOG_64_MAX_MSG_LEN, 8)
    };

    if char_count < 1 || char_count > max_length {
        return Err(Error::InvalidParameters);
    }

    for i in 0..=5 {
        log_bytes[reg_size * i..reg_size * (i + 1)]
            .copy_from_slice(&char_lists[i].to_le_bytes()[0..reg_size]);
    }

    Ok(())
}
