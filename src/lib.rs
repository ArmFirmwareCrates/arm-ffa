// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(not(test), no_std)]

use core::fmt::{self, Debug, Display, Formatter};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;
use uuid::Uuid;

pub mod boot_info;
mod ffa_v1_1;
pub mod memory_management;
pub mod partition_info;

// On many occasions the FF-A spec defines memory size as count of 4K pages,
// regardless of the current translation granule
pub const FFA_PAGE_SIZE_4K: usize = 4096;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unrecognised FF-A function ID {0}")]
    UnrecognisedFunctionId(u32),
    #[error("Unrecognised FF-A feature ID {0}")]
    UnrecognisedFeatureId(u8),
    #[error("Unrecognised FF-A error code {0}")]
    UnrecognisedErrorCode(i32),
    #[error("Invalid version {0}")]
    InvalidVersion(u32),
}

impl From<Error> for FfaError {
    fn from(value: Error) -> Self {
        match value {
            Error::UnrecognisedFunctionId(_) | Error::UnrecognisedFeatureId(_) => {
                Self::NotSupported
            }
            Error::UnrecognisedErrorCode(_) | Error::InvalidVersion(_) => Self::InvalidParameters,
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum Instance {
    SecurePhysical,
    SecureVirtual(u16),
}

/// FF-A v1.1: Function IDs
#[derive(Clone, Copy, Debug, Eq, IntoPrimitive, PartialEq, TryFromPrimitive)]
#[num_enum(error_type(name = Error, constructor = Error::UnrecognisedFunctionId))]
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

/// FF-A v1.1, Table 12.2: Error status codes
#[derive(Clone, Copy, Debug, Eq, Error, IntoPrimitive, PartialEq, TryFromPrimitive)]
#[num_enum(error_type(name = Error, constructor = Error::UnrecognisedErrorCode))]
#[repr(i32)]
pub enum FfaError {
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

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct TargetInfo {
    pub endpoint_id: u16,
    pub vcpu_id: u16,
}

impl From<u32> for TargetInfo {
    fn from(value: u32) -> Self {
        Self {
            endpoint_id: (value >> 16) as u16,
            vcpu_id: value as u16,
        }
    }
}

impl From<TargetInfo> for u32 {
    fn from(value: TargetInfo) -> Self {
        (value.endpoint_id as u32) << 16 | value.vcpu_id as u32
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum SuccessArgs {
    Result32([u32; 6]),
    Result64([u64; 6]),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Version(pub u16, pub u16);

impl Version {
    /// Returns whether the caller's version (self) is compatible with the callee's version (input parameter)
    pub fn is_compatible_to(&self, callee_version: &Version) -> bool {
        self.0 == callee_version.0 && self.1 <= callee_version.1
    }

    // MSG flag for when responding to FFA_VERSION
    pub const VERSION_MSG_FLAG: u32 = 0b0000_1001;
}

impl TryFrom<u32> for Version {
    type Error = Error;

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        if (val & (1 << 31)) != 0 {
            Err(Error::InvalidVersion(val))
        } else {
            Ok(Self((val >> 16) as u16, val as u16))
        }
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

#[derive(Clone, Copy, Debug, Eq, IntoPrimitive, PartialEq, TryFromPrimitive)]
#[num_enum(error_type(name = Error, constructor = Error::UnrecognisedFeatureId))]
#[repr(u8)]
pub enum FeatureId {
    NotificationPendingInterrupt = 0x1,
    ScheduleReceiverInterrupt = 0x2,
    ManagedExitInterrupt = 0x3,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Feature {
    FuncId(FuncId),
    FeatureId(FeatureId),
}

impl TryFrom<u32> for Feature {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let res = if (value >> 31) & 1 == 1 {
            Self::FuncId(value.try_into()?)
        } else {
            Self::FeatureId((value as u8).try_into()?)
        };

        Ok(res)
    }
}

impl From<Feature> for u32 {
    fn from(value: Feature) -> Self {
        match value {
            Feature::FuncId(func_id) => (1 << 31) | func_id as u32,
            Feature::FeatureId(feature_id) => feature_id as u32,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum RxTxAddr {
    Addr32 { rx: u32, tx: u32 },
    Addr64 { rx: u64, tx: u64 },
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum DirectMsgArgs {
    Args32([u32; 5]),
    Args64([u64; 5]),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum MemOpBuf {
    Buf32 { addr: u32, page_cnt: u32 },
    Buf64 { addr: u64, page_cnt: u32 },
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum MemAddr {
    Addr32(u32),
    Addr64(u64),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum ConsoleLogChars {
    Reg32([u32; 6]),
    Reg64([u64; 6]),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Interface {
    Error {
        target_info: TargetInfo,
        error_code: FfaError,
    },
    Success {
        target_info: u32,
        args: SuccessArgs,
    },
    Interrupt {
        target_info: TargetInfo,
        interrupt_id: u32,
    },
    Version {
        input_version: Version,
    },
    VersionOut {
        output_version: Version,
    },
    Features {
        feat_id: Feature,
        input_properties: u32,
    },
    RxAcquire {
        vm_id: u16,
    },
    RxRelease {
        vm_id: u16,
    },
    RxTxMap {
        addr: RxTxAddr,
        page_cnt: u32,
    },
    RxTxUnmap {
        id: u16,
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
        target_info: TargetInfo,
    },
    NormalWorldResume,
    MsgSend2 {
        sender_vm_id: u16,
        flags: u32,
    },
    MsgSendDirectReq {
        src_id: u16,
        dst_id: u16,
        flags: u32,
        args: DirectMsgArgs,
    },
    MsgSendDirectResp {
        src_id: u16,
        dst_id: u16,
        flags: u32,
        args: DirectMsgArgs,
    },
    MemDonate {
        total_len: u32,
        frag_len: u32,
        buf: Option<MemOpBuf>,
    },
    MemLend {
        total_len: u32,
        frag_len: u32,
        buf: Option<MemOpBuf>,
    },
    MemShare {
        total_len: u32,
        frag_len: u32,
        buf: Option<MemOpBuf>,
    },
    MemRetrieveReq {
        total_len: u32,
        frag_len: u32,
        buf: Option<MemOpBuf>,
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
        addr: MemAddr,
    },
    MemPermSet {
        addr: MemAddr,
        page_cnt: u32,
        mem_perm: u32,
    },
    ConsoleLog {
        char_cnt: u8,
        char_lists: ConsoleLogChars,
    },
}

impl TryFrom<[u64; 8]> for Interface {
    type Error = Error;

    fn try_from(regs: [u64; 8]) -> Result<Self, Error> {
        let fid = FuncId::try_from(regs[0] as u32)?;

        let msg = match fid {
            FuncId::Error => Self::Error {
                target_info: (regs[1] as u32).into(),
                error_code: FfaError::try_from(regs[2] as i32)?,
            },
            FuncId::Success32 => Self::Success {
                target_info: regs[1] as u32,
                args: SuccessArgs::Result32([
                    regs[2] as u32,
                    regs[3] as u32,
                    regs[4] as u32,
                    regs[5] as u32,
                    regs[6] as u32,
                    regs[7] as u32,
                ]),
            },
            FuncId::Success64 => Self::Success {
                target_info: regs[1] as u32,
                args: SuccessArgs::Result64([regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]]),
            },
            FuncId::Interrupt => Self::Interrupt {
                target_info: (regs[1] as u32).into(),
                interrupt_id: regs[2] as u32,
            },
            FuncId::Version => Self::Version {
                input_version: (regs[1] as u32).try_into()?,
            },
            FuncId::Features => Self::Features {
                feat_id: (regs[1] as u32).try_into()?,
                input_properties: regs[2] as u32,
            },
            FuncId::RxAcquire => Self::RxAcquire {
                vm_id: regs[1] as u16,
            },
            FuncId::RxRelease => Self::RxRelease {
                vm_id: regs[1] as u16,
            },
            FuncId::RxTxMap32 => {
                let addr = RxTxAddr::Addr32 {
                    rx: regs[2] as u32,
                    tx: regs[1] as u32,
                };
                let page_cnt = regs[3] as u32;

                Self::RxTxMap { addr, page_cnt }
            }
            FuncId::RxTxMap64 => {
                let addr = RxTxAddr::Addr64 {
                    rx: regs[2],
                    tx: regs[1],
                };
                let page_cnt = regs[3] as u32;

                Self::RxTxMap { addr, page_cnt }
            }
            FuncId::RxTxUnmap => Self::RxTxUnmap { id: regs[1] as u16 },
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
                target_info: (regs[1] as u32).into(),
            },
            FuncId::NormalWorldResume => Self::NormalWorldResume,
            FuncId::MsgSend2 => Self::MsgSend2 {
                sender_vm_id: regs[1] as u16,
                flags: regs[2] as u32,
            },
            FuncId::MsgSendDirectReq32 => Self::MsgSendDirectReq {
                src_id: (regs[1] >> 16) as u16,
                dst_id: regs[1] as u16,
                flags: regs[2] as u32,
                args: DirectMsgArgs::Args32([
                    regs[3] as u32,
                    regs[4] as u32,
                    regs[5] as u32,
                    regs[6] as u32,
                    regs[7] as u32,
                ]),
            },
            FuncId::MsgSendDirectReq64 => Self::MsgSendDirectReq {
                src_id: (regs[1] >> 16) as u16,
                dst_id: regs[1] as u16,
                flags: regs[2] as u32,
                args: DirectMsgArgs::Args64([regs[3], regs[4], regs[5], regs[6], regs[7]]),
            },
            FuncId::MsgSendDirectResp32 => Self::MsgSendDirectResp {
                src_id: (regs[1] >> 16) as u16,
                dst_id: regs[1] as u16,
                flags: regs[2] as u32,
                args: DirectMsgArgs::Args32([
                    regs[3] as u32,
                    regs[4] as u32,
                    regs[5] as u32,
                    regs[6] as u32,
                    regs[7] as u32,
                ]),
            },
            FuncId::MsgSendDirectResp64 => Self::MsgSendDirectResp {
                src_id: (regs[1] >> 16) as u16,
                dst_id: regs[1] as u16,
                flags: regs[2] as u32,
                args: DirectMsgArgs::Args64([regs[3], regs[4], regs[5], regs[6], regs[7]]),
            },
            FuncId::MemDonate32 => Self::MemDonate {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf32 {
                        addr: regs[3] as u32,
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemDonate64 => Self::MemDonate {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf64 {
                        addr: regs[3],
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemLend32 => Self::MemLend {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf32 {
                        addr: regs[3] as u32,
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemLend64 => Self::MemLend {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf64 {
                        addr: regs[3],
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemShare32 => Self::MemShare {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf32 {
                        addr: regs[3] as u32,
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemShare64 => Self::MemShare {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf64 {
                        addr: regs[3],
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemRetrieveReq32 => Self::MemRetrieveReq {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf32 {
                        addr: regs[3] as u32,
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemRetrieveReq64 => Self::MemRetrieveReq {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
                buf: if regs[3] != 0 && regs[4] != 0 {
                    Some(MemOpBuf::Buf64 {
                        addr: regs[3],
                        page_cnt: regs[4] as u32,
                    })
                } else {
                    None
                },
            },
            FuncId::MemRetrieveResp => Self::MemRetrieveResp {
                total_len: regs[1] as u32,
                frag_len: regs[2] as u32,
            },
            FuncId::MemRelinquish => Self::MemRelinquish,
            FuncId::MemReclaim => Self::MemReclaim {
                handle: memory_management::Handle::from([regs[1] as u32, regs[2] as u32]),
                flags: regs[3] as u32,
            },
            FuncId::MemPermGet32 => Self::MemPermGet {
                addr: MemAddr::Addr32(regs[1] as u32),
            },
            FuncId::MemPermGet64 => Self::MemPermGet {
                addr: MemAddr::Addr64(regs[1]),
            },
            FuncId::MemPermSet32 => Self::MemPermSet {
                addr: MemAddr::Addr32(regs[1] as u32),
                page_cnt: regs[2] as u32,
                mem_perm: regs[3] as u32,
            },
            FuncId::MemPermSet64 => Self::MemPermSet {
                addr: MemAddr::Addr64(regs[1]),
                page_cnt: regs[2] as u32,
                mem_perm: regs[3] as u32,
            },
            FuncId::ConsoleLog32 => Self::ConsoleLog {
                char_cnt: regs[1] as u8,
                char_lists: ConsoleLogChars::Reg32([
                    regs[2] as u32,
                    regs[3] as u32,
                    regs[4] as u32,
                    regs[5] as u32,
                    regs[6] as u32,
                    regs[7] as u32,
                ]),
            },
            FuncId::ConsoleLog64 => Self::ConsoleLog {
                char_cnt: regs[1] as u8,
                char_lists: ConsoleLogChars::Reg64([
                    regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
                ]),
            },
        };

        Ok(msg)
    }
}

impl Interface {
    /// Returns the function ID for the call, if it has one.
    pub fn function_id(&self) -> Option<FuncId> {
        match self {
            Interface::Error { .. } => Some(FuncId::Error),
            Interface::Success { args, .. } => match args {
                SuccessArgs::Result32(..) => Some(FuncId::Success32),
                SuccessArgs::Result64(..) => Some(FuncId::Success64),
            },
            Interface::Interrupt { .. } => Some(FuncId::Interrupt),
            Interface::Version { .. } => Some(FuncId::Version),
            Interface::VersionOut { .. } => None,
            Interface::Features { .. } => Some(FuncId::Features),
            Interface::RxAcquire { .. } => Some(FuncId::RxAcquire),
            Interface::RxRelease { .. } => Some(FuncId::RxRelease),
            Interface::RxTxMap { addr, .. } => match addr {
                RxTxAddr::Addr32 { .. } => Some(FuncId::RxTxMap32),
                RxTxAddr::Addr64 { .. } => Some(FuncId::RxTxMap64),
            },
            Interface::RxTxUnmap { .. } => Some(FuncId::RxTxUnmap),
            Interface::PartitionInfoGet { .. } => Some(FuncId::PartitionInfoGet),
            Interface::IdGet => Some(FuncId::IdGet),
            Interface::SpmIdGet => Some(FuncId::SpmIdGet),
            Interface::MsgWait => Some(FuncId::MsgWait),
            Interface::Yield => Some(FuncId::Yield),
            Interface::Run { .. } => Some(FuncId::Run),
            Interface::NormalWorldResume => Some(FuncId::NormalWorldResume),
            Interface::MsgSend2 { .. } => Some(FuncId::MsgSend2),
            Interface::MsgSendDirectReq { args, .. } => match args {
                DirectMsgArgs::Args32(_) => Some(FuncId::MsgSendDirectReq32),
                DirectMsgArgs::Args64(_) => Some(FuncId::MsgSendDirectReq64),
            },
            Interface::MsgSendDirectResp { args, .. } => match args {
                DirectMsgArgs::Args32(_) => Some(FuncId::MsgSendDirectResp32),
                DirectMsgArgs::Args64(_) => Some(FuncId::MsgSendDirectResp64),
            },
            Interface::MemDonate { buf, .. } => match buf {
                Some(MemOpBuf::Buf64 { .. }) => Some(FuncId::MemDonate64),
                _ => Some(FuncId::MemDonate32),
            },
            Interface::MemLend { buf, .. } => match buf {
                Some(MemOpBuf::Buf64 { .. }) => Some(FuncId::MemLend64),
                _ => Some(FuncId::MemLend32),
            },
            Interface::MemShare { buf, .. } => match buf {
                Some(MemOpBuf::Buf64 { .. }) => Some(FuncId::MemShare64),
                _ => Some(FuncId::MemShare32),
            },
            Interface::MemRetrieveReq { buf, .. } => match buf {
                Some(MemOpBuf::Buf64 { .. }) => Some(FuncId::MemRetrieveReq64),
                _ => Some(FuncId::MemRetrieveReq32),
            },
            Interface::MemRetrieveResp { .. } => Some(FuncId::MemRetrieveResp),
            Interface::MemRelinquish => Some(FuncId::MemRelinquish),
            Interface::MemReclaim { .. } => Some(FuncId::MemReclaim),
            Interface::MemPermGet { addr, .. } => match addr {
                MemAddr::Addr32(_) => Some(FuncId::MemPermGet32),
                MemAddr::Addr64(_) => Some(FuncId::MemPermGet64),
            },
            Interface::MemPermSet { addr, .. } => match addr {
                MemAddr::Addr32(_) => Some(FuncId::MemPermSet32),
                MemAddr::Addr64(_) => Some(FuncId::MemPermSet64),
            },
            Interface::ConsoleLog { char_lists, .. } => match char_lists {
                ConsoleLogChars::Reg32(_) => Some(FuncId::ConsoleLog32),
                ConsoleLogChars::Reg64(_) => Some(FuncId::ConsoleLog64),
            },
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
            Interface::Success {
                args: SuccessArgs::Result32(..),
                ..
            } => true,
            Interface::RxTxMap {
                addr: RxTxAddr::Addr32 { .. },
                ..
            } => true,
            Interface::MsgSendDirectReq { args, .. }
            | Interface::MsgSendDirectResp { args, .. }
                if matches!(args, DirectMsgArgs::Args32(_)) =>
            {
                true
            }
            Interface::MemDonate { buf, .. }
            | Interface::MemLend { buf, .. }
            | Interface::MemShare { buf, .. }
            | Interface::MemRetrieveReq { buf, .. }
                if buf.is_none() || matches!(buf, Some(MemOpBuf::Buf32 { .. })) =>
            {
                true
            }
            Interface::MemPermGet { addr, .. } | Interface::MemPermSet { addr, .. }
                if matches!(addr, MemAddr::Addr32(_)) =>
            {
                true
            }
            Interface::ConsoleLog {
                char_lists: ConsoleLogChars::Reg32(_),
                ..
            } => true,
            _ => false,
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
                a[1] = u32::from(target_info).into();
                a[2] = (error_code as u32).into();
            }
            Interface::Success { target_info, args } => {
                a[1] = target_info.into();
                match args {
                    SuccessArgs::Result32(regs) => {
                        a[2] = regs[0].into();
                        a[3] = regs[1].into();
                        a[4] = regs[2].into();
                        a[5] = regs[3].into();
                        a[6] = regs[4].into();
                        a[7] = regs[5].into();
                    }
                    SuccessArgs::Result64(regs) => {
                        a[2] = regs[0];
                        a[3] = regs[1];
                        a[4] = regs[2];
                        a[5] = regs[3];
                        a[6] = regs[4];
                        a[7] = regs[5];
                    }
                }
            }
            Interface::Interrupt {
                target_info,
                interrupt_id,
            } => {
                a[1] = u32::from(target_info).into();
                a[2] = interrupt_id.into();
            }
            Interface::Version { input_version } => {
                a[1] = u32::from(input_version).into();
            }
            Interface::VersionOut { output_version } => {
                a[0] = u32::from(output_version).into();
            }
            Interface::Features {
                feat_id,
                input_properties,
            } => {
                a[1] = u32::from(feat_id).into();
                a[2] = input_properties.into();
            }
            Interface::RxAcquire { vm_id } => {
                a[1] = vm_id.into();
            }
            Interface::RxRelease { vm_id } => {
                a[1] = vm_id.into();
            }
            Interface::RxTxMap { addr, page_cnt } => {
                match addr {
                    RxTxAddr::Addr32 { rx, tx } => {
                        a[1] = tx.into();
                        a[2] = rx.into();
                    }
                    RxTxAddr::Addr64 { rx, tx } => {
                        a[1] = tx;
                        a[2] = rx;
                    }
                }
                a[3] = page_cnt.into();
            }
            Interface::RxTxUnmap { id } => {
                a[1] = id.into();
            }
            Interface::PartitionInfoGet { uuid, flags } => {
                let bytes = uuid.into_bytes();
                a[1] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).into();
                a[2] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]).into();
                a[3] = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]).into();
                a[4] = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]).into();
                a[5] = flags.into();
            }
            Interface::IdGet | Interface::SpmIdGet | Interface::MsgWait | Interface::Yield => {}
            Interface::Run { target_info } => {
                a[1] = u32::from(target_info).into();
            }
            Interface::NormalWorldResume => {}
            Interface::MsgSend2 {
                sender_vm_id,
                flags,
            } => {
                a[1] = sender_vm_id.into();
                a[2] = flags.into();
            }
            Interface::MsgSendDirectReq {
                src_id,
                dst_id,
                flags,
                args,
            } => {
                a[1] = (src_id as u64) << 16 | dst_id as u64;
                a[2] = flags.into();
                match args {
                    DirectMsgArgs::Args32(args) => {
                        a[3] = args[0].into();
                        a[4] = args[1].into();
                        a[5] = args[2].into();
                        a[6] = args[3].into();
                        a[7] = args[4].into();
                    }
                    DirectMsgArgs::Args64(args) => {
                        a[3] = args[0];
                        a[4] = args[1];
                        a[5] = args[2];
                        a[6] = args[3];
                        a[7] = args[4];
                    }
                }
            }
            Interface::MsgSendDirectResp {
                src_id,
                dst_id,
                flags,
                args,
            } => {
                a[1] = (src_id as u64) << 16 | dst_id as u64;
                a[2] = flags.into();
                match args {
                    DirectMsgArgs::Args32(args) => {
                        a[3] = args[0].into();
                        a[4] = args[1].into();
                        a[5] = args[2].into();
                        a[6] = args[3].into();
                        a[7] = args[4].into();
                    }
                    DirectMsgArgs::Args64(args) => {
                        a[3] = args[0];
                        a[4] = args[1];
                        a[5] = args[2];
                        a[6] = args[3];
                        a[7] = args[4];
                    }
                }
            }
            Interface::MemDonate {
                total_len,
                frag_len,
                buf,
            } => {
                a[1] = total_len.into();
                a[2] = frag_len.into();
                (a[3], a[4]) = match buf {
                    Some(MemOpBuf::Buf32 { addr, page_cnt }) => (addr.into(), page_cnt.into()),
                    Some(MemOpBuf::Buf64 { addr, page_cnt }) => (addr, page_cnt.into()),
                    None => (0, 0),
                };
            }
            Interface::MemLend {
                total_len,
                frag_len,
                buf,
            } => {
                a[1] = total_len.into();
                a[2] = frag_len.into();
                (a[3], a[4]) = match buf {
                    Some(MemOpBuf::Buf32 { addr, page_cnt }) => (addr.into(), page_cnt.into()),
                    Some(MemOpBuf::Buf64 { addr, page_cnt }) => (addr, page_cnt.into()),
                    None => (0, 0),
                };
            }
            Interface::MemShare {
                total_len,
                frag_len,
                buf,
            } => {
                a[1] = total_len.into();
                a[2] = frag_len.into();
                (a[3], a[4]) = match buf {
                    Some(MemOpBuf::Buf32 { addr, page_cnt }) => (addr.into(), page_cnt.into()),
                    Some(MemOpBuf::Buf64 { addr, page_cnt }) => (addr, page_cnt.into()),
                    None => (0, 0),
                };
            }
            Interface::MemRetrieveReq {
                total_len,
                frag_len,
                buf,
            } => {
                a[1] = total_len.into();
                a[2] = frag_len.into();
                (a[3], a[4]) = match buf {
                    Some(MemOpBuf::Buf32 { addr, page_cnt }) => (addr.into(), page_cnt.into()),
                    Some(MemOpBuf::Buf64 { addr, page_cnt }) => (addr, page_cnt.into()),
                    None => (0, 0),
                };
            }
            Interface::MemRetrieveResp {
                total_len,
                frag_len,
            } => {
                a[1] = total_len.into();
                a[2] = frag_len.into();
            }
            Interface::MemRelinquish => {}
            Interface::MemReclaim { handle, flags } => {
                let handle_regs: [u32; 2] = handle.into();
                a[1] = handle_regs[0].into();
                a[2] = handle_regs[1].into();
                a[3] = flags.into();
            }
            Interface::MemPermGet { addr } => {
                a[1] = match addr {
                    MemAddr::Addr32(addr) => addr.into(),
                    MemAddr::Addr64(addr) => addr,
                };
            }
            Interface::MemPermSet {
                addr,
                page_cnt,
                mem_perm,
            } => {
                a[1] = match addr {
                    MemAddr::Addr32(addr) => addr.into(),
                    MemAddr::Addr64(addr) => addr,
                };
                a[2] = page_cnt.into();
                a[3] = mem_perm.into();
            }
            Interface::ConsoleLog {
                char_cnt,
                char_lists,
            } => {
                a[1] = char_cnt.into();
                match char_lists {
                    ConsoleLogChars::Reg32(regs) => {
                        a[2] = regs[0].into();
                        a[3] = regs[1].into();
                        a[4] = regs[2].into();
                        a[5] = regs[3].into();
                        a[6] = regs[4].into();
                        a[7] = regs[5].into();
                    }
                    ConsoleLogChars::Reg64(regs) => {
                        a[2] = regs[0];
                        a[3] = regs[1];
                        a[4] = regs[2];
                        a[5] = regs[3];
                        a[6] = regs[4];
                        a[7] = regs[5];
                    }
                }
            }
        }
    }

    /// Helper function to create an FFA_SUCCESS interface without any arguments
    pub fn success32_noargs() -> Self {
        Self::Success {
            target_info: 0,
            args: SuccessArgs::Result32([0, 0, 0, 0, 0, 0]),
        }
    }

    /// Helper function to create an FFA_ERROR interface without any arguments
    pub fn error(error_code: FfaError) -> Self {
        Self::Error {
            target_info: TargetInfo {
                endpoint_id: 0,
                vcpu_id: 0,
            },
            error_code,
        }
    }
}

pub const CONSOLE_LOG_32_MAX_MSG_LEN: u8 = 24;
pub const CONSOLE_LOG_64_MAX_MSG_LEN: u8 = 48;

pub fn parse_console_log(
    char_cnt: u8,
    char_lists: &ConsoleLogChars,
    log_bytes: &mut [u8],
) -> Result<(), FfaError> {
    match char_lists {
        ConsoleLogChars::Reg32(regs) => {
            if !(1..=CONSOLE_LOG_32_MAX_MSG_LEN).contains(&char_cnt) {
                return Err(FfaError::InvalidParameters);
            }
            for (i, reg) in regs.iter().enumerate() {
                log_bytes[4 * i..4 * (i + 1)].copy_from_slice(&reg.to_le_bytes());
            }
        }
        ConsoleLogChars::Reg64(regs) => {
            if !(1..=CONSOLE_LOG_64_MAX_MSG_LEN).contains(&char_cnt) {
                return Err(FfaError::InvalidParameters);
            }
            for (i, reg) in regs.iter().enumerate() {
                log_bytes[8 * i..8 * (i + 1)].copy_from_slice(&reg.to_le_bytes());
            }
        }
    }

    Ok(())
}
