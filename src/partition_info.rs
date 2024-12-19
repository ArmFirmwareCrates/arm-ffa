// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ffa_v1_1::partition_info_descriptor;
use thiserror::Error;
use uuid::Uuid;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid buffer size")]
    InvalidBufferSize,
    #[error("Malformed descriptor")]
    MalformedDescriptor,
}

impl From<Error> for crate::FfaError {
    fn from(_value: Error) -> Self {
        Self::InvalidParameters
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionIdType {
    PeEndpoint { execution_ctx_count: u16 },
    SepidIndep,
    SepidDep { proxy_endpoint_id: u16 },
    Aux,
}

impl PartitionIdType {
    const SHIFT: usize = 4;
    const MASK: u32 = 0b11;
    const PE_ENDPOINT: u32 = 0b00;
    const SEPID_INDEP: u32 = 0b01;
    const SEPID_DEP: u32 = 0b10;
    const AUX: u32 = 0b11;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PartitionProperties {
    /// Supports receipt of direct requests
    pub support_direct_req_rec: bool,
    /// Can send direct requests
    pub support_direct_req_send: bool,
    /// Can send and receive indirect messages
    pub support_indirect_msg: bool,
    /// Supports receipt of notifications
    pub support_notif_rec: bool,
    /// Must be informed about each VM that is created by the Hypervisor
    pub subscribe_vm_created: bool,
    /// Must be informed about each VM that is destroyed by the Hypervisor
    pub subscribe_vm_destroyed: bool,
    /// Partition runs in the AArch64 execution state
    pub is_aarch64: bool,
}

impl PartitionProperties {
    const SUPPORT_DIRECT_REQ_REC_SHIFT: usize = 0;
    const SUPPORT_DIRECT_REQ_SEND_SHIFT: usize = 1;
    const SUPPORT_INDIRECT_MSG_SHIFT: usize = 2;
    const SUPPORT_NOTIF_REC_SHIFT: usize = 3;
    const SUBSCRIBE_VM_CREATED_SHIFT: usize = 6;
    const SUBSCRIBE_VM_DESTROYED_SHIFT: usize = 7;
    const IS_AARCH64_SHIFT: usize = 8;
}

struct PartPropWrapper(PartitionIdType, PartitionProperties);

impl From<PartPropWrapper> for (u32, u16) {
    fn from(value: PartPropWrapper) -> Self {
        let exec_ctx_count_or_proxy_id = match value.0 {
            PartitionIdType::PeEndpoint {
                execution_ctx_count,
            } => execution_ctx_count,
            PartitionIdType::SepidIndep => 0,
            PartitionIdType::SepidDep { proxy_endpoint_id } => proxy_endpoint_id,
            PartitionIdType::Aux => 0,
        };

        let mut props = match value.0 {
            PartitionIdType::PeEndpoint { .. } => {
                let mut p = PartitionIdType::PE_ENDPOINT << PartitionIdType::SHIFT;

                if value.1.support_direct_req_rec {
                    p |= 1 << PartitionProperties::SUPPORT_DIRECT_REQ_REC_SHIFT;
                    if value.1.subscribe_vm_created {
                        // TODO: how to handle if ABI is invoked at NS phys instance?
                        p |= 1 << PartitionProperties::SUBSCRIBE_VM_CREATED_SHIFT
                    }
                    if value.1.subscribe_vm_destroyed {
                        // TODO: how to handle if ABI is invoked at NS phys instance?
                        p |= 1 << PartitionProperties::SUBSCRIBE_VM_DESTROYED_SHIFT
                    }
                }
                if value.1.support_direct_req_send {
                    p |= 1 << PartitionProperties::SUPPORT_DIRECT_REQ_SEND_SHIFT
                }
                if value.1.support_indirect_msg {
                    p |= 1 << PartitionProperties::SUPPORT_INDIRECT_MSG_SHIFT
                }
                if value.1.support_notif_rec {
                    p |= 1 << PartitionProperties::SUPPORT_NOTIF_REC_SHIFT
                }

                p
            }
            PartitionIdType::SepidIndep => PartitionIdType::SEPID_INDEP << PartitionIdType::SHIFT,
            PartitionIdType::SepidDep { .. } => {
                PartitionIdType::SEPID_DEP << PartitionIdType::SHIFT
            }
            PartitionIdType::Aux => PartitionIdType::AUX << PartitionIdType::SHIFT,
        };

        if value.1.is_aarch64 {
            props |= 1 << PartitionProperties::IS_AARCH64_SHIFT
        }

        (props, exec_ctx_count_or_proxy_id)
    }
}

impl From<(u32, u16)> for PartPropWrapper {
    fn from(value: (u32, u16)) -> Self {
        let part_id_type = match (value.0 >> PartitionIdType::SHIFT) & PartitionIdType::MASK {
            PartitionIdType::PE_ENDPOINT => PartitionIdType::PeEndpoint {
                execution_ctx_count: value.1,
            },
            PartitionIdType::SEPID_INDEP => PartitionIdType::SepidIndep,
            PartitionIdType::SEPID_DEP => PartitionIdType::SepidDep {
                proxy_endpoint_id: value.1,
            },
            PartitionIdType::AUX => PartitionIdType::Aux,
            _ => panic!(), // The match is exhaustive for a 2-bit value
        };

        let mut part_props = PartitionProperties::default();

        if (value.0 >> PartitionIdType::SHIFT) & PartitionIdType::MASK
            == PartitionIdType::PE_ENDPOINT
        {
            if (value.0 >> PartitionProperties::SUPPORT_DIRECT_REQ_REC_SHIFT) & 0b1 == 1 {
                part_props.support_direct_req_rec = true;

                if (value.0 >> PartitionProperties::SUBSCRIBE_VM_CREATED_SHIFT) & 0b1 == 1 {
                    part_props.subscribe_vm_created = true;
                }

                if (value.0 >> PartitionProperties::SUBSCRIBE_VM_DESTROYED_SHIFT) & 0b1 == 1 {
                    part_props.subscribe_vm_destroyed = true;
                }
            }

            if (value.0 >> PartitionProperties::SUPPORT_DIRECT_REQ_SEND_SHIFT) & 0b1 == 1 {
                part_props.support_direct_req_send = true;
            }

            if (value.0 >> PartitionProperties::SUPPORT_INDIRECT_MSG_SHIFT) & 0b1 == 1 {
                part_props.support_indirect_msg = true;
            }

            if (value.0 >> PartitionProperties::SUPPORT_NOTIF_REC_SHIFT) & 0b1 == 1 {
                part_props.support_notif_rec = true;
            }
        }

        if (value.0 >> PartitionProperties::IS_AARCH64_SHIFT) & 0b1 == 1 {
            part_props.is_aarch64 = true;
        }

        PartPropWrapper(part_id_type, part_props)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionInfo {
    pub uuid: Uuid,
    pub partition_id: u16,
    pub partition_id_type: PartitionIdType,
    pub props: PartitionProperties,
}

impl PartitionInfo {
    pub const DESC_SIZE: usize = size_of::<partition_info_descriptor>();

    pub fn pack(descriptors: &[PartitionInfo], buf: &mut [u8], fill_uuid: bool) {
        let mut offset = 0;

        for desc in descriptors {
            let mut desc_raw = partition_info_descriptor {
                partition_id: desc.partition_id,
                ..Default::default()
            };

            (
                desc_raw.partition_props,
                desc_raw.exec_ctx_count_or_proxy_id,
            ) = PartPropWrapper(desc.partition_id_type, desc.props).into();

            if fill_uuid {
                desc_raw.uuid.copy_from_slice(desc.uuid.as_bytes());
            }

            desc_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += Self::DESC_SIZE;
        }
    }
}

pub struct PartitionInfoIterator<'a> {
    buf: &'a [u8],
    offset: usize,
    count: usize,
}

impl<'a> PartitionInfoIterator<'a> {
    pub fn new(buf: &'a [u8], count: usize) -> Result<Self, Error> {
        let Some(total_size) = count.checked_mul(PartitionInfo::DESC_SIZE) else {
            return Err(Error::InvalidBufferSize);
        };

        if buf.len() < total_size {
            return Err(Error::InvalidBufferSize);
        }

        Ok(Self {
            buf,
            offset: 0,
            count,
        })
    }
}

impl Iterator for PartitionInfoIterator<'_> {
    type Item = Result<PartitionInfo, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count > 0 {
            let offset = self.offset;
            self.offset += PartitionInfo::DESC_SIZE;
            self.count -= 1;

            let Ok(desc_raw) = partition_info_descriptor::ref_from_bytes(
                &self.buf[offset..offset + PartitionInfo::DESC_SIZE],
            ) else {
                return Some(Err(Error::MalformedDescriptor));
            };

            let partition_id = desc_raw.partition_id;

            let wrapper = PartPropWrapper::from((
                desc_raw.partition_props,
                desc_raw.exec_ctx_count_or_proxy_id,
            ));

            let uuid = Uuid::from_bytes(desc_raw.uuid);

            let desc = PartitionInfo {
                uuid,
                partition_id,
                partition_id_type: wrapper.0,
                props: wrapper.1,
            };

            return Some(Ok(desc));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::uuid;

    // TODO: add tests with a known correct partition info blob

    #[test]
    fn part_info() {
        let desc1 = PartitionInfo {
            uuid: uuid!("12345678-1234-1234-1234-123456789abc"),
            partition_id: 0x8001,
            partition_id_type: PartitionIdType::PeEndpoint {
                execution_ctx_count: 1,
            },
            props: PartitionProperties {
                support_direct_req_rec: true,
                support_direct_req_send: true,
                support_indirect_msg: false,
                support_notif_rec: false,
                subscribe_vm_created: true,
                subscribe_vm_destroyed: true,
                is_aarch64: true,
            },
        };

        let desc2 = PartitionInfo {
            uuid: uuid!("abcdef00-abcd-dcba-1234-abcdef012345"),
            partition_id: 0x8002,
            partition_id_type: PartitionIdType::SepidIndep,
            props: PartitionProperties {
                support_direct_req_rec: false,
                support_direct_req_send: false,
                support_indirect_msg: false,
                support_notif_rec: false,
                subscribe_vm_created: false,
                subscribe_vm_destroyed: false,
                is_aarch64: true,
            },
        };

        let mut buf = [0u8; 0xff];
        PartitionInfo::pack(&[desc1, desc2], &mut buf, true);

        let mut descriptors = PartitionInfoIterator::new(&buf, 2).unwrap();
        let desc1_check = descriptors.next().unwrap().unwrap();
        let desc2_check = descriptors.next().unwrap().unwrap();

        assert_eq!(desc1, desc1_check);
        assert_eq!(desc2, desc2_check);
    }
}
