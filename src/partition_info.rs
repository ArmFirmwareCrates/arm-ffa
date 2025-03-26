// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Implementation of FF-A partition discovery data structures.

use thiserror::Error;
use uuid::Uuid;
use zerocopy::{FromBytes, IntoBytes};

// This module uses FF-A v1.1 types by default.
// FF-A v1.2 specified some previously reserved bits in the partition info properties field, but
// this doesn't change the descriptor format.
use crate::{ffa_v1_1::partition_info_descriptor, Version};

// Sanity check to catch if the descriptor format is changed.
const _: () = assert!(
    size_of::<crate::ffa_v1_1::partition_info_descriptor>()
        == size_of::<crate::ffa_v1_2::partition_info_descriptor>()
);

/// Rich error types returned by this module. Should be converted to [`crate::FfaError`] when used
/// with the `FFA_ERROR` interface.
#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("Invalid buffer size")]
    InvalidBufferSize,
    #[error("Malformed descriptor")]
    MalformedDescriptor,
    #[error("Invalid Information Tag")]
    InvalidInformationTag,
    #[error("Invalid Start Index")]
    InvalidStartIndex,
}

impl From<Error> for crate::FfaError {
    fn from(_value: Error) -> Self {
        Self::InvalidParameters
    }
}

/// Type of partition identified by the partition ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionIdType {
    /// Partition ID is a PE endpoint ID. Contains the number of execution contexts implemented by
    /// this partition.
    PeEndpoint { execution_ctx_count: u16 },
    /// Partition ID is a SEPID for an independent peripheral device.
    SepidIndep,
    /// Partition ID is a SEPID for an dependent peripheral device. Contains the ID of the proxy
    /// endpoint for a dependent peripheral device.
    SepidDep { proxy_endpoint_id: u16 },
    /// Partition ID is an auxiliary ID.
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

/// Properties of a partition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PartitionProperties {
    /// The partition supports receipt of direct requests.
    pub support_direct_req_rec: bool,
    /// The partition can send direct requests.
    pub support_direct_req_send: bool,
    /// The partition supports receipt of direct requests via the FFA_MSG_SEND_DIRECT_REQ2 ABI.
    /// Added in FF-A v1.2
    pub support_direct_req2_rec: Option<bool>,
    /// The partition can send direct requests via the FFA_MSG_SEND_DIRECT_REQ2 ABI.
    /// Added in FF-A v1.2
    pub support_direct_req2_send: Option<bool>,
    /// The partition can send and receive indirect messages.
    pub support_indirect_msg: bool,
    /// The partition supports receipt of notifications.
    pub support_notif_rec: bool,
    /// The partition must be informed about each VM that is created by the Hypervisor.
    pub subscribe_vm_created: bool,
    /// The partition must be informed about each VM that is destroyed by the Hypervisor.
    pub subscribe_vm_destroyed: bool,
    /// The partition runs in the AArch64 execution state.
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
    const SUPPORT_DIRECT_REQ2_REC_SHIFT: usize = 9;
    const SUPPORT_DIRECT_REQ2_SEND_SHIFT: usize = 10;
}

fn create_partition_properties(
    version: Version,
    id_type: PartitionIdType,
    properties: PartitionProperties,
) -> (u32, u16) {
    let exec_ctx_count_or_proxy_id = match id_type {
        PartitionIdType::PeEndpoint {
            execution_ctx_count,
        } => execution_ctx_count,
        PartitionIdType::SepidIndep => 0,
        PartitionIdType::SepidDep { proxy_endpoint_id } => proxy_endpoint_id,
        PartitionIdType::Aux => 0,
    };

    let mut prop_bits = match id_type {
        PartitionIdType::PeEndpoint { .. } => {
            let mut p = PartitionIdType::PE_ENDPOINT << PartitionIdType::SHIFT;

            if properties.support_direct_req_rec {
                p |= 1 << PartitionProperties::SUPPORT_DIRECT_REQ_REC_SHIFT;
                if properties.subscribe_vm_created {
                    // TODO: how to handle if ABI is invoked at NS phys instance?
                    p |= 1 << PartitionProperties::SUBSCRIBE_VM_CREATED_SHIFT
                }
                if properties.subscribe_vm_destroyed {
                    // TODO: how to handle if ABI is invoked at NS phys instance?
                    p |= 1 << PartitionProperties::SUBSCRIBE_VM_DESTROYED_SHIFT
                }
            }

            if properties.support_direct_req_send {
                p |= 1 << PartitionProperties::SUPPORT_DIRECT_REQ_SEND_SHIFT
            }

            // For v1.2 and later it's mandatory to specify these properties
            if version >= Version(1, 2) {
                if properties.support_direct_req2_rec.unwrap() {
                    p |= 1 << PartitionProperties::SUPPORT_DIRECT_REQ2_REC_SHIFT
                }

                if properties.support_direct_req2_send.unwrap() {
                    p |= 1 << PartitionProperties::SUPPORT_DIRECT_REQ2_SEND_SHIFT
                }
            }

            if properties.support_indirect_msg {
                p |= 1 << PartitionProperties::SUPPORT_INDIRECT_MSG_SHIFT
            }

            if properties.support_notif_rec {
                p |= 1 << PartitionProperties::SUPPORT_NOTIF_REC_SHIFT
            }

            p
        }
        PartitionIdType::SepidIndep => PartitionIdType::SEPID_INDEP << PartitionIdType::SHIFT,
        PartitionIdType::SepidDep { .. } => PartitionIdType::SEPID_DEP << PartitionIdType::SHIFT,
        PartitionIdType::Aux => PartitionIdType::AUX << PartitionIdType::SHIFT,
    };

    if properties.is_aarch64 {
        prop_bits |= 1 << PartitionProperties::IS_AARCH64_SHIFT
    }

    (prop_bits, exec_ctx_count_or_proxy_id)
}

fn parse_partition_properties(
    version: Version,
    prop_bits: u32,
    id_type: u16,
) -> (PartitionIdType, PartitionProperties) {
    let part_id_type = match (prop_bits >> PartitionIdType::SHIFT) & PartitionIdType::MASK {
        PartitionIdType::PE_ENDPOINT => PartitionIdType::PeEndpoint {
            execution_ctx_count: id_type,
        },
        PartitionIdType::SEPID_INDEP => PartitionIdType::SepidIndep,
        PartitionIdType::SEPID_DEP => PartitionIdType::SepidDep {
            proxy_endpoint_id: id_type,
        },
        PartitionIdType::AUX => PartitionIdType::Aux,
        _ => panic!(), // The match is exhaustive for a 2-bit value
    };

    let mut part_props = PartitionProperties::default();

    if matches!(part_id_type, PartitionIdType::PeEndpoint { .. }) {
        if (prop_bits >> PartitionProperties::SUPPORT_DIRECT_REQ_REC_SHIFT) & 0b1 == 1 {
            part_props.support_direct_req_rec = true;

            if (prop_bits >> PartitionProperties::SUBSCRIBE_VM_CREATED_SHIFT) & 0b1 == 1 {
                part_props.subscribe_vm_created = true;
            }

            if (prop_bits >> PartitionProperties::SUBSCRIBE_VM_DESTROYED_SHIFT) & 0b1 == 1 {
                part_props.subscribe_vm_destroyed = true;
            }
        }

        if (prop_bits >> PartitionProperties::SUPPORT_DIRECT_REQ_SEND_SHIFT) & 0b1 == 1 {
            part_props.support_direct_req_send = true;
        }

        if version >= Version(1, 2) {
            part_props.support_direct_req2_rec =
                Some((prop_bits >> PartitionProperties::SUPPORT_DIRECT_REQ2_REC_SHIFT) & 0b1 == 1);
            part_props.support_direct_req2_send =
                Some((prop_bits >> PartitionProperties::SUPPORT_DIRECT_REQ2_SEND_SHIFT) & 0b1 == 1);
        }

        if (prop_bits >> PartitionProperties::SUPPORT_INDIRECT_MSG_SHIFT) & 0b1 == 1 {
            part_props.support_indirect_msg = true;
        }

        if (prop_bits >> PartitionProperties::SUPPORT_NOTIF_REC_SHIFT) & 0b1 == 1 {
            part_props.support_notif_rec = true;
        }
    }

    if (prop_bits >> PartitionProperties::IS_AARCH64_SHIFT) & 0b1 == 1 {
        part_props.is_aarch64 = true;
    }

    (part_id_type, part_props)
}

/// Variables for the callee to store when dealing with an ongoing `FFA_PARTITION_INFO_GET_REGS`
/// interface request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionInfoGetRegsStatus {
    last_index: u16,
    current_index: u16,
    info_tag: u16,
}

impl PartitionInfoGetRegsStatus {
    // Amount of registers to fill each time the `FFA_PARTITION_INFO_GET_REGS` interface is called.
    const REGS_STEP: usize = 5;
    // TAG value for the calle to call and identify its requests. This value is currently fixed.
    const INFO_TAG: u16 = 0x7;

    const LAST_INDEX_SHIFT: usize = 0;
    const CURRENT_INDEX_SHIFT: usize = 16;
    const INFO_TAG_SHIFT: usize = 32;
    const DESC_ENTRY_SIZE_SHIFT: usize = 48;

    pub fn new() -> Self {
        Self {
            last_index: 0,
            current_index: 0,
            info_tag: 0,
        }
    }

    /// Get the next index of the Partition Info list to start iterating with
    ///
    /// Returns None if the iteration has reached its end (start index = current index)
    /// Returns the next start index to either:
    /// * start iterating over the Partition Info list
    /// * continue iterating over the Partition Info list from where the previous iteration was
    ///   left from.
    fn get_next_start_index(&self) -> Option<u16> {
        if self.current_index == 0 {
            Some(0)
        } else if self.current_index < self.last_index {
            Some(self.current_index + 1)
        } else {
            None
        }
    }
}

impl From<PartitionInfoGetRegsStatus> for u64 {
    fn from(get_regs_status: PartitionInfoGetRegsStatus) -> u64 {
        let PartitionInfoGetRegsStatus {
            last_index,
            current_index,
            info_tag,
        } = get_regs_status;

        (u64::from(last_index) << PartitionInfoGetRegsStatus::LAST_INDEX_SHIFT)
            | (u64::from(current_index) << PartitionInfoGetRegsStatus::CURRENT_INDEX_SHIFT)
            | (u64::from(info_tag) << PartitionInfoGetRegsStatus::INFO_TAG_SHIFT)
            | (u64::try_from(PartitionInfo::DESC_SIZE).unwrap()
                << PartitionInfoGetRegsStatus::DESC_ENTRY_SIZE_SHIFT)
    }
}

/// Partition information descriptor, returned by the `FFA_PARTITION_INFO_GET` interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionInfo {
    pub uuid: Uuid,
    pub partition_id: u16,
    pub partition_id_type: PartitionIdType,
    pub props: PartitionProperties,
}

impl PartitionInfo {
    pub const DESC_SIZE: usize = size_of::<partition_info_descriptor>();

    /// Serialize a list of partition information descriptors into a buffer. The `fill_uuid`
    /// parameter controls whether the UUID field of the descriptor will be filled.
    pub fn pack(version: Version, descriptors: &[PartitionInfo], buf: &mut [u8], fill_uuid: bool) {
        assert!((Version(1, 1)..=Version(1, 2)).contains(&version));

        let mut offset = 0;

        for desc in descriptors {
            let mut desc_raw = partition_info_descriptor {
                partition_id: desc.partition_id,
                ..Default::default()
            };

            (
                desc_raw.partition_props,
                desc_raw.exec_ctx_count_or_proxy_id,
            ) = create_partition_properties(version, desc.partition_id_type, desc.props);

            if fill_uuid {
                desc_raw.uuid.copy_from_slice(desc.uuid.as_bytes());
            }

            desc_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += Self::DESC_SIZE;
        }
    }

    /// Fill `regs` according to the logic of the `FFA_PARTITION_INFO_GET_REGS` interface.
    /// Updates the PartitionInfoGetRegsStatus structure accordingly so that the user can keep track
    /// of the status of their request.
    /// The `fill_uuid` parameter controls whether the UUID field of the descriptor will be filled.
    pub fn pack_in_regs(
        version: Version,
        descriptors: &[PartitionInfo],
        get_regs_status: &mut PartitionInfoGetRegsStatus,
        regs: &mut [u64],
        fill_uuid: bool,
    ) -> Result<(), Error> {
        assert!(version >= Version(1, 2));
        regs.fill(0);

        let start_index = match get_regs_status.get_next_start_index() {
            None => return Err(Error::InvalidStartIndex),
            Some(start_index) => usize::from(start_index),
        };
        // Validate info tag
        if (start_index == 0) && (get_regs_status.info_tag != 0)
            || (start_index != 0
                && get_regs_status.info_tag != PartitionInfoGetRegsStatus::INFO_TAG)
        {
            return Err(Error::InvalidInformationTag);
        }

        // Validate start index: It should be a valid index into the descriptors list
        if !(0..descriptors.len()).contains(&start_index) {
            return Err(Error::InvalidStartIndex);
        }

        get_regs_status.current_index = start_index.try_into().unwrap();
        get_regs_status.last_index = u16::try_from(descriptors.len() - 1).unwrap();
        // We know by the validation that if start_index != 0 the correct tag is already there.
        get_regs_status.info_tag = PartitionInfoGetRegsStatus::INFO_TAG;

        let end_of_iteration = core::cmp::min(
            descriptors.len(),
            start_index + PartitionInfoGetRegsStatus::REGS_STEP,
        );
        for (current_index, desc) in descriptors[start_index..end_of_iteration]
            .iter()
            .enumerate()
        {
            let regs_index = current_index * 3;
            let (partition_props, exec_ctx_count_or_proxy_id) =
                create_partition_properties(version, desc.partition_id_type, desc.props);

            regs[regs_index] = (u64::from(partition_props) << 32)
                | (u64::from(exec_ctx_count_or_proxy_id) << 16)
                | u64::from(desc.partition_id);

            if fill_uuid {
                let uuid_bytes = desc.uuid.as_bytes();
                // Bytes[0...7] of the UUID with byte 0 in the low-order bits.
                let lo_bytes: [u8; 8] = uuid_bytes[0..8].try_into().unwrap();
                // From spec:
                // "Each descriptor is encoded in 3 registers in little endian format as described
                // below." -> "Bytes[0...7] of the UUID with byte 0 in the low-order bits.""
                regs[regs_index + 1] = u64::from_le_bytes(lo_bytes);
                let hi_bytes: [u8; 8] = uuid_bytes[8..16].try_into().unwrap();
                regs[regs_index + 2] = u64::from_le_bytes(hi_bytes);
            } else {
                (regs[regs_index + 2], regs[regs_index + 1]) = (0, 0);
            }

            get_regs_status.current_index += 1;
        }

        // We need current index to be the last array entry that could fit in the returned partition
        // information.
        get_regs_status.current_index -= 1;

        Ok(())
    }
}

/// Iterator of partition information descriptors.
pub struct PartitionInfoIterator<'a> {
    version: Version,
    buf: &'a [u8],
    offset: usize,
    count: usize,
}

impl<'a> PartitionInfoIterator<'a> {
    /// Create an iterator of partition information descriptors from a buffer.
    pub fn new(version: Version, buf: &'a [u8], count: usize) -> Result<Self, Error> {
        assert!((Version(1, 1)..=Version(1, 2)).contains(&version));

        let Some(total_size) = count.checked_mul(PartitionInfo::DESC_SIZE) else {
            return Err(Error::InvalidBufferSize);
        };

        if buf.len() < total_size {
            return Err(Error::InvalidBufferSize);
        }

        Ok(Self {
            version,
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

            let (partition_id_type, props) = parse_partition_properties(
                self.version,
                desc_raw.partition_props,
                desc_raw.exec_ctx_count_or_proxy_id,
            );

            let uuid = Uuid::from_bytes(desc_raw.uuid);

            let desc = PartitionInfo {
                uuid,
                partition_id,
                partition_id_type,
                props,
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
                support_direct_req2_rec: Some(true),
                support_direct_req2_send: Some(true),
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
                support_direct_req2_rec: None,
                support_direct_req2_send: None,
            },
        };

        let mut buf = [0u8; 0xff];
        PartitionInfo::pack(Version(1, 2), &[desc1, desc2], &mut buf, true);

        let mut descriptors = PartitionInfoIterator::new(Version(1, 2), &buf, 2).unwrap();
        let desc1_check = descriptors.next().unwrap().unwrap();
        let desc2_check = descriptors.next().unwrap().unwrap();

        assert_eq!(desc1, desc1_check);
        assert_eq!(desc2, desc2_check);
    }

    #[test]
    fn part_info_get_regs() {
        let version = Version(1, 2);

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
                support_direct_req2_rec: Some(true),
                support_direct_req2_send: Some(true),
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
                support_direct_req2_rec: None,
                support_direct_req2_send: None,
            },
        };

        let (prop_bits_desc1, exec_ctx_count_or_proxy_id_desc1) =
            create_partition_properties(version, desc1.partition_id_type, desc1.props);
        let expected_x3_desc1 = (u64::from(prop_bits_desc1) << 32)
            | (u64::from(exec_ctx_count_or_proxy_id_desc1) << 16)
            | u64::from(desc1.partition_id);

        let (prop_bits_desc2, exec_ctx_count_or_proxy_id_desc2) =
            create_partition_properties(version, desc2.partition_id_type, desc2.props);
        let expected_x3_desc2 = (u64::from(prop_bits_desc2) << 32)
            | (u64::from(exec_ctx_count_or_proxy_id_desc2) << 16)
            | u64::from(desc2.partition_id);
        let descriptors = [desc1, desc2, desc1, desc2, desc1, desc2, desc2, desc1];

        // Checks with Nil UUID:
        {
            let mut get_regs_status = PartitionInfoGetRegsStatus::new();

            let mut output_regs: [u64; 15] = [0; 15];

            PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                true,
            )
            .unwrap();

            // First, verify that get_regs_status: PartitionInfoGetRegsStatus has the correct
            // information:
            assert_eq!(
                get_regs_status.last_index,
                u16::try_from(descriptors.len() - 1).unwrap()
            );
            assert_eq!(
                get_regs_status.info_tag,
                PartitionInfoGetRegsStatus::INFO_TAG
            );
            assert_eq!(
                get_regs_status.current_index,
                u16::try_from(PartitionInfoGetRegsStatus::REGS_STEP - 1).unwrap()
            );

            // Then, verify the contents of the output_regs
            assert_eq!(desc1.uuid.as_bytes(), output_regs[1..3].as_bytes());
            assert_eq!(desc2.uuid.as_bytes(), output_regs[4..6].as_bytes());

            assert_eq!(
                output_regs,
                [
                    expected_x3_desc1,
                    output_regs[1], // already verified above
                    output_regs[2], // already verified above
                    expected_x3_desc2,
                    output_regs[4], // already verified above
                    output_regs[5], // already verified above
                    expected_x3_desc1,
                    output_regs[1], // already verified above
                    output_regs[2], // already verified above
                    expected_x3_desc2,
                    output_regs[4], // already verified above
                    output_regs[5], // already verified above
                    expected_x3_desc1,
                    output_regs[1], // already verified above
                    output_regs[2], // already verified above
                ]
            );

            PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                true,
            )
            .unwrap();

            // First, verify that get_regs_status: PartitionInfoGetRegsStatus has the correct
            // information:
            assert_eq!(
                get_regs_status.last_index,
                u16::try_from(descriptors.len() - 1).unwrap()
            );
            assert_eq!(
                get_regs_status.info_tag,
                PartitionInfoGetRegsStatus::INFO_TAG
            );
            assert_eq!(get_regs_status.current_index, get_regs_status.last_index);

            // Then, verify the contents of the output_regs
            assert_eq!(desc2.uuid.as_bytes(), output_regs[1..3].as_bytes());
            assert_eq!(desc1.uuid.as_bytes(), output_regs[7..9].as_bytes());

            assert_eq!(
                output_regs,
                [
                    expected_x3_desc2,
                    output_regs[1], // already verified above
                    output_regs[2], // already verified above
                    expected_x3_desc2,
                    output_regs[1], // already verified above
                    output_regs[2], // already verified above
                    expected_x3_desc1,
                    output_regs[7], // already verified above
                    output_regs[8], // already verified above
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            );
        }

        // Checks with non-Nil UUID:
        {
            let mut get_regs_status = PartitionInfoGetRegsStatus::new();

            let mut output_regs: [u64; 15] = [0; 15];

            PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                false,
            )
            .unwrap();

            // First, verify that get_regs_status: PartitionInfoGetRegsStatus has the correct
            // information:
            assert_eq!(
                get_regs_status.last_index,
                u16::try_from(descriptors.len() - 1).unwrap()
            );
            assert_eq!(
                get_regs_status.info_tag,
                PartitionInfoGetRegsStatus::INFO_TAG
            );
            assert_eq!(
                get_regs_status.current_index,
                u16::try_from(PartitionInfoGetRegsStatus::REGS_STEP - 1).unwrap()
            );

            // Then, verify the contents of the output_regs
            assert_eq!(
                output_regs,
                [
                    expected_x3_desc1,
                    0,
                    0,
                    expected_x3_desc2,
                    0,
                    0,
                    expected_x3_desc1,
                    0,
                    0,
                    expected_x3_desc2,
                    0,
                    0,
                    expected_x3_desc1,
                    0,
                    0,
                ]
            );

            PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                false,
            )
            .unwrap();

            // First, verify that get_regs_status: PartitionInfoGetRegsStatus has the correct
            // information:
            assert_eq!(
                get_regs_status.last_index,
                u16::try_from(descriptors.len() - 1).unwrap()
            );
            assert_eq!(
                get_regs_status.info_tag,
                PartitionInfoGetRegsStatus::INFO_TAG
            );
            assert_eq!(get_regs_status.current_index, get_regs_status.last_index);

            // Then, verify the contents of the output_regs
            assert_eq!(
                output_regs,
                [
                    expected_x3_desc2,
                    0,
                    0,
                    expected_x3_desc2,
                    0,
                    0,
                    expected_x3_desc1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            );
        }
    }
    #[test]
    fn info_get_regs_info_empty() {
        let descriptors: [PartitionInfo; 0] = [];
        let version = Version(1, 2);
        let mut output_regs: [u64; 15] = [0; 15];

        let mut get_regs_status = PartitionInfoGetRegsStatus::new();

        let error = PartitionInfo::pack_in_regs(
            version,
            &descriptors,
            &mut get_regs_status,
            &mut output_regs,
            false,
        );
        assert!(error.is_err_and(|e| e == Error::InvalidStartIndex));
    }

    #[test]
    fn info_get_regs_info_tag() {
        let version = Version(1, 3);
        let mut output_regs: [u64; 15] = [0; 15];

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
                support_direct_req2_rec: Some(true),
                support_direct_req2_send: Some(true),
            },
        };
        let descriptors = [desc1, desc1, desc1, desc1, desc1, desc1];
        {
            let mut get_regs_status = PartitionInfoGetRegsStatus::new();
            get_regs_status.info_tag = PartitionInfoGetRegsStatus::INFO_TAG;
            let error = PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                true,
            );

            assert!(error.is_err_and(|e| e == Error::InvalidInformationTag));
        }

        {
            let mut get_regs_status = PartitionInfoGetRegsStatus::new();
            PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                true,
            )
            .unwrap();

            assert_eq!(
                get_regs_status.info_tag,
                PartitionInfoGetRegsStatus::INFO_TAG
            );
            assert_eq!(
                usize::from(get_regs_status.current_index),
                PartitionInfoGetRegsStatus::REGS_STEP - 1
            );
            get_regs_status.info_tag = !PartitionInfoGetRegsStatus::INFO_TAG;
            let error = PartitionInfo::pack_in_regs(
                version,
                &descriptors,
                &mut get_regs_status,
                &mut output_regs,
                true,
            );
            assert!(error.is_err_and(|e| e == Error::InvalidInformationTag));
        }
    }

    #[test]
    fn info_get_regs_info_conversion() {
        let mut info_get_regs = PartitionInfoGetRegsStatus::new();
        info_get_regs.last_index = 12;
        info_get_regs.current_index = 14;
        info_get_regs.info_tag = 9;

        let translate_value: u64 = (24 << 48) | (9 << 32) | (14 << 16) | 12;
        assert_eq!(u64::from(info_get_regs), translate_value);
    }
}
