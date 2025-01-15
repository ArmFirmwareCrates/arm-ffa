// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ffa_v1_1::{
    composite_memory_region_descriptor, constituent_memory_region_descriptor,
    endpoint_memory_access_descriptor, memory_access_permission_descriptor,
    memory_relinquish_descriptor, memory_transaction_descriptor,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handle(pub u64);

impl From<[u32; 2]> for Handle {
    fn from(value: [u32; 2]) -> Self {
        Self((value[1] as u64) << 32 | value[0] as u64)
    }
}

impl From<Handle> for [u32; 2] {
    fn from(value: Handle) -> Self {
        [value.0 as u32, (value.0 >> 32) as u32]
    }
}

impl Handle {
    pub const INVALID: u64 = 0xffff_ffff_ffff_ffff;
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum Cacheability {
    #[default]
    NonCacheable = Self::NON_CACHEABLE << Self::SHIFT,
    WriteBack = Self::WRITE_BACK << Self::SHIFT,
}

impl TryFrom<u16> for Cacheability {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NON_CACHEABLE => Ok(Cacheability::NonCacheable),
            Self::WRITE_BACK => Ok(Cacheability::WriteBack),
            _ => Err(()),
        }
    }
}

impl Cacheability {
    const SHIFT: usize = 2;
    const MASK: u16 = 0b11;
    const NON_CACHEABLE: u16 = 0b01;
    const WRITE_BACK: u16 = 0b11;
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum Shareability {
    #[default]
    NonShareable = Self::NON_SHAREABLE << Self::SHIFT,
    Outer = Self::OUTER << Self::SHIFT,
    Inner = Self::INNER << Self::SHIFT,
}

impl TryFrom<u16> for Shareability {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NON_SHAREABLE => Ok(Self::NonShareable),
            Self::OUTER => Ok(Self::Outer),
            Self::INNER => Ok(Self::Inner),
            _ => Err(()),
        }
    }
}

impl Shareability {
    const SHIFT: usize = 0;
    const MASK: u16 = 0b11;
    const NON_SHAREABLE: u16 = 0b00;
    const OUTER: u16 = 0b10;
    const INNER: u16 = 0b11;
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(u16)]
pub enum DeviceMemAttributes {
    #[default]
    DevnGnRnE = Self::DEV_NGNRNE << Self::SHIFT,
    DevnGnRE = Self::DEV_NGNRE << Self::SHIFT,
    DevnGRE = Self::DEV_NGRE << Self::SHIFT,
    DevGRE = Self::DEV_GRE << Self::SHIFT,
}

impl TryFrom<u16> for DeviceMemAttributes {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // TODO: sanity check if it's device memory
        match (value >> Self::SHIFT) & Self::MASK {
            Self::DEV_NGNRNE => Ok(Self::DevnGnRnE),
            Self::DEV_NGNRE => Ok(Self::DevnGnRE),
            Self::DEV_NGRE => Ok(Self::DevnGRE),
            Self::DEV_GRE => Ok(Self::DevGRE),
            _ => Err(()),
        }
    }
}

impl DeviceMemAttributes {
    const SHIFT: usize = 2;
    const MASK: u16 = 0b11;
    const DEV_NGNRNE: u16 = 0b00;
    const DEV_NGNRE: u16 = 0b01;
    const DEV_NGRE: u16 = 0b10;
    const DEV_GRE: u16 = 0b11;
}

#[derive(Debug, Default, Clone, Copy)]
pub enum MemType {
    #[default]
    NotSpecified,
    Device(DeviceMemAttributes),
    Normal {
        cacheability: Cacheability,
        shareability: Shareability,
    },
}

impl TryFrom<u16> for MemType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NOT_SPECIFIED => Ok(Self::NotSpecified),
            Self::DEVICE => Ok(Self::Device(DeviceMemAttributes::try_from(value)?)),
            Self::NORMAL => Ok(Self::Normal {
                cacheability: Cacheability::try_from(value)?,
                shareability: Shareability::try_from(value)?,
            }),
            _ => Err(()),
        }
    }
}

impl From<MemType> for u16 {
    fn from(value: MemType) -> Self {
        match value {
            MemType::NotSpecified => MemType::NOT_SPECIFIED << MemType::SHIFT,
            MemType::Device(attr) => attr as u16 | MemType::DEVICE << MemType::SHIFT,
            MemType::Normal {
                cacheability,
                shareability,
            } => cacheability as u16 | shareability as u16 | MemType::NORMAL << MemType::SHIFT,
        }
    }
}

impl MemType {
    const SHIFT: usize = 4;
    const MASK: u16 = 0b11;
    const NOT_SPECIFIED: u16 = 0b00;
    const DEVICE: u16 = 0b01;
    const NORMAL: u16 = 0b10;
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum MemRegionSecurity {
    #[default]
    Secure = Self::SECURE << Self::SHIFT,
    NonSecure = Self::NON_SECURE << Self::SHIFT,
}

impl TryFrom<u16> for MemRegionSecurity {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::SECURE => Ok(Self::Secure),
            Self::NON_SECURE => Ok(Self::NonSecure),
            _ => Err(()),
        }
    }
}

impl MemRegionSecurity {
    const SHIFT: usize = 6;
    const MASK: u16 = 0b1;
    const SECURE: u16 = 0b0;
    const NON_SECURE: u16 = 0b1;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MemRegionAttributes {
    pub security: MemRegionSecurity,
    pub mem_type: MemType,
}

impl TryFrom<u16> for MemRegionAttributes {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // bits[15:7]: Reserved (MBZ)
        assert_eq!(value >> 7, 0);
        Ok(Self {
            security: MemRegionSecurity::try_from(value)?,
            mem_type: MemType::try_from(value)?,
        })
    }
}

impl From<MemRegionAttributes> for u16 {
    fn from(value: MemRegionAttributes) -> Self {
        value.security as u16 | u16::from(value.mem_type)
    }
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(u8)]
pub enum InstuctionAccessPerm {
    #[default]
    NotSpecified = Self::NOT_SPECIFIED << Self::SHIFT,
    NotExecutable = Self::NOT_EXECUTABLE << Self::SHIFT,
    Executable = Self::EXECUTABLE << Self::SHIFT,
}

impl TryFrom<u8> for InstuctionAccessPerm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NOT_SPECIFIED => Ok(Self::NotSpecified),
            Self::NOT_EXECUTABLE => Ok(Self::NotExecutable),
            Self::EXECUTABLE => Ok(Self::Executable),
            _ => Err(()),
        }
    }
}

impl InstuctionAccessPerm {
    const SHIFT: usize = 2;
    const MASK: u8 = 0b11;
    const NOT_SPECIFIED: u8 = 0b00;
    const NOT_EXECUTABLE: u8 = 0b01;
    const EXECUTABLE: u8 = 0b10;
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(u8)]
pub enum DataAccessPerm {
    #[default]
    NotSpecified = Self::NOT_SPECIFIED << Self::SHIFT,
    ReadOnly = Self::READ_ONLY << Self::SHIFT,
    ReadWrite = Self::READ_WRITE << Self::SHIFT,
}

impl TryFrom<u8> for DataAccessPerm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NOT_SPECIFIED => Ok(Self::NotSpecified),
            Self::READ_ONLY => Ok(Self::ReadOnly),
            Self::READ_WRITE => Ok(Self::ReadWrite),
            _ => Err(()),
        }
    }
}

impl DataAccessPerm {
    const SHIFT: usize = 0;
    const MASK: u8 = 0b11;
    const NOT_SPECIFIED: u8 = 0b00;
    const READ_ONLY: u8 = 0b01;
    const READ_WRITE: u8 = 0b10;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MemAccessPermDesc {
    pub endpoint_id: u16,
    pub instr_access: InstuctionAccessPerm,
    pub data_access: DataAccessPerm,
    pub flags: u8, // TODO
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EndpointMemAccessDesc {
    pub mem_access_perm: MemAccessPermDesc,
    pub composite_offset: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MemTransactionFlags(pub u32);

#[allow(dead_code)]
impl MemTransactionFlags {
    const MEM_SHARE_MASK: u32 = 0b11;
    const MEM_RETRIEVE_REQ_MASK: u32 = 0b11_1111_1111;
    const MEM_RETRIEVE_RESP_MASK: u32 = 0b1_1111;
    const ZERO_MEMORY: u32 = 0b1;
    const TIME_SLICING: u32 = 0b1 << 1;
    const ZERO_AFTER_RELINQ: u32 = 0b1 << 2;
    pub const TYPE_SHARE: u32 = 0b01 << 3;
    const TYPE_LEND: u32 = 0b10 << 3;
    const TYPE_DONATE: u32 = 0b11 << 3;
    const ALIGN_HINT_MASK: u32 = 0b1111 << 5;
    const HINT_VALID: u32 = 0b1 << 9;
}

#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct CompositeMemRegionDesc {
    pub total_page_cnt: u32,
    pub constituents: Vec<ConstituentMemRegionDesc>,
}

#[cfg(feature = "alloc")]
impl CompositeMemRegionDesc {
    const CONSTITUENT_ARRAY_OFFSET: usize = 16;
}

#[cfg(feature = "alloc")]
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstituentMemRegionDesc {
    pub address: u64,
    pub page_cnt: u32,
}

#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct MemTransactionDesc {
    pub sender_id: u16,
    pub mem_region_attr: MemRegionAttributes,
    pub flags: MemTransactionFlags,
    pub handle: Handle,
    pub tag: u64, // TODO
    pub ep_access_descs: Vec<EndpointMemAccessDesc>,
}

#[cfg(feature = "alloc")]
impl MemTransactionDesc {
    // Offset from the base of the memory transaction descriptor to the first element in the
    // endpoint memory access descriptor array. Must be 16 byte aligned, but otherwise we're free to
    // choose any value here. Let's just pack it right after the memory transaction descriptor.
    const ENDPOINT_MEM_ACCESS_DESC_OFFSET: usize =
        core::mem::size_of::<memory_transaction_descriptor>().next_multiple_of(16);

    pub fn pack(&self, composite_desc: &CompositeMemRegionDesc, buf: &mut [u8]) -> usize {
        let mem_access_desc_size = core::mem::size_of::<endpoint_memory_access_descriptor>();
        let mem_access_desc_cnt = self.ep_access_descs.len();

        let transaction_desc_raw = memory_transaction_descriptor {
            sender_endpoint_id: self.sender_id,
            memory_region_attributes: self.mem_region_attr.into(),
            flags: self.flags.0,
            handle: self.handle.0,
            tag: self.tag,
            endpoint_mem_access_desc_size: mem_access_desc_size as u32,
            endpoint_mem_access_desc_count: mem_access_desc_cnt as u32,
            endpoint_mem_access_desc_array_offset: Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET as u32,
            reserved1: 0,
            reserved2: 0,
        };

        transaction_desc_raw.write_to_prefix(buf).unwrap();

        // Offset from the base of the memory transaction descriptor to the composite memory region
        // descriptor to which the endpoint access permissions apply.
        let composite_offset = (Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET
            + mem_access_desc_cnt * mem_access_desc_size)
            .next_multiple_of(8);

        let mut offset = Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET;

        for desc in &self.ep_access_descs {
            let desc_raw = endpoint_memory_access_descriptor {
                access_perm_desc: memory_access_permission_descriptor {
                    endpoint_id: desc.mem_access_perm.endpoint_id,
                    memory_access_permissions: desc.mem_access_perm.data_access as u8
                        | desc.mem_access_perm.instr_access as u8,
                    flags: desc.mem_access_perm.flags,
                },
                composite_offset: composite_offset as u32,
                reserved: 0,
            };

            desc_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += mem_access_desc_size;
        }

        offset = composite_offset;

        let composite_desc_raw = composite_memory_region_descriptor {
            total_page_count: composite_desc.total_page_cnt,
            address_range_count: composite_desc.constituents.len() as u32,
            reserved: 0,
        };

        composite_desc_raw
            .write_to_prefix(&mut buf[offset..])
            .unwrap();

        offset = composite_offset + CompositeMemRegionDesc::CONSTITUENT_ARRAY_OFFSET;
        for constituent in &composite_desc.constituents {
            let constituent_raw = constituent_memory_region_descriptor {
                address: constituent.address,
                page_count: constituent.page_cnt,
                reserved: 0,
            };

            constituent_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += core::mem::size_of::<constituent_memory_region_descriptor>();
        }

        offset
    }

    pub fn unpack(
        &mut self,
        composite_desc: &mut CompositeMemRegionDesc,
        buf: &[u8],
    ) -> Result<(), ()> {
        let transaction_desc_raw = memory_transaction_descriptor::ref_from_bytes(
            &buf[0..core::mem::size_of::<memory_transaction_descriptor>()],
        )
        .unwrap();

        self.sender_id = transaction_desc_raw.sender_endpoint_id;
        self.mem_region_attr =
            MemRegionAttributes::try_from(transaction_desc_raw.memory_region_attributes)?;
        self.flags.0 = transaction_desc_raw.flags;
        self.handle.0 = transaction_desc_raw.handle;
        self.tag = transaction_desc_raw.tag;

        let endpoint_mem_access_desc_size =
            transaction_desc_raw.endpoint_mem_access_desc_size as usize;
        let endpoint_mem_access_desc_cnt =
            transaction_desc_raw.endpoint_mem_access_desc_count as usize;
        let endpoint_mem_access_desc_offset =
            transaction_desc_raw.endpoint_mem_access_desc_array_offset as usize;

        assert_eq!(
            core::mem::size_of::<endpoint_memory_access_descriptor>(),
            endpoint_mem_access_desc_size
        );

        assert!(
            endpoint_mem_access_desc_offset
                + endpoint_mem_access_desc_cnt * endpoint_mem_access_desc_size
                <= buf.len()
        );

        let mut composite_offset = 0;
        let mut offset = endpoint_mem_access_desc_offset;

        for _ in 0..endpoint_mem_access_desc_cnt {
            let desc_raw = endpoint_memory_access_descriptor::ref_from_bytes(
                &buf[offset..offset + endpoint_mem_access_desc_size],
            )
            .unwrap();

            let desc = EndpointMemAccessDesc {
                mem_access_perm: MemAccessPermDesc {
                    endpoint_id: desc_raw.access_perm_desc.endpoint_id,
                    instr_access: desc_raw
                        .access_perm_desc
                        .memory_access_permissions
                        .try_into()?,
                    data_access: desc_raw
                        .access_perm_desc
                        .memory_access_permissions
                        .try_into()?,
                    flags: desc_raw.access_perm_desc.flags,
                },
                composite_offset: desc_raw.composite_offset,
            };
            self.ep_access_descs.push(desc);

            // TODO: what to do if composite offset differs in the endpoint access descriptors?
            composite_offset = desc_raw.composite_offset as usize;
            offset += endpoint_mem_access_desc_size;
        }

        if self.handle != Handle(0) || composite_offset == 0 {
            return Ok(());
        }

        let composite_desc_raw = composite_memory_region_descriptor::ref_from_bytes(
            &buf[composite_offset
                ..composite_offset + core::mem::size_of::<composite_memory_region_descriptor>()],
        )
        .unwrap();

        composite_desc.total_page_cnt = composite_desc_raw.total_page_count;

        offset = composite_offset + CompositeMemRegionDesc::CONSTITUENT_ARRAY_OFFSET;
        let mut total_page_cnt = 0;
        for _ in 0..composite_desc_raw.address_range_count {
            let desc_raw = constituent_memory_region_descriptor::read_from_bytes(
                &buf[offset..offset + core::mem::size_of::<constituent_memory_region_descriptor>()],
            )
            .unwrap();

            let desc = ConstituentMemRegionDesc {
                address: desc_raw.address,
                page_cnt: desc_raw.page_count,
            };
            total_page_cnt += desc.page_cnt;

            composite_desc.constituents.push(desc);

            offset += core::mem::size_of::<constituent_memory_region_descriptor>();
        }

        assert_eq!(total_page_cnt, composite_desc.total_page_cnt);

        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct MemRelinquishDesc {
    pub handle: Handle,
    pub flags: u32,
    pub endpoints: Vec<u16>,
}

#[cfg(feature = "alloc")]
impl TryFrom<&[u8]> for MemRelinquishDesc {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let desc_raw = memory_relinquish_descriptor::ref_from_bytes(
            &value[0..core::mem::size_of::<memory_relinquish_descriptor>()],
        )
        .unwrap();

        let mut desc = Self {
            handle: Handle(desc_raw.handle),
            flags: desc_raw.flags, // TODO: validate
            endpoints: Vec::new(),
        };

        let mut offset = MemRelinquishDesc::ENDPOINT_ARRAY_OFFSET;
        for _ in 0..desc_raw.endpoint_count {
            let endpoint = u16::from_le_bytes([value[offset], value[offset + 1]]);
            desc.endpoints.push(endpoint);
            offset += 2;
        }

        Ok(desc)
    }
}

#[cfg(feature = "alloc")]
impl MemRelinquishDesc {
    const ENDPOINT_ARRAY_OFFSET: usize = 16;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    const MEM_SHARE_FROM_SP1: &[u8] = &[
        0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[allow(dead_code)]
    const MEM_SHARE_FROM_SP2: &[u8] = &[
        0x06, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x80, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x07, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[allow(dead_code)]
    const MEM_RETRIEVE_REQ_FROM_SP1: &[u8] = &[
        0x05, 0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[allow(dead_code)]
    const MEM_RETRIEVE_REQ_FROM_SP2: &[u8] = &[
        0x06, 0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[allow(dead_code)]
    const MEM_SHARE_FROM_NWD: &[u8] = &[
        0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x22, 0x80, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[cfg(feature = "alloc")]
    #[test]
    fn mem_share() {
        let mut transaction_desc = MemTransactionDesc::default();
        let mut composite_desc = CompositeMemRegionDesc::default();

        transaction_desc
            .unpack(&mut composite_desc, MEM_RETRIEVE_REQ_FROM_SP1)
            .unwrap();

        println!("transaction desc: {:#x?}", transaction_desc);
        println!("endpont desc: {:#x?}", transaction_desc.ep_access_descs);
        println!("composite desc: {:#x?}", composite_desc);
        println!("constituent desc: {:#x?}", composite_desc.constituents);
    }
}
