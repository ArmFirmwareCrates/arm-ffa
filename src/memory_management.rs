// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec::Vec;

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

/// FF-A v1.1: Table 10.18: Memory region attributes descriptor
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

/// FF-A v1.1: Table 10.15: Memory access permissions descriptor
#[derive(Debug, Default, Clone, Copy)]
pub struct MemAccessPermDesc {
    pub endpoint_id: u16,
    pub instr_access: InstuctionAccessPerm,
    pub data_access: DataAccessPerm,
    pub flags: u8, // TODO
}

/// FF-A v1.1 Table 10.16: Endpoint memory access descriptor
#[derive(Debug, Default, Clone, Copy)]
pub struct EndpointMemAccessDesc {
    pub mem_access_perm: MemAccessPermDesc,
    pub composite_offset: u32,
}

impl EndpointMemAccessDesc {
    const SIZE: usize = 16;
}

/// FF-A v1.1 Table 10.21: Flags usage in FFA_MEM_DONATE, FFA_MEM_LEND and FFA_MEM_SHARE ABIs
/// FF-A v1.1 Table 10.22: Flags usage in FFA_MEM_RETRIEVE_REQ ABI
/// FF-A v1.1 Table 10.23: Flags usage in FFA_MEM_RETRIEVE_RESP ABI
#[derive(Debug, Default, Clone, Copy)]
pub struct MemTransactionFlags(pub u32); // TODO: use bitflags?

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

/// FF-A v1.1: Table 10.20: Memory transaction descriptor
#[derive(Debug, Default)]
pub struct MemTransactionDesc {
    pub sender_id: u16,
    pub mem_region_attr: MemRegionAttributes,
    pub flags: MemTransactionFlags,
    pub handle: Handle,
    pub tag: u64, // TODO
    pub ep_access_descs: Vec<EndpointMemAccessDesc>,
}

/// FF-A v1.1 Table 10.13: Composite memory region descriptor
#[derive(Debug, Default)]
pub struct CompositeMemRegionDesc {
    pub total_page_cnt: u32,
    pub constituents: Vec<ConstituentMemRegionDesc>,
}

impl CompositeMemRegionDesc {
    const CONSTITUENT_ARRAY_OFFSET: usize = 16;
}

/// FF-A v1.1 Table 10.14: Constituent memory region descriptor
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstituentMemRegionDesc {
    pub address: u64,
    pub page_cnt: u32,
}

impl ConstituentMemRegionDesc {
    const SIZE: usize = 16;
}

impl MemTransactionDesc {
    // Must be 16 byte aligned
    const ENDPOINT_MEM_ACCESS_DESC_OFFSET: usize = 48;

    pub fn create(&self, composite_desc: &CompositeMemRegionDesc, buf: &mut [u8]) -> usize {
        let mem_access_desc_cnt = self.ep_access_descs.len();
        let composite_offset = (Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET
            + mem_access_desc_cnt * EndpointMemAccessDesc::SIZE)
            .next_multiple_of(8);

        // Offset 0, length 2: ID of the Owner endpoint.
        buf[0..2].copy_from_slice(&self.sender_id.to_le_bytes());

        // Offset 2, length 2: Memory region attributes
        let mem_reg_attr = u16::from(self.mem_region_attr);
        buf[2..4].copy_from_slice(&mem_reg_attr.to_le_bytes());

        // Offset 4, length 4: Flags
        buf[4..8].copy_from_slice(&self.flags.0.to_le_bytes());

        // Offset 8, length 8: Handle
        buf[8..16].copy_from_slice(&self.handle.0.to_le_bytes());

        // Offset 16, length 8: Tag
        buf[16..24].copy_from_slice(&self.tag.to_le_bytes());

        // Offset 24, length 4: Size of each endpoint memory access descriptor in the array.
        buf[24..28].copy_from_slice(&(EndpointMemAccessDesc::SIZE as u32).to_le_bytes());

        // Offset 28, length 4: Count of endpoint memory access descriptors.
        buf[28..32].copy_from_slice(&(mem_access_desc_cnt as u32).to_le_bytes());

        // Offset 32, length 4: 16-byte aligned offset from the base address of this descriptor to the first element of the Endpoint memory access descriptor array.
        buf[32..36].copy_from_slice(&(Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET as u32).to_le_bytes());

        let mut offset = Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET;
        for desc in &self.ep_access_descs {
            // Offset 0, length 4: Memory access permissions descriptor
            // Offset 0, length 2: 16-bit ID of endpoint to which the memory access permissions apply
            buf[offset..offset + 2]
                .copy_from_slice(&desc.mem_access_perm.endpoint_id.to_le_bytes());

            // Offset 2, length 1: Permissions used to access a memory region.
            buf[offset + 2] =
                desc.mem_access_perm.data_access as u8 | desc.mem_access_perm.instr_access as u8;

            // Offset 3, length 1: ABI specific flags
            buf[offset + 2] = desc.mem_access_perm.flags;

            // Offset 4, length 4: Offset to the composite memory region descriptor to which the endpoint access permissions apply
            buf[offset + 4..offset + 8].copy_from_slice(&(composite_offset as u32).to_le_bytes());

            // Offset 8, length 8: Reserved (MBZ)
            buf[offset + 8..offset + 16].fill(0);

            offset += EndpointMemAccessDesc::SIZE;
        }

        offset = composite_offset;
        // Offset 0, length 4: Size of the memory region described as the count of 4K pages
        buf[offset..offset + 4].copy_from_slice(&composite_desc.total_page_cnt.to_le_bytes());

        // Offset 4, length 4: Count of address ranges specified using constituent memory region descriptors
        let addr_range_cnt = composite_desc.constituents.len() as u32;
        buf[offset + 4..offset + 8].copy_from_slice(&addr_range_cnt.to_le_bytes());

        // Offset 8, length 8: Reserved (MBZ)
        buf[offset + 8..offset + 16].fill(0);

        offset = composite_offset + CompositeMemRegionDesc::CONSTITUENT_ARRAY_OFFSET;
        for constituent in &composite_desc.constituents {
            // Offset 0, length 8: Base VA, PA or IPA of constituent memory region aligned to the page size (4K) granularity.
            buf[offset..offset + 8].copy_from_slice(&constituent.address.to_le_bytes());

            // Offset 8, length 4: Number of 4K pages in constituent memory region
            buf[offset + 8..offset + 12].copy_from_slice(&constituent.page_cnt.to_le_bytes());

            // Offset 12, length 4: Reserved (MBZ)
            buf[offset + 12..offset + 16].fill(0);

            offset += ConstituentMemRegionDesc::SIZE;
        }

        offset
    }

    pub fn parse(
        &mut self,
        composite_desc: &mut CompositeMemRegionDesc,
        buf: &[u8],
    ) -> Result<(), ()> {
        // Offset 0, length 2: ID of the Owner endpoint.
        self.sender_id = u16::from_le_bytes(buf[0..2].try_into().unwrap());

        // Offset 2, length 2: Memory region attributes
        let mem_attr = u16::from_le_bytes(buf[2..4].try_into().unwrap());
        self.mem_region_attr = MemRegionAttributes::try_from(mem_attr)?;

        // Offset 4, length 4: Flags
        self.flags.0 = u32::from_le_bytes(buf[4..8].try_into().unwrap()); // TODO: validate

        // Offset 8, length 8: Handle
        self.handle.0 = u64::from_le_bytes(buf[8..16].try_into().unwrap());

        // Offset 16, length 8: Tag
        self.tag = u64::from_le_bytes(buf[16..24].try_into().unwrap());

        // Offset 24, length 4: Size of each endpoint memory access descriptor in the array.
        let endpoint_mem_access_desc_size = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        assert_eq!(
            EndpointMemAccessDesc::SIZE,
            endpoint_mem_access_desc_size as usize
        );

        // Offset 28, length 4: Count of endpoint memory access descriptors.
        let endpoint_mem_access_desc_cnt = u32::from_le_bytes(buf[28..32].try_into().unwrap());

        // Offset 32, length 4: 16-byte aligned offset from the base address of this descriptor to
        // the first element of the Endpoint memory access descriptor array.
        let endpoint_mem_access_desc_offset = u32::from_le_bytes(buf[32..36].try_into().unwrap());

        assert!(
            endpoint_mem_access_desc_offset
                + endpoint_mem_access_desc_cnt * endpoint_mem_access_desc_size
                <= buf.len() as u32
        );

        let mut composite_offset = 0;
        let mut offset = endpoint_mem_access_desc_offset as usize;
        for _ in 0..endpoint_mem_access_desc_cnt {
            let mut desc = EndpointMemAccessDesc::default();
            desc.mem_access_perm.endpoint_id =
                u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap());

            desc.mem_access_perm.instr_access = InstuctionAccessPerm::try_from(buf[offset + 2])?;
            desc.mem_access_perm.data_access = DataAccessPerm::try_from(buf[offset + 2])?;
            desc.mem_access_perm.flags = buf[offset + 3];
            desc.composite_offset =
                u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
            // TODO: different composite offsets?
            composite_offset = desc.composite_offset as usize;

            self.ep_access_descs.push(desc);

            offset += endpoint_mem_access_desc_size as usize;
        }

        if self.handle != Handle(0) || composite_offset == 0 {
            return Ok(());
        }

        composite_desc.total_page_cnt = u32::from_le_bytes(
            buf[composite_offset..composite_offset + 4]
                .try_into()
                .unwrap(),
        );

        let addr_range_cnt = u32::from_le_bytes(
            buf[composite_offset + 4..composite_offset + 8]
                .try_into()
                .unwrap(),
        );

        offset = composite_offset + CompositeMemRegionDesc::CONSTITUENT_ARRAY_OFFSET;
        let mut total_page_cnt = 0;
        for _ in 0..addr_range_cnt {
            let desc = ConstituentMemRegionDesc {
                address: u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap()),
                page_cnt: u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap()),
            };
            total_page_cnt += desc.page_cnt;

            composite_desc.constituents.push(desc);

            offset += ConstituentMemRegionDesc::SIZE;
        }

        assert_eq!(total_page_cnt, composite_desc.total_page_cnt);

        Ok(())
    }
}

/// FF-A v1.1 Table 16.25: Descriptor to relinquish a memory region
#[derive(Debug, Default)]
pub struct MemRelinquishDesc {
    pub handle: Handle,
    pub flags: u32,
    pub endpoints: Vec<u16>,
}

impl MemRelinquishDesc {
    const ENDPOINT_ARRAY_OFFSET: usize = 16;

    pub fn parse(&mut self, buf: &[u8]) -> Result<(), ()> {
        // Offset 0, length 8: Handle
        self.handle.0 = u64::from_le_bytes(buf[0..8].try_into().unwrap());

        // Offset 8, length 4: Flags
        self.flags = u32::from_le_bytes(buf[8..12].try_into().unwrap()); // TODO: validate

        // Offset 12, length 4: Count of endpoint ID entries in the Endpoint array
        let endpoint_cnt = u32::from_le_bytes(buf[12..16].try_into().unwrap());

        let mut offset = MemRelinquishDesc::ENDPOINT_ARRAY_OFFSET;
        for _ in 0..endpoint_cnt as usize {
            let endpoint = u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap());
            self.endpoints.push(endpoint);
            offset += 2;
        }

        Ok(())
    }
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

    #[test]
    fn mem_share() {
        let mut transaction_desc = MemTransactionDesc::default();
        let mut composite_desc = CompositeMemRegionDesc::default();

        transaction_desc
            .parse(&mut composite_desc, MEM_RETRIEVE_REQ_FROM_SP1)
            .unwrap();

        println!("transaction desc: {:#x?}", transaction_desc);
        println!("endpont desc: {:#x?}", transaction_desc.ep_access_descs);
        println!("composite desc: {:#x?}", composite_desc);
        println!("constituent desc: {:#x?}", composite_desc.constituents);
    }
}
