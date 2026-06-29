// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Implementation of the FF-A Memory Management protocol.
//!
//! FF-A describes mechanisms and interfaces that enable FF-A components to manage access and
//! ownership of memory regions in the physical address space. FF-A components can use a combination
//! of Framework and Partition messages to manage memory regions in the following ways:
//! - The Owner of a memory region can transfer its ownership to another FF-A endpoint.
//! - The Owner of a memory region can transfer its access to one or more FF-A endpoints.
//! - The Owner of a memory region can share access to it with one or more FF-A endpoints.
//! - The Owner can reclaim access to a memory region after the FF-A endpoints that were granted
//!   access to that memory region have relinquished their access.

use crate::{
    ffa_v1_3::{
        composite_memory_region_descriptor, constituent_memory_region_descriptor,
        endpoint_memory_access_descriptor, memory_access_permission_descriptor,
        memory_relinquish_descriptor, memory_transaction_descriptor,
    },
    interface_args::SuccessArgs,
};
use core::mem::size_of;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

/// Rich error types returned by this module. Should be converted to [`crate::FfaError`] when used
/// with the `FFA_ERROR` interface.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    #[error("Invalid cacheability attribute {0}")]
    InvalidCacheability(u16),
    #[error("Invalid shareability attribute {0}")]
    InvalidShareability(u16),
    #[error("Invalid device memory attributes {0}")]
    InvalidDevMemAttributes(u16),
    #[error("Invalid instruction access permission {0}")]
    InvalidInstrAccessPerm(u8),
    #[error("Invalid instruction data permission {0}")]
    InvalidDataAccessPerm(u8),
    #[error("Invalid memory type {0}")]
    InvalidMemType(u16),
    #[error("Invalid memory attributes {0}")]
    InvalidMemAttributes(u16),
    #[error("Composite offset mismatch")]
    CompositeOffsetMismatch,
    #[error("Invalid endpoint count {0}")]
    UnsupportedEndpointCount(u32),
    #[error("Invalid buffer size")]
    InvalidBufferSize,
    #[error("Malformed descriptor")]
    MalformedDescriptor,
    #[error("Invalid get/set instruction access permission {0}")]
    InvalidInstrAccessPermGetSet(u32),
    #[error("Invalid get/set instruction data permission {0}")]
    InvalidDataAccessPermGetSet(u32),
    #[error("Invalid page count")]
    InvalidPageCount,
    #[error("Invalid memory reclaim flags {0}")]
    InvalidMemReclaimFlags(u32),
}

impl From<Error> for crate::FfaError {
    fn from(_value: Error) -> Self {
        Self::InvalidParameters
    }
}

/// Memory region handle, used to identify a composite memory region description.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handle(pub u64);

impl From<[u32; 2]> for Handle {
    fn from(value: [u32; 2]) -> Self {
        Self(((value[1] as u64) << 32) | value[0] as u64)
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

/// Cacheability attribute of a memory region. Only valid for normal memory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Cacheability {
    #[default]
    NonCacheable = Self::NON_CACHEABLE << Self::SHIFT,
    WriteBack = Self::WRITE_BACK << Self::SHIFT,
}

impl TryFrom<u16> for Cacheability {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NON_CACHEABLE => Ok(Cacheability::NonCacheable),
            Self::WRITE_BACK => Ok(Cacheability::WriteBack),
            _ => Err(Error::InvalidCacheability(value)),
        }
    }
}

impl Cacheability {
    const SHIFT: usize = 2;
    const MASK: u16 = 0b11;
    const NON_CACHEABLE: u16 = 0b01;
    const WRITE_BACK: u16 = 0b11;
}

/// Shareability attribute of a memory region. Only valid for normal memory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Shareability {
    #[default]
    NonShareable = Self::NON_SHAREABLE << Self::SHIFT,
    Outer = Self::OUTER << Self::SHIFT,
    Inner = Self::INNER << Self::SHIFT,
}

impl TryFrom<u16> for Shareability {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NON_SHAREABLE => Ok(Self::NonShareable),
            Self::OUTER => Ok(Self::Outer),
            Self::INNER => Ok(Self::Inner),
            _ => Err(Error::InvalidShareability(value)),
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

/// Device memory attributes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DeviceMemAttributes {
    #[default]
    DevnGnRnE = Self::DEV_NGNRNE << Self::SHIFT,
    DevnGnRE = Self::DEV_NGNRE << Self::SHIFT,
    DevnGRE = Self::DEV_NGRE << Self::SHIFT,
    DevGRE = Self::DEV_GRE << Self::SHIFT,
}

impl TryFrom<u16> for DeviceMemAttributes {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::DEV_NGNRNE => Ok(Self::DevnGnRnE),
            Self::DEV_NGNRE => Ok(Self::DevnGnRE),
            Self::DEV_NGRE => Ok(Self::DevnGRE),
            Self::DEV_GRE => Ok(Self::DevGRE),
            _ => Err(Error::InvalidDevMemAttributes(value)),
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

/// Memory region type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NOT_SPECIFIED => Ok(Self::NotSpecified),
            Self::DEVICE => Ok(Self::Device(value.try_into()?)),
            Self::NORMAL => Ok(Self::Normal {
                cacheability: value.try_into()?,
                shareability: value.try_into()?,
            }),
            _ => Err(Error::InvalidMemType(value)),
        }
    }
}

impl From<MemType> for u16 {
    fn from(value: MemType) -> Self {
        match value {
            MemType::NotSpecified => MemType::NOT_SPECIFIED << MemType::SHIFT,
            MemType::Device(attr) => attr as u16 | (MemType::DEVICE << MemType::SHIFT),
            MemType::Normal {
                cacheability,
                shareability,
            } => cacheability as u16 | shareability as u16 | (MemType::NORMAL << MemType::SHIFT),
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

/// Memory region security attribute.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MemRegionSecurity {
    #[default]
    Secure = Self::SECURE << Self::SHIFT,
    NonSecure = Self::NON_SECURE << Self::SHIFT,
}

impl From<u16> for MemRegionSecurity {
    fn from(value: u16) -> Self {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::SECURE => Self::Secure,
            Self::NON_SECURE => Self::NonSecure,
            _ => panic!(), // The match is exhaustive for a 1-bit value
        }
    }
}

impl MemRegionSecurity {
    const SHIFT: usize = 6;
    const MASK: u16 = 0b1;
    const SECURE: u16 = 0b0;
    const NON_SECURE: u16 = 0b1;
}

/// Memory region attributes descriptor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MemRegionAttributes {
    pub security: MemRegionSecurity,
    pub mem_type: MemType,
}

impl TryFrom<u16> for MemRegionAttributes {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // bits[15:7]: Reserved (MBZ)
        if value >> 7 == 0 {
            Ok(Self {
                security: value.into(),
                mem_type: value.try_into()?,
            })
        } else {
            Err(Error::InvalidMemAttributes(value))
        }
    }
}

impl From<MemRegionAttributes> for u16 {
    fn from(value: MemRegionAttributes) -> Self {
        value.security as u16 | u16::from(value.mem_type)
    }
}

/// Instruction access permissions of a memory region.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InstuctionAccessPerm {
    #[default]
    NotSpecified = Self::NOT_SPECIFIED << Self::SHIFT,
    NotExecutable = Self::NOT_EXECUTABLE << Self::SHIFT,
    Executable = Self::EXECUTABLE << Self::SHIFT,
}

impl TryFrom<u8> for InstuctionAccessPerm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NOT_SPECIFIED => Ok(Self::NotSpecified),
            Self::NOT_EXECUTABLE => Ok(Self::NotExecutable),
            Self::EXECUTABLE => Ok(Self::Executable),
            _ => Err(Error::InvalidInstrAccessPerm(value)),
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

/// Data access permissions of a memory region.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataAccessPerm {
    #[default]
    NotSpecified = Self::NOT_SPECIFIED << Self::SHIFT,
    ReadOnly = Self::READ_ONLY << Self::SHIFT,
    ReadWrite = Self::READ_WRITE << Self::SHIFT,
}

impl TryFrom<u8> for DataAccessPerm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NOT_SPECIFIED => Ok(Self::NotSpecified),
            Self::READ_ONLY => Ok(Self::ReadOnly),
            Self::READ_WRITE => Ok(Self::ReadWrite),
            _ => Err(Error::InvalidDataAccessPerm(value)),
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

/// Endpoint memory access permissions descriptor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MemAccessPerm {
    pub endpoint_id: u16,
    pub instr_access: InstuctionAccessPerm,
    pub data_access: DataAccessPerm,
    pub flags: u8, // TODO
}

/// Constituent memory region descriptor.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct ConstituentMemRegion {
    pub address: u64,
    pub page_cnt: u32,
}

/// Flags of a memory management transaction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MemTransactionFlags(pub u32);

impl MemTransactionFlags {
    pub const MEM_SHARE_MASK: u32 = 0b11;
    pub const MEM_RETRIEVE_REQ_MASK: u32 = 0b11_1111_1111;
    pub const MEM_RETRIEVE_RESP_MASK: u32 = 0b1_1111;
    pub const ZERO_MEMORY: u32 = 0b1;
    pub const TIME_SLICING: u32 = 0b1 << 1;
    pub const ZERO_AFTER_RELINQ: u32 = 0b1 << 2;
    pub const TYPE_SHARE: u32 = 0b01 << 3;
    pub const TYPE_LEND: u32 = 0b10 << 3;
    pub const TYPE_DONATE: u32 = 0b11 << 3;
    pub const ALIGN_HINT_MASK: u32 = 0b1111 << 5;
    pub const HINT_VALID: u32 = 0b1 << 9;
}

/// Memory transaction decriptor. Used by an Owner/Lender and a Borrower/Receiver in a transaction
/// to donate, lend or share a memory region.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemTransactionDesc {
    pub sender_id: u16,
    pub mem_region_attr: MemRegionAttributes,
    pub flags: MemTransactionFlags,
    pub handle: Handle,
    pub tag: u64, // TODO
}

impl MemTransactionDesc {
    // Offset from the base of the memory transaction descriptor to the first element in the
    // endpoint memory access descriptor array. Must be 16 byte aligned, but otherwise we're free to
    // choose any value here. Let's just pack it right after the memory transaction descriptor.
    const ENDPOINT_MEM_ACCESS_DESC_OFFSET: usize =
        size_of::<memory_transaction_descriptor>().next_multiple_of(16);

    // The array of constituent memory region descriptors starts right after the composite memory
    // region descriptor
    const CONSTITUENT_ARRAY_OFFSET: usize = size_of::<composite_memory_region_descriptor>();

    /// Serialize a memory transaction descriptor and the related constituent memory region
    /// descriptors and endpoint memory access permission descriptors into a buffer.
    pub fn pack(
        &self,
        constituents: &[ConstituentMemRegion],
        access_descriptors: &[MemAccessPerm],
        buf: &mut [u8],
    ) -> usize {
        let mem_access_desc_size = size_of::<endpoint_memory_access_descriptor>();
        let mem_access_desc_cnt = access_descriptors.len();

        let transaction_desc_raw = memory_transaction_descriptor {
            sender_endpoint_id: self.sender_id,
            memory_region_attributes: self.mem_region_attr.into(),
            flags: self.flags.0,
            handle: self.handle.0,
            tag: self.tag,
            endpoint_mem_access_desc_size: mem_access_desc_size as u32,
            endpoint_mem_access_desc_count: mem_access_desc_cnt as u32,
            endpoint_mem_access_desc_array_offset: Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET as u32,
            reserved: [0; 12],
        };

        transaction_desc_raw.write_to_prefix(buf).unwrap();

        // Offset from the base of the memory transaction descriptor to the composite memory region
        // descriptor to which the endpoint access permissions apply.
        let composite_offset = mem_access_desc_cnt
            .checked_mul(mem_access_desc_size)
            .unwrap()
            .checked_add(Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET)
            .unwrap()
            .next_multiple_of(8);

        let mut offset = Self::ENDPOINT_MEM_ACCESS_DESC_OFFSET;

        for desc in access_descriptors {
            let desc_raw = endpoint_memory_access_descriptor {
                access_perm_desc: memory_access_permission_descriptor {
                    endpoint_id: desc.endpoint_id,
                    memory_access_permissions: desc.data_access as u8 | desc.instr_access as u8,
                    flags: desc.flags,
                },
                composite_offset: composite_offset as u32,
                impdef_info: [0; 16],
                reserved: 0,
            };

            desc_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += mem_access_desc_size;
        }

        let mut total_page_count: u32 = 0;

        offset = composite_offset + Self::CONSTITUENT_ARRAY_OFFSET;
        for constituent in constituents {
            let constituent_raw = constituent_memory_region_descriptor {
                address: constituent.address,
                page_count: constituent.page_cnt,
                reserved: 0,
            };

            constituent_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += size_of::<constituent_memory_region_descriptor>();

            total_page_count = total_page_count
                .checked_add(constituent_raw.page_count)
                .expect("total_page_count overflow");
        }

        let composite_desc_raw = composite_memory_region_descriptor {
            total_page_count,
            address_range_count: constituents.len() as u32,
            reserved: 0,
        };

        composite_desc_raw
            .write_to_prefix(&mut buf[composite_offset..])
            .unwrap();

        offset
    }

    /// Deserialize a memory transaction descriptor from a buffer and return an interator of the
    /// related endpoint memory access permission descriptors and constituent memory region
    /// descriptors, if any.
    ///
    /// Scenarios described by the spec:
    /// - FFA_MEM_DONATE (sender, relayer):
    ///   - endpoint_mem_access_desc_count == 1
    ///   - composite_offset != 0
    /// - FFA_MEM_LEND and FFA_MEM_SHARE (sender, relayer):
    ///   - all values of composite_offset must be equal but != 0
    /// - FFA_MEM_RETRIEVE_REQ (receiver, relayer):
    ///   - each composite_offset may be different, including zero
    /// - FFA_MEM_RETRIEVE_RESP (relayer):
    ///   - as above
    ///
    /// In all cases, endpoint_mem_access_desc_count > 0
    ///
    /// TODO current implementation only covers the first case properly
    pub fn unpack<'a>(
        buf: &'a [u8],
    ) -> Result<
        (
            MemTransactionDesc,
            impl ExactSizeIterator<Item = Result<MemAccessPerm, Error>> + 'a,
            Option<impl ExactSizeIterator<Item = ConstituentMemRegion> + 'a>,
        ),
        Error,
    > {
        let (transaction_desc_raw, _) = memory_transaction_descriptor::ref_from_prefix(buf)
            .map_err(|_| Error::InvalidBufferSize)?;

        let access_array_start = transaction_desc_raw.endpoint_mem_access_desc_array_offset;
        if (access_array_start as usize) < size_of::<memory_transaction_descriptor>()
            || !access_array_start.is_multiple_of(16)
            || size_of::<endpoint_memory_access_descriptor>()
                != transaction_desc_raw.endpoint_mem_access_desc_size as usize
            || transaction_desc_raw.endpoint_mem_access_desc_count == 0
        {
            return Err(Error::MalformedDescriptor);
        }

        let access_array_end = transaction_desc_raw
            .endpoint_mem_access_desc_size
            .checked_mul(transaction_desc_raw.endpoint_mem_access_desc_count)
            .and_then(|x| x.checked_add(access_array_start))
            .ok_or(Error::InvalidBufferSize)?;

        let access_array_buf = buf
            .get(access_array_start as usize..access_array_end as usize)
            .ok_or(Error::InvalidBufferSize)?;
        let access_array = <[endpoint_memory_access_descriptor]>::ref_from_bytes_with_elems(
            access_array_buf,
            transaction_desc_raw.endpoint_mem_access_desc_count as usize,
        )
        .map_err(|_| Error::InvalidBufferSize)?;

        let transaction_desc = Self {
            sender_id: transaction_desc_raw.sender_endpoint_id,
            mem_region_attr: transaction_desc_raw.memory_region_attributes.try_into()?,
            flags: MemTransactionFlags(transaction_desc_raw.flags),
            handle: Handle(transaction_desc_raw.handle),
            tag: transaction_desc_raw.tag,
        };

        let access_desc_iter = access_array.iter().map(|desc_raw| {
            let perm_raw = &desc_raw.access_perm_desc;
            Ok(MemAccessPerm {
                endpoint_id: desc_raw.access_perm_desc.endpoint_id,
                instr_access: perm_raw.memory_access_permissions.try_into()?,
                data_access: perm_raw.memory_access_permissions.try_into()?,
                flags: desc_raw.access_perm_desc.flags,
            })
        });

        // We have to check the first endpoint memory access descriptor to get the composite offset
        // Note that we checked earlier that endpoint_mem_access_desc_count != 0
        let composite_offset = access_array[0].composite_offset;

        // An offset value of 0 indicates that the endpoint access permissions apply to a memory
        // region description identified by the Handle (i.e. there is no composite descriptor)
        if composite_offset == 0 {
            return Ok((transaction_desc, access_desc_iter, None));
        }

        let composite_desc_buf = buf
            .get(composite_offset as usize..)
            .ok_or(Error::InvalidBufferSize)?;

        let (composite_desc_raw, constituent_buf) =
            composite_memory_region_descriptor::ref_from_prefix(composite_desc_buf)
                .map_err(|_| Error::InvalidBufferSize)?;

        let (constituents, _) =
            <[constituent_memory_region_descriptor]>::ref_from_prefix_with_elems(
                constituent_buf,
                composite_desc_raw.address_range_count as usize,
            )
            .map_err(|_| Error::InvalidBufferSize)?;

        let page_count_sum = constituents
            .iter()
            .try_fold(0u32, |acc, desc| acc.checked_add(desc.page_count));
        if page_count_sum != Some(composite_desc_raw.total_page_count) {
            return Err(Error::MalformedDescriptor);
        }

        let constituent_iter = constituents.iter().map(|desc| ConstituentMemRegion {
            address: desc.address,
            page_cnt: desc.page_count,
        });

        Ok((transaction_desc, access_desc_iter, Some(constituent_iter)))
    }
}

/// Descriptor to relinquish a memory region.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct MemRelinquishDesc<'a> {
    pub handle: Handle,
    pub flags: u32,
    pub endpoints: &'a [u16],
}

impl<'a> MemRelinquishDesc<'a> {
    const ENDPOINT_ARRAY_OFFSET: usize = size_of::<memory_relinquish_descriptor>();

    /// Serialize memory relinquish descriptor and the endpoint IDs into a buffer.
    pub fn pack(&self, buf: &mut [u8]) -> usize {
        let (desc_raw, endpoint_buf) = memory_relinquish_descriptor::mut_from_prefix(buf).unwrap();
        desc_raw.handle = self.handle.0;
        desc_raw.flags = self.flags;
        desc_raw.endpoint_count = self.endpoints.len().try_into().unwrap();

        <[u16]>::mut_from_prefix_with_elems(endpoint_buf, self.endpoints.len())
            .unwrap()
            .0
            .copy_from_slice(self.endpoints);

        Self::ENDPOINT_ARRAY_OFFSET + self.endpoints.len() * 2
    }

    /// Deserialize a memory relinquish descriptor from a buffer and return an iterator to the
    /// endpoint IDs.
    pub fn unpack(buf: &'a [u8]) -> Result<Self, Error> {
        let (desc_raw, endpoint_buf) = memory_relinquish_descriptor::ref_from_prefix(buf)
            .map_err(|_| Error::InvalidBufferSize)?;

        let (endpoints, _) =
            <[u16]>::ref_from_prefix_with_elems(endpoint_buf, desc_raw.endpoint_count as usize)
                .map_err(|_| Error::InvalidBufferSize)?;

        Ok(Self {
            handle: Handle(desc_raw.handle),
            flags: desc_raw.flags, // TODO: validate
            endpoints,
        })
    }
}

/// Flags field of the FFA_MEM_RECLAIM interface.
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct MemReclaimFlags {
    pub zero_memory: bool,
    pub time_slicing: bool,
}

impl MemReclaimFlags {
    pub const ZERO_MEMORY: u32 = 0b1 << 0;
    pub const TIME_SLICING: u32 = 0b1 << 1;
    const MBZ_BITS: u32 = 0xffff_fffc;
}

impl TryFrom<u32> for MemReclaimFlags {
    type Error = Error;

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        if (val & Self::MBZ_BITS) != 0 {
            Err(Error::InvalidMemReclaimFlags(val))
        } else {
            Ok(MemReclaimFlags {
                zero_memory: val & Self::ZERO_MEMORY != 0,
                time_slicing: val & Self::TIME_SLICING != 0,
            })
        }
    }
}

impl From<MemReclaimFlags> for u32 {
    fn from(flags: MemReclaimFlags) -> Self {
        let mut bits: u32 = 0;
        if flags.zero_memory {
            bits |= MemReclaimFlags::ZERO_MEMORY;
        }
        if flags.time_slicing {
            bits |= MemReclaimFlags::TIME_SLICING;
        }
        bits
    }
}

/// Success argument structure for `FFA_MEM_DONATE`, `FFA_MEM_LEND` and `FFA_MEM_SHARE`.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct SuccessArgsMemOp {
    pub handle: Handle,
}

impl From<SuccessArgsMemOp> for SuccessArgs {
    fn from(value: SuccessArgsMemOp) -> Self {
        let [handle_lo, handle_hi]: [u32; 2] = value.handle.into();
        SuccessArgs::Args32([handle_lo, handle_hi, 0, 0, 0, 0])
    }
}

impl TryFrom<SuccessArgs> for SuccessArgsMemOp {
    type Error = crate::Error;

    fn try_from(value: SuccessArgs) -> Result<Self, Self::Error> {
        let [handle_lo, handle_hi, ..] = value.try_get_args32()?;
        Ok(Self {
            handle: [handle_lo, handle_hi].into(),
        })
    }
}

/// Data access permission enum for `FFA_MEM_PERM_GET` and `FFA_MEM_PERM_SET` calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DataAccessPermGetSet {
    NoAccess = Self::NO_ACCESS << Self::SHIFT,
    ReadWrite = Self::READ_WRITE << Self::SHIFT,
    ReadOnly = Self::READ_ONLY << Self::SHIFT,
}

impl DataAccessPermGetSet {
    const SHIFT: usize = 0;
    const MASK: u32 = 0b11;
    const NO_ACCESS: u32 = 0b00;
    const READ_WRITE: u32 = 0b01;
    const READ_ONLY: u32 = 0b11;
}

impl TryFrom<u32> for DataAccessPermGetSet {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::NO_ACCESS => Ok(Self::NoAccess),
            Self::READ_WRITE => Ok(Self::ReadWrite),
            Self::READ_ONLY => Ok(Self::ReadOnly),
            _ => Err(Error::InvalidDataAccessPermGetSet(value)),
        }
    }
}

/// Instructions access permission enum for `FFA_MEM_PERM_GET` and `FFA_MEM_PERM_SET` calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InstructionAccessPermGetSet {
    Executable = Self::EXECUTABLE << Self::SHIFT,
    NonExecutable = Self::NON_EXECUTABLE << Self::SHIFT,
}

impl InstructionAccessPermGetSet {
    const SHIFT: usize = 2;
    const MASK: u32 = 0b1;
    const EXECUTABLE: u32 = 0b0;
    const NON_EXECUTABLE: u32 = 0b1;
}

impl TryFrom<u32> for InstructionAccessPermGetSet {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::EXECUTABLE => Ok(Self::Executable),
            Self::NON_EXECUTABLE => Ok(Self::NonExecutable),
            _ => Err(Error::InvalidInstrAccessPermGetSet(value)),
        }
    }
}

/// Memory permission structure for `FFA_MEM_PERM_GET` and `FFA_MEM_PERM_SET` calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemPermissionsGetSet {
    pub data_access: DataAccessPermGetSet,
    pub instr_access: InstructionAccessPermGetSet,
}

impl TryFrom<u32> for MemPermissionsGetSet {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(Self {
            data_access: value.try_into()?,
            instr_access: value.try_into()?,
        })
    }
}

impl From<MemPermissionsGetSet> for u32 {
    fn from(value: MemPermissionsGetSet) -> Self {
        value.data_access as u32 | value.instr_access as u32
    }
}

/// Success argument structure for `FFA_MEM_PERM_GET`.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct SuccessArgsMemPermGet {
    pub perm: MemPermissionsGetSet,
    pub page_cnt: u32,
}

impl From<SuccessArgsMemPermGet> for SuccessArgs {
    fn from(value: SuccessArgsMemPermGet) -> Self {
        assert_ne!(value.page_cnt, 0);
        SuccessArgs::Args32([value.perm.into(), value.page_cnt - 1, 0, 0, 0, 0])
    }
}

impl TryFrom<SuccessArgs> for SuccessArgsMemPermGet {
    type Error = crate::Error;

    fn try_from(value: SuccessArgs) -> Result<Self, Self::Error> {
        let [perm, page_cnt, ..] = value.try_get_args32()?;
        Ok(Self {
            perm: perm.try_into()?,
            page_cnt: page_cnt.checked_add(1).ok_or(Error::InvalidPageCount)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        interface::Interface,
        interface_args::{MemAddr, MemOpBuf},
        tests::{test_args_serde, test_regs_serde},
    };

    use super::*;

    const MEM_SHARE_FROM_SP1: &[u8] = &[
        0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34,
        0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const MEM_SHARE_FROM_SP2: &[u8] = &[
        0x06, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34,
        0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x80, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x07, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    macro_rules! test_memory_desc_packing {
        ($buf:expr, $desc:expr, $perms:expr, $constituents:expr) => {
            let (transaction_desc, access_desc, constituents) =
                MemTransactionDesc::unpack($buf).unwrap();

            assert_eq!(transaction_desc, $desc);

            let perms: Vec<_> = access_desc.map(|e| e.unwrap()).collect();
            assert_eq!(perms, &$perms);

            let constituents = constituents.unwrap();
            let constituents: Vec<_> = constituents.collect();
            assert_eq!(constituents, &$constituents);

            // Non-null initial value to ensure that empty/reserved fields are set.
            let mut buf = [0x88; 4096];
            let size = $desc.pack(&$constituents, &$perms, &mut buf);

            assert_eq!(size, $buf.len());
            assert_eq!(&buf[0..size], $buf);
        };
    }

    #[test]
    fn mem_share_pack() {
        test_memory_desc_packing!(
            MEM_SHARE_FROM_SP1,
            MemTransactionDesc {
                sender_id: 0x8005,
                mem_region_attr: MemRegionAttributes {
                    security: MemRegionSecurity::Secure,
                    mem_type: MemType::Normal {
                        cacheability: Cacheability::WriteBack,
                        shareability: Shareability::Inner,
                    },
                },
                flags: MemTransactionFlags(0),
                handle: Handle(0x1234_5678_90ab_cdef),
                tag: 0xdead_0000_beef,
            },
            [MemAccessPerm {
                endpoint_id: 0x8003,
                instr_access: InstuctionAccessPerm::NotSpecified,
                data_access: DataAccessPerm::ReadWrite,
                flags: 0x0,
            }],
            [ConstituentMemRegion {
                address: 0x4010f000,
                page_cnt: 0x1,
            }]
        );

        test_memory_desc_packing!(
            MEM_SHARE_FROM_SP2,
            MemTransactionDesc {
                sender_id: 0x8006,
                mem_region_attr: MemRegionAttributes {
                    security: MemRegionSecurity::Secure,
                    mem_type: MemType::Normal {
                        cacheability: Cacheability::WriteBack,
                        shareability: Shareability::Inner,
                    },
                },
                flags: MemTransactionFlags(0),
                handle: Handle(0x1234_5678_90ab_cdef),
                tag: 0xdead_0000_beef,
            },
            [MemAccessPerm {
                endpoint_id: 0x8005,
                instr_access: InstuctionAccessPerm::NotSpecified,
                data_access: DataAccessPerm::ReadWrite,
                flags: 0x0,
            }],
            [ConstituentMemRegion {
                address: 0x40074000,
                page_cnt: 0x1,
            }]
        );
    }

    #[test]
    fn mem_tx_unpack_err1() {
        assert!(MemTransactionDesc::unpack(&[0; 3]).is_err());
    }

    #[test]
    fn mem_tx_unpack_err2() {
        // Indicates one endpoint but the array is empty.
        assert!(
            MemTransactionDesc::unpack(&[
                0x06, 0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err3() {
        // Indicates three endpoints but the array is two.
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x04, 0x80, 0x02, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err4() {
        // Endpoint array offset out of bounds.
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err5() {
        // Invalid enpoint desc size
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err6() {
        // Empty endpoint array
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err7() {
        // Overflow when computing size.
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err8() {
        // Composite entry offset out of range.
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x10, 0x40,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_err9() {
        // Incomplete composite entry.
        assert!(
            MemTransactionDesc::unpack(&[
                0x05, 0x80, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                0x34, 0x12, 0xef, 0xbe, 0x00, 0x00, 0xad, 0xde, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_tx_unpack_unaligned_offset() {
        // Unaligned endpoint array offset.
        let mut buf = MEM_SHARE_FROM_SP1.to_vec();
        // The offset is at byte 32, change it to a non-16-multiple.
        buf[32] = 0x31;
        assert!(matches!(
            MemTransactionDesc::unpack(&buf),
            Err(Error::MalformedDescriptor)
        ));
    }

    #[test]
    fn mem_relinquish_pack() {
        let expected_desc = MemRelinquishDesc {
            handle: Handle(0x1234_5678),
            flags: MemTransactionFlags::ZERO_MEMORY | MemTransactionFlags::TIME_SLICING,
            endpoints: &[0x13, 0x1234, 0xbeef],
        };

        let expected_buf: &[u8] = &[
            0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0b11, 0, 0, 0, 0x3, 0, 0, 0, 0x13, 0, 0x34, 0x12,
            0xef, 0xbe,
        ];

        let actual_desc = MemRelinquishDesc::unpack(expected_buf).unwrap();
        assert_eq!(actual_desc, expected_desc);

        let mut buf = [0; 128];
        let size = expected_desc.pack(&mut buf);

        println!("{buf:x?}");

        assert_eq!(size, expected_buf.len());
        assert_eq!(&buf[0..size], expected_buf);
    }

    #[test]
    fn mem_relinquish_unpack_err1() {
        assert!(MemRelinquishDesc::unpack(&[0; 4]).is_err());
    }

    #[test]
    fn mem_relinquish_unpack_err2() {
        // Indicates one entrypoint but array is empty.
        assert!(
            MemRelinquishDesc::unpack(&[
                0x78, 0x56, 0x34, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
            ])
            .is_err()
        );
    }

    #[test]
    fn mem_relinquish_unpack_err3() {
        // Indicates two entrypoint but array is one.
        assert!(
            MemRelinquishDesc::unpack(&[
                0x78, 0x56, 0x34, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
                0xab, 0xcd,
            ])
            .is_err()
        );
    }

    #[test]
    fn ffa_mem_donate_serde() {
        test_regs_serde!(
            Interface::MemDonate {
                total_len: 0x1234_5678,
                frag_len: 0xabcd,
                buf: None
            },
            [0x84000071, 0x1234_5678, 0xabcd]
        );
        test_regs_serde!(
            Interface::MemDonate {
                total_len: 0x1234_5678,
                frag_len: 0xabcd,
                buf: Some(MemOpBuf::Buf32 {
                    addr: 0xdead_beef,
                    page_cnt: 0x1000
                })
            },
            [0x84000071, 0x1234_5678, 0xabcd, 0xdead_beef, 0x1000]
        );
        test_regs_serde!(
            Interface::MemDonate {
                total_len: 0x1234_5678,
                frag_len: 0xabcd,
                buf: Some(MemOpBuf::Buf64 {
                    addr: 0xdead_0000_beef,
                    page_cnt: 0x1000
                })
            },
            [0xC4000071, 0x1234_5678, 0xabcd, 0xdead_0000_beef, 0x1000]
        );
        test_args_serde!(
            SuccessArgs::Args32([0x5678_def0, 0x1234_abcd, 0, 0, 0, 0]),
            SuccessArgsMemOp {
                handle: Handle(0x1234_abcd_5678_def0)
            }
        );
    }

    #[test]
    fn ffa_mem_lend_serde() {
        test_regs_serde!(
            Interface::MemLend {
                total_len: 0x1234_0000,
                frag_len: 0x10_0000,
                buf: None
            },
            [0x84000072, 0x1234_0000, 0x10_0000]
        );
        test_regs_serde!(
            Interface::MemLend {
                total_len: 0x1234_0000,
                frag_len: 0x10_0000,
                buf: Some(MemOpBuf::Buf32 {
                    addr: 0xffff_ffff,
                    page_cnt: 0x1000
                })
            },
            [0x84000072, 0x1234_0000, 0x10_0000, 0xffff_ffff, 0x1000]
        );
        test_regs_serde!(
            Interface::MemLend {
                total_len: 0x1234_0000,
                frag_len: 0x10_0000,
                buf: Some(MemOpBuf::Buf64 {
                    addr: 0xffff_1234_ffff,
                    page_cnt: 0x1000
                })
            },
            [0xC4000072, 0x1234_0000, 0x10_0000, 0xffff_1234_ffff, 0x1000]
        );
    }

    #[test]
    fn ffa_mem_share_serde() {
        test_regs_serde!(
            Interface::MemShare {
                total_len: 0x1234_0000,
                frag_len: 0x10_0000,
                buf: None
            },
            [0x84000073, 0x1234_0000, 0x10_0000]
        );
        test_regs_serde!(
            Interface::MemShare {
                total_len: 0x1234_0000,
                frag_len: 0x10_0000,
                buf: Some(MemOpBuf::Buf32 {
                    addr: 0x1234_5678,
                    page_cnt: 0x1000
                })
            },
            [0x84000073, 0x1234_0000, 0x10_0000, 0x1234_5678, 0x1000]
        );
        test_regs_serde!(
            Interface::MemShare {
                total_len: 0x1234_0000,
                frag_len: 0x10_0000,
                buf: Some(MemOpBuf::Buf64 {
                    addr: 0xffff_1234_ffff,
                    page_cnt: 0x1000
                })
            },
            [0xC4000073, 0x1234_0000, 0x10_0000, 0xffff_1234_ffff, 0x1000]
        );
    }

    #[test]
    fn ffa_mem_retrieve_req_serde() {
        test_regs_serde!(
            Interface::MemRetrieveReq {
                total_len: 0x1234_5678,
                frag_len: 0xabcd,
                buf: None
            },
            [0x84000074, 0x1234_5678, 0xabcd]
        );
        test_regs_serde!(
            Interface::MemRetrieveReq {
                total_len: 0x1234_5678,
                frag_len: 0xabcd,
                buf: Some(MemOpBuf::Buf32 {
                    addr: 0xdead_beef,
                    page_cnt: 0x1000
                })
            },
            [0x84000074, 0x1234_5678, 0xabcd, 0xdead_beef, 0x1000]
        );
        test_regs_serde!(
            Interface::MemRetrieveReq {
                total_len: 0x1234_5678,
                frag_len: 0xabcd,
                buf: Some(MemOpBuf::Buf64 {
                    addr: 0xdead_0000_beef,
                    page_cnt: 0x1000
                })
            },
            [0xC4000074, 0x1234_5678, 0xabcd, 0xdead_0000_beef, 0x1000]
        );
    }

    #[test]
    fn ffa_mem_retrieve_resp_serde() {
        test_regs_serde!(
            Interface::MemRetrieveResp {
                total_len: 0xaaaa_bbbb,
                frag_len: 0xaaaa_0000
            },
            [0x84000075, 0xaaaa_bbbb, 0xaaaa_0000]
        );
    }

    #[test]
    fn ffa_mem_relinquish_serde() {
        test_regs_serde!(Interface::MemRelinquish, [0x84000076]);
    }

    #[test]
    fn ffa_mem_reclaim_serde() {
        test_regs_serde!(
            Interface::MemReclaim {
                handle: Handle(0x1234_ffff_1234),
                flags: MemReclaimFlags {
                    zero_memory: true,
                    time_slicing: true
                }
            },
            [0x84000077, 0xffff_1234, 0x1234, 0b11]
        );
    }

    #[test]
    fn ffa_mem_perm_get_serde() {
        test_regs_serde!(
            Interface::MemPermGet {
                addr: MemAddr::Addr32(0xdead_beef),
                page_cnt: 1
            },
            [0x84000088, 0xdead_beef]
        );
        test_args_serde!(
            SuccessArgs::Args32([0b001, 0x1234_abcd, 0, 0, 0, 0]),
            SuccessArgsMemPermGet {
                perm: MemPermissionsGetSet {
                    data_access: DataAccessPermGetSet::ReadWrite,
                    instr_access: InstructionAccessPermGetSet::Executable
                },
                page_cnt: 0x1234_abce
            }
        );
    }

    #[test]
    fn ffa_mem_perm_set_serde() {
        test_regs_serde!(
            Interface::MemPermSet {
                addr: MemAddr::Addr64(0x1234_5678_abcd),
                page_cnt: 0x1000,
                mem_perm: MemPermissionsGetSet {
                    data_access: DataAccessPermGetSet::ReadOnly,
                    instr_access: InstructionAccessPermGetSet::NonExecutable
                }
            },
            [0xC4000089, 0x1234_5678_abcd, 0x1000, 0b111]
        );
    }

    #[test]
    fn ffa_mem_op_pause_serde() {
        test_regs_serde!(
            Interface::MemOpPause {
                handle: Handle(0xaaaa_bbbb_cccc_dddd)
            },
            [0x84000078, 0xcccc_dddd, 0xaaaa_bbbb]
        );
    }

    #[test]
    fn ffa_mem_op_resume_serde() {
        test_regs_serde!(
            Interface::MemOpResume {
                handle: Handle(0xaaaa_bbbb_cccc_dddd)
            },
            [0x84000079, 0xcccc_dddd, 0xaaaa_bbbb]
        );
    }

    #[test]
    fn ffa_mem_frag_rx_serde() {
        test_regs_serde!(
            Interface::MemFragRx {
                handle: Handle(0xaaaa_bbbb_cccc_dddd),
                frag_offset: 0x1234_5678,
                endpoint_id: 0xabcd
            },
            [
                0x8400007A,
                0xcccc_dddd,
                0xaaaa_bbbb,
                0x1234_5678,
                0xabcd_0000
            ]
        );
    }

    #[test]
    fn ffa_mem_frag_tx_serde() {
        test_regs_serde!(
            Interface::MemFragTx {
                handle: Handle(0xaaaa_bbbb_cccc_dddd),
                frag_len: 0x1234_5678,
                endpoint_id: 0xabcd
            },
            [
                0x8400007B,
                0xcccc_dddd,
                0xaaaa_bbbb,
                0x1234_5678,
                0xabcd_0000
            ]
        );
    }

    #[test]
    fn parse_cacheability() {
        assert_eq!(
            Cacheability::try_from(0b0100),
            Ok(Cacheability::NonCacheable)
        );
        assert_eq!(Cacheability::try_from(0b1100), Ok(Cacheability::WriteBack));

        assert!(Cacheability::try_from(0b1000).is_err());
        assert!(Cacheability::try_from(0b0000).is_err());
    }

    #[test]
    fn parse_shareability() {
        assert_eq!(Shareability::try_from(0b00), Ok(Shareability::NonShareable));
        assert_eq!(Shareability::try_from(0b10), Ok(Shareability::Outer));
        assert_eq!(Shareability::try_from(0b11), Ok(Shareability::Inner));

        assert!(Shareability::try_from(0b01).is_err());
    }

    #[test]
    fn parse_device_memory_attributes() {
        assert_eq!(
            DeviceMemAttributes::try_from(0b0000),
            Ok(DeviceMemAttributes::DevnGnRnE)
        );
        assert_eq!(
            DeviceMemAttributes::try_from(0b0100),
            Ok(DeviceMemAttributes::DevnGnRE)
        );
        assert_eq!(
            DeviceMemAttributes::try_from(0b1000),
            Ok(DeviceMemAttributes::DevnGRE)
        );
        assert_eq!(
            DeviceMemAttributes::try_from(0b1100),
            Ok(DeviceMemAttributes::DevGRE)
        );
    }

    #[test]
    fn parse_memory_type() {
        assert_eq!(MemType::try_from(0x00), Ok(MemType::NotSpecified));
        assert_eq!(
            MemType::try_from(0x10),
            Ok(MemType::Device(DeviceMemAttributes::DevnGnRnE))
        );
        assert_eq!(
            MemType::try_from(0x2f),
            Ok(MemType::Normal {
                cacheability: Cacheability::WriteBack,
                shareability: Shareability::Inner
            })
        );

        assert!(MemType::try_from(0x30).is_err());
    }

    #[test]
    fn parse_instruction_access_permissions() {
        assert_eq!(
            InstuctionAccessPerm::try_from(0b0000),
            Ok(InstuctionAccessPerm::NotSpecified)
        );
        assert_eq!(
            InstuctionAccessPerm::try_from(0b0100),
            Ok(InstuctionAccessPerm::NotExecutable)
        );
        assert_eq!(
            InstuctionAccessPerm::try_from(0b1000),
            Ok(InstuctionAccessPerm::Executable)
        );

        assert!(InstuctionAccessPerm::try_from(0b1100).is_err());
    }

    #[test]
    fn parse_data_access_permissions() {
        assert_eq!(
            DataAccessPerm::try_from(0b00),
            Ok(DataAccessPerm::NotSpecified)
        );
        assert_eq!(DataAccessPerm::try_from(0b01), Ok(DataAccessPerm::ReadOnly));
        assert_eq!(
            DataAccessPerm::try_from(0b10),
            Ok(DataAccessPerm::ReadWrite)
        );

        assert!(DataAccessPerm::try_from(0b11).is_err());
    }
}
