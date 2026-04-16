// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Implementation of the FF-A Boot information protocol.
//!
//! An SP or SPMC could rely on boot information for their initialization e.g. a flattened device
//! tree with nodes to describe the devices and memory regions assigned to the SP or SPMC. FF-A
//! specifies a protocol that can be used by a producer to pass boot information to a consumer at a
//! Secure FF-A instance. The Framework assumes that the boot information protocol is used by a
//! producer and consumer pair that reside at adjacent exception levels as listed below.
//! - SPMD (producer) and an SPMC (consumer) in either S-EL1 or S-EL2.
//! - An SPMC (producer) and SP (consumer) pair listed below.
//!   - EL3 SPMC and a Logical S-EL1 SP.
//!   - S-EL2 SPMC and Physical S-EL1 SP.
//!   - EL3 SPMC and a S-EL0 SP.
//!   - S-EL2 SPMC and a S-EL0 SP.
//!   - S-EL1 SPMC and a S-EL0 SP.

use core::ffi::CStr;
use thiserror::Error;
use uuid::Uuid;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    UuidHelper, Version,
    ffa_v1_3::{boot_info_descriptor, boot_info_header},
};

/// Rich error types returned by this module. Should be converted to [`crate::FfaError`] when used
/// with the `FFA_ERROR` interface.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    #[error("Invalid standard type {0}")]
    InvalidStdType(u8),
    #[error("Invalid type {0}")]
    InvalidType(u8),
    #[error("Invalid contents format {0}")]
    InvalidContentsFormat(u16),
    #[error("Invalid name format {0}")]
    InvalidNameFormat(u16),
    #[error("Invalid name")]
    InvalidName,
    #[error("Invalid flags {0}")]
    InvalidFlags(u16),
    #[error("Invalid header size or alignment")]
    InvalidHeader,
    #[error("Invalid buffer size")]
    InvalidBufferSize,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid version {0}")]
    InvalidVersion(Version),
    #[error("Malformed descriptor")]
    MalformedDescriptor,
}

impl From<Error> for crate::FfaError {
    fn from(_value: Error) -> Self {
        Self::InvalidParameters
    }
}

/// Name of boot information descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootInfoName<'a> {
    NullTermString(&'a CStr),
    Uuid(Uuid),
}

/// ID for supported standard boot information types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootInfoStdId {
    Fdt = Self::FDT,
    Hob = Self::HOB,
}

impl TryFrom<u8> for BootInfoStdId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::FDT => Ok(BootInfoStdId::Fdt),
            Self::HOB => Ok(BootInfoStdId::Hob),
            _ => Err(Error::InvalidStdType(value)),
        }
    }
}

impl BootInfoStdId {
    const FDT: u8 = 0;
    const HOB: u8 = 1;
}

/// ID for implementation defined boot information type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfoImpdefId(pub u8);

impl From<u8> for BootInfoImpdefId {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

/// Boot information type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoType {
    Std(BootInfoStdId),
    Impdef(BootInfoImpdefId),
}

impl TryFrom<u8> for BootInfoType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> Self::TYPE_SHIFT) & Self::TYPE_MASK {
            Self::TYPE_STANDARD => Ok(BootInfoType::Std((value & Self::ID_MASK).try_into()?)),
            Self::TYPE_IMPDEF => Ok(BootInfoType::Impdef((value & Self::ID_MASK).into())),
            _ => Err(Error::InvalidType(value)),
        }
    }
}

impl From<BootInfoType> for u8 {
    fn from(value: BootInfoType) -> Self {
        match value {
            BootInfoType::Std(std_type) => {
                std_type as u8 | (BootInfoType::TYPE_STANDARD << BootInfoType::TYPE_SHIFT)
            }
            BootInfoType::Impdef(impdef_type) => {
                impdef_type.0 | (BootInfoType::TYPE_IMPDEF << BootInfoType::TYPE_SHIFT)
            }
        }
    }
}

impl BootInfoType {
    // This field contains the boot info type at bit[7] and the boot info identifier in bits[6:0]
    const TYPE_SHIFT: usize = 7;
    const TYPE_MASK: u8 = 0b1;
    const TYPE_STANDARD: u8 = 0b0;
    const TYPE_IMPDEF: u8 = 0b1;
    // Mask for boot info identifier in bits[6:0]
    const ID_MASK: u8 = 0b0111_1111;
}

/// Boot information contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoContents<'a> {
    Buffer { content_buf: &'a [u8] },
    Value { val: u64, len: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum BootInfoContentsFormat {
    Address = Self::ADDRESS << Self::SHIFT,
    Value = Self::VALUE << Self::SHIFT,
    Offset = Self::OFFSET << Self::SHIFT,
}

impl TryFrom<u16> for BootInfoContentsFormat {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::ADDRESS => Ok(BootInfoContentsFormat::Address),
            Self::VALUE => Ok(BootInfoContentsFormat::Value),
            Self::OFFSET => Ok(BootInfoContentsFormat::Offset),
            _ => Err(Error::InvalidContentsFormat(value)),
        }
    }
}

impl BootInfoContentsFormat {
    const SHIFT: usize = 2;
    const MASK: u16 = 0b11;
    const ADDRESS: u16 = 0b00;
    const VALUE: u16 = 0b01;
    const OFFSET: u16 = 0b10;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum BootInfoNameFormat {
    String = Self::STRING << Self::SHIFT,
    Uuid = Self::UUID << Self::SHIFT,
}

impl TryFrom<u16> for BootInfoNameFormat {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::STRING => Ok(BootInfoNameFormat::String),
            Self::UUID => Ok(BootInfoNameFormat::Uuid),
            _ => Err(Error::InvalidNameFormat(value)),
        }
    }
}

impl BootInfoNameFormat {
    const SHIFT: usize = 0;
    const MASK: u16 = 0b11;
    const STRING: u16 = 0b00;
    const UUID: u16 = 0b01;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootInfoFlags {
    contents_format: BootInfoContentsFormat,
    name_format: BootInfoNameFormat,
}

impl TryFrom<u16> for BootInfoFlags {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // bits[15:4]: Reserved (MBZ)
        if value >> 4 == 0 {
            Ok(Self {
                contents_format: BootInfoContentsFormat::try_from(value)?,
                name_format: BootInfoNameFormat::try_from(value)?,
            })
        } else {
            Err(Error::InvalidFlags(value))
        }
    }
}

impl From<BootInfoFlags> for u16 {
    fn from(value: BootInfoFlags) -> Self {
        value.contents_format as u16 | value.name_format as u16
    }
}

/// Boot information descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootInfo<'a> {
    pub name: BootInfoName<'a>,
    pub r#type: BootInfoType,
    pub contents: BootInfoContents<'a>,
}

impl BootInfo<'_> {
    /// Serialize a list of boot information descriptors into a buffer.
    ///
    /// If the `mapped_addr` parameter is None, the serialized descriptor will use the offset in
    /// `buf` to describe the address of the individual boot information content.
    /// Otherwise `mapped_addr` must contain the address of `buf` in the consumer's translation
    /// regime (typically a virtual address where the buffer is mapped to). The individual boot
    /// information content's address will be described with an absolute address calculated inside
    /// the buffer.
    pub fn pack(descriptors: &[BootInfo], buf: &mut [u8], mapped_addr: Option<usize>) {
        // Offset from the base of the header to the first element in the boot info descriptor array
        // Must be 8 byte aligned, but otherwise we're free to choose any value here.
        // Let's just pack the array right after the header.
        const DESC_ARRAY_OFFSET: usize = size_of::<boot_info_header>().next_multiple_of(8);
        const DESC_SIZE: usize = size_of::<boot_info_descriptor>();

        assert!(buf.len() <= u32::MAX as usize);

        let desc_cnt = descriptors.len();

        // Add the already known fields, later we have to add the sizes referenced by the individual
        // descriptors

        // The Size of boot information blob field specifies the size of the blob that spans one or
        // more contiguous 4K pages used by the producer to populate it. It is calculated by adding
        // the following values:
        // 1. Boot information descriptor array offset
        // 2. Product of Boot information descriptor count and Boot information descriptor size.
        // 3. Total size of all boot information referenced by boot information descriptors.
        //    This is determined by adding the values in the Size field of each boot information
        //    descriptor whose Contents field contains an address.
        // 4. Any padding between,
        //    1. The boot information descriptor array and the boot information referenced from it.
        //    2. Distinct instances of boot information referenced from the boot information
        //       descriptor array.
        let mut total_offset = 0usize;

        // No. 1 from the "Size of boot information blob" list
        total_offset = total_offset.checked_add(DESC_ARRAY_OFFSET).unwrap();

        // No. 2 from the "Size of boot information blob" list
        total_offset = total_offset
            .checked_add(desc_cnt.checked_mul(DESC_SIZE).unwrap())
            .unwrap();

        // Fail early if the buffer is too small
        assert!(total_offset <= buf.len());

        // Fill the boot info descriptor array, all offset based from DESC_ARRAY_OFFSET
        let mut desc_array_offset = DESC_ARRAY_OFFSET;

        for desc in descriptors {
            let mut desc_raw = boot_info_descriptor::default();

            let name_format = match desc.name {
                BootInfoName::NullTermString(name) => {
                    // count_bytes() doesn't include nul terminator
                    let name_len = name.count_bytes().min(15);
                    desc_raw.name[..name_len].copy_from_slice(&name.to_bytes()[..name_len]);
                    // Add nul terminator and zero fill the rest
                    desc_raw.name[name_len..].fill(0);

                    BootInfoNameFormat::String
                }
                BootInfoName::Uuid(uuid) => {
                    desc_raw.name.copy_from_slice(&UuidHelper::to_bytes(uuid));
                    BootInfoNameFormat::Uuid
                }
            };

            let contents_format = match desc.contents {
                BootInfoContents::Buffer { content_buf } => {
                    // We have to copy the contents referenced by the boot info descriptor into the
                    // boot info blob. At this offset we're after the boot info header and all of
                    // the boot info descriptors. The contents referenced from the individual boot
                    // info descriptors will get copied to this starting address. The 8 byte
                    // alignment is not explicitly mentioned by the spec, but it's better to have it
                    // anyway.
                    // No. 4 from the "Size of boot information blob" list
                    total_offset = total_offset.next_multiple_of(8);

                    // To describe the content buffer's address, by default we use the offset from
                    // the base of the boot info blob. If the mapped_addr argument is provided, we
                    // will calculate the content's absolute address in the consumer's translation
                    // regime.
                    let (content_addr_or_offset, content_format) =
                        if let Some(mapped_addr) = mapped_addr {
                            (
                                total_offset.checked_add(mapped_addr).unwrap(),
                                BootInfoContentsFormat::Address,
                            )
                        } else {
                            (total_offset, BootInfoContentsFormat::Offset)
                        };

                    // Check if the content fits before copying
                    let content_len = content_buf.len();
                    total_offset.checked_add(content_len).unwrap();

                    // Do the copy and increase the total size
                    // No. 3 from the "Size of boot information blob" list
                    buf[total_offset..total_offset + content_len].copy_from_slice(content_buf);
                    total_offset += content_len;

                    desc_raw.contents = content_addr_or_offset as u64;
                    desc_raw.size = content_len as u32;

                    content_format
                }
                BootInfoContents::Value { val, len } => {
                    assert!((1..=8).contains(&len));
                    desc_raw.contents = val;
                    desc_raw.size = len as u32;

                    BootInfoContentsFormat::Value
                }
            };

            let flags = BootInfoFlags {
                contents_format,
                name_format,
            };

            desc_raw.flags = flags.into();
            desc_raw.r#type = desc.r#type.into();

            desc_raw
                .write_to_prefix(&mut buf[desc_array_offset..])
                .unwrap();
            desc_array_offset += DESC_SIZE;
        }

        let header_raw = boot_info_header {
            signature: 0x0ffa,
            version: Version(1, 3).into(),
            boot_info_blob_size: total_offset as u32,
            boot_info_desc_size: DESC_SIZE as u32,
            boot_info_desc_count: desc_cnt as u32,
            boot_info_array_offset: DESC_ARRAY_OFFSET as u32,
            reserved: 0,
        };

        header_raw.write_to_prefix(buf).unwrap();
    }

    /// Validate and return the boot information header
    fn get_header(buf: &[u8]) -> Result<&boot_info_header, Error> {
        let (header_raw, _) =
            boot_info_header::ref_from_prefix(buf).map_err(|_| Error::InvalidHeader)?;

        if header_raw.signature != 0x0ffa {
            return Err(Error::InvalidSignature);
        }

        let header_version = header_raw
            .version
            .try_into()
            .map_err(|_| Error::InvalidHeader)?;
        if header_version != Version(1, 3) {
            return Err(Error::InvalidVersion(header_version));
        }

        Ok(header_raw)
    }

    /// Get the size of the boot information blob spanning contiguous memory. This enables a
    /// consumer to map all of the boot information blob in its translation regime or copy it to
    /// another memory location without parsing each element in the boot information descriptor
    /// array.
    pub fn get_blob_size(buf: &[u8]) -> Result<usize, Error> {
        let header_raw = Self::get_header(buf)?;

        Ok(header_raw.boot_info_blob_size as usize)
    }
}

/// Iterator of boot information descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfoIterator<'a> {
    buf: &'a [u8],
    offset: usize,
    desc_count: usize,
    desc_size: usize,
}

impl<'a> BootInfoIterator<'a> {
    /// Create an iterator of boot information descriptors from a buffer.
    pub fn new(buf: &'a [u8]) -> Result<Self, Error> {
        let header_raw = BootInfo::get_header(buf)?;

        if buf.len() < header_raw.boot_info_blob_size as usize {
            return Err(Error::InvalidBufferSize);
        }

        if header_raw.boot_info_desc_size as usize != size_of::<boot_info_descriptor>() {
            return Err(Error::MalformedDescriptor);
        }

        let Some(total_desc_size) = header_raw
            .boot_info_desc_count
            .checked_mul(header_raw.boot_info_desc_size)
            .and_then(|x| x.checked_add(header_raw.boot_info_array_offset))
        else {
            return Err(Error::InvalidBufferSize);
        };

        if buf.len() < total_desc_size as usize {
            return Err(Error::InvalidBufferSize);
        }

        Ok(Self {
            buf,
            offset: header_raw.boot_info_array_offset as usize,
            desc_count: header_raw.boot_info_desc_count as usize,
            desc_size: header_raw.boot_info_desc_size as usize,
        })
    }
}

impl<'a> Iterator for BootInfoIterator<'a> {
    type Item = Result<BootInfo<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.desc_count > 0 {
            let desc_offset = self.offset;
            self.offset += self.desc_size;
            self.desc_count -= 1;

            let Ok(desc_raw) = boot_info_descriptor::ref_from_bytes(
                &self.buf[desc_offset..desc_offset + self.desc_size],
            ) else {
                return Some(Err(Error::MalformedDescriptor));
            };

            if desc_raw.reserved != 0 {
                return Some(Err(Error::MalformedDescriptor));
            }

            let r#type: BootInfoType = match desc_raw.r#type.try_into() {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let flags: BootInfoFlags = match desc_raw.flags.try_into() {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let name = match flags.name_format {
                BootInfoNameFormat::String => {
                    let Ok(name_str) = CStr::from_bytes_until_nul(desc_raw.name.as_bytes()) else {
                        return Some(Err(Error::InvalidName));
                    };
                    BootInfoName::NullTermString(name_str)
                }
                BootInfoNameFormat::Uuid => {
                    BootInfoName::Uuid(UuidHelper::from_bytes(desc_raw.name))
                }
            };

            let contents = match flags.contents_format {
                BootInfoContentsFormat::Address | BootInfoContentsFormat::Offset => {
                    let contents = desc_raw.contents as usize;
                    let contents_size = desc_raw.size as usize;

                    let start = if flags.contents_format == BootInfoContentsFormat::Address {
                        let Some(offset) = contents.checked_sub(self.buf.as_ptr() as usize) else {
                            return Some(Err(Error::InvalidBufferSize));
                        };
                        offset
                    } else {
                        contents
                    };

                    let Some(end) = start.checked_add(contents_size) else {
                        return Some(Err(Error::InvalidBufferSize));
                    };

                    let Some(content_buf) = self.buf.get(start..end) else {
                        return Some(Err(Error::InvalidBufferSize));
                    };

                    BootInfoContents::Buffer { content_buf }
                }

                BootInfoContentsFormat::Value => {
                    let len = desc_raw.size as usize;
                    if (1..=8).contains(&len) {
                        BootInfoContents::Value {
                            val: desc_raw.contents,
                            len,
                        }
                    } else {
                        return Some(Err(Error::MalformedDescriptor));
                    }
                }
            };

            return Some(Ok(BootInfo {
                name,
                r#type,
                contents,
            }));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::uuid;

    #[test]
    fn boot_info() {
        let desc1 = BootInfo {
            name: BootInfoName::NullTermString(c"test1234test123"),
            r#type: BootInfoType::Impdef(BootInfoImpdefId(0x2b)),
            contents: BootInfoContents::Value {
                val: 0xdeadbeef,
                len: 4,
            },
        };

        let fdt = [0u8; 0xff];
        let desc2 = BootInfo {
            name: BootInfoName::Uuid(uuid!("12345678-abcd-dcba-1234-123456789abc")),
            r#type: BootInfoType::Std(BootInfoStdId::Fdt),
            contents: BootInfoContents::Buffer { content_buf: &fdt },
        };

        let mut buf = [0u8; 0x1ff];
        let buf_addr = buf.as_ptr() as usize;
        BootInfo::pack(&[desc1.clone(), desc2.clone()], &mut buf, Some(buf_addr));
        let mut descriptors = BootInfoIterator::new(&buf).unwrap();
        let desc1_check = descriptors.next().unwrap().unwrap();
        let desc2_check = descriptors.next().unwrap().unwrap();

        assert_eq!(desc1, desc1_check);
        assert_eq!(desc2, desc2_check);

        assert_eq!(BootInfo::get_blob_size(&buf), Ok(351));

        let fa = (buf.as_ptr() as u64 + 96).to_le_bytes();

        let expected = [
            // Header
            0xfa, 0x0f, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // End of Header
            // Desc1
            0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32,
            0x33, 0x00, 0xab, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde,
            0x00, 0x00, 0x00, 0x00, // End of Desc1
            // Desc2
            0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xdc, 0xba, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0x00, 0x00, 0x01, 0x00, 0xff, 0x00, 0x00, 0x00, fa[0], fa[1], fa[2], fa[3],
            fa[4], fa[5], fa[6], fa[7], // End of Desc2
        ];

        assert_eq!(expected, buf[0..expected.len()]);
    }

    #[test]
    pub fn get_blob_size_invalid_version() {
        // Valid header but wrong version (1.1 instead of 1.3)
        assert_eq!(
            BootInfo::get_blob_size(&[
                0xfa, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            Err(Error::InvalidVersion(Version(1, 1)))
        );
    }

    #[test]
    pub fn boot_info_iter_new_err1() {
        assert_eq!(BootInfoIterator::new(&[0; 4]), Err(Error::InvalidHeader));
    }

    #[test]
    pub fn boot_info_iter_new_err2() {
        // Empty boot info.
        assert_eq!(
            BootInfoIterator::new(&[
                0xfa, 0x0f, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x20, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]),
            Err(Error::InvalidBufferSize)
        );
    }

    #[test]
    pub fn boot_info_iter_new_err3() {
        // Indicates two entries but array is one.
        assert_eq!(
            BootInfoIterator::new(&[
                0xfa, 0x0f, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x20, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34, 0x74, 0x65,
                0x73, 0x74, 0x31, 0x32, 0x33, 0x00, 0xab, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
                0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
            ]),
            Err(Error::InvalidBufferSize)
        );
    }

    #[test]
    pub fn boot_info_iter_new_err4() {
        // Invalid entry size.
        assert_eq!(
            BootInfoIterator::new(&[
                0xfa, 0x0f, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x10, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34, 0x74, 0x65,
                0x73, 0x74, 0x31, 0x32, 0x33, 0x00, 0xab, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
                0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
            ]),
            Err(Error::InvalidBufferSize)
        );
    }

    #[test]
    pub fn boot_info_iter_new_err5() {
        // Array offset out of range.
        assert_eq!(
            BootInfoIterator::new(&[
                0xfa, 0x0f, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x20, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34, 0x74, 0x65,
                0x73, 0x74, 0x31, 0x32, 0x33, 0x00, 0xab, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
                0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
            ]),
            Err(Error::InvalidBufferSize)
        );
    }
}
