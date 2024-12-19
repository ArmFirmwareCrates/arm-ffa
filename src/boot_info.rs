// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    ffa_v1_1::{boot_info_descriptor, boot_info_header},
    Version,
};
use core::ffi::CStr;
use thiserror::Error;
use uuid::Uuid;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Error)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootInfoName<'a> {
    NullTermString(&'a CStr),
    Uuid(Uuid),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootInfoStdType {
    Fdt = Self::FDT,
    Hob = Self::HOB,
}

impl TryFrom<u8> for BootInfoStdType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::FDT => Ok(BootInfoStdType::Fdt),
            Self::HOB => Ok(BootInfoStdType::Hob),
            _ => Err(Error::InvalidStdType(value)),
        }
    }
}

impl BootInfoStdType {
    const FDT: u8 = 0;
    const HOB: u8 = 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfoImpdefType(u8);

impl From<u8> for BootInfoImpdefType {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoType {
    Std(BootInfoStdType),
    Impdef(BootInfoImpdefType),
}

impl TryFrom<u8> for BootInfoType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::STANDARD => Ok(BootInfoType::Std((value & Self::TYPE_MASK).try_into()?)),
            Self::IMPDEF => Ok(BootInfoType::Impdef((value & Self::TYPE_MASK).into())),
            _ => Err(Error::InvalidType(value)),
        }
    }
}

impl From<BootInfoType> for u8 {
    fn from(value: BootInfoType) -> Self {
        match value {
            BootInfoType::Std(std_type) => {
                std_type as u8 | BootInfoType::STANDARD << BootInfoType::SHIFT
            }
            BootInfoType::Impdef(impdef_type) => {
                impdef_type.0 | BootInfoType::IMPDEF << BootInfoType::SHIFT
            }
        }
    }
}

impl BootInfoType {
    const SHIFT: usize = 7;
    const MASK: u8 = 0b1;
    const STANDARD: u8 = 0b0;
    const IMPDEF: u8 = 0b1;
    const TYPE_MASK: u8 = 0b0111_1111;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoContents<'a> {
    Address { content_buf: &'a [u8] },
    Value { val: u64, len: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum BootInfoContentsFormat {
    Address = Self::ADDRESS << Self::SHIFT,
    Value = Self::VALUE << Self::SHIFT,
}

impl TryFrom<u16> for BootInfoContentsFormat {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::ADDRESS => Ok(BootInfoContentsFormat::Address),
            Self::VALUE => Ok(BootInfoContentsFormat::Value),
            _ => Err(Error::InvalidContentsFormat(value)),
        }
    }
}

impl BootInfoContentsFormat {
    const SHIFT: usize = 2;
    const MASK: u16 = 0b11;
    const ADDRESS: u16 = 0b00;
    const VALUE: u16 = 0b01;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootInfo<'a> {
    pub name: BootInfoName<'a>,
    pub typ: BootInfoType,
    pub contents: BootInfoContents<'a>,
}

impl BootInfo<'_> {
    pub fn pack(descriptors: &[BootInfo], buf: &mut [u8], mapped_addr: Option<usize>) {
        // Offset from the base of the header to the first element in the boot info descriptor array
        // Must be 8 byte aligned, but otherwise we're free to choose any value here.
        // Let's just  pack the array right after the header.
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

            let name_format = match &desc.name {
                BootInfoName::NullTermString(name) => {
                    // count_bytes() doesn't include nul terminator
                    let name_len = name.count_bytes().min(15);
                    desc_raw.name[..name_len].copy_from_slice(&name.to_bytes()[..name_len]);
                    // Add nul terminator and zero fill the rest
                    desc_raw.name[name_len..].fill(0);

                    BootInfoNameFormat::String
                }
                BootInfoName::Uuid(uuid) => {
                    desc_raw.name.copy_from_slice(&uuid.to_bytes_le());
                    BootInfoNameFormat::Uuid
                }
            };

            let contents_format = match desc.contents {
                BootInfoContents::Address { content_buf } => {
                    // We have to copy the contents referenced by the boot info descriptor into the
                    // boot info blob. At this offset we're after the boot info header and all of
                    // the boot info descriptors. The contents referenced from the individual boot
                    // info descriptors will get copied to this starting address. The 8 byte
                    // alignment is not explicitly mentioned by the spec, but it's better to have it
                    // anyway.
                    // No. 4 from the "Size of boot information blob" list
                    total_offset = total_offset.next_multiple_of(8);

                    // The mapped_addr argument contains the address where buf is mapped to in the
                    // consumer's translation regime. If it's None, we assume identity mapping is
                    // used, so the buffer's address stays the same.
                    let buf_addr = mapped_addr.unwrap_or(buf.as_ptr() as usize);

                    // The content's address in the consumer's translation regime will be the
                    // buffer's address in the consumer's translation regime plus the offset of the
                    // content within the boot info blob.
                    let content_addr = buf_addr.checked_add(total_offset).unwrap();

                    // Check if the content fits before copying
                    let content_len = content_buf.len();
                    total_offset.checked_add(content_len).unwrap();

                    // Do the copy and increase the total size
                    // No. 3 from the "Size of boot information blob" list
                    buf[total_offset..total_offset + content_len].copy_from_slice(content_buf);
                    total_offset += content_len;

                    desc_raw.contents = content_addr as u64;
                    desc_raw.size = content_len as u32;

                    BootInfoContentsFormat::Address
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
            desc_raw.typ = desc.typ.into();

            desc_raw
                .write_to_prefix(&mut buf[desc_array_offset..])
                .unwrap();
            desc_array_offset += DESC_SIZE;
        }

        let header_raw = boot_info_header {
            signature: 0x0ffa,
            version: Version(1, 1).into(),
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

        let version = Version::from(header_raw.version);
        if version != Version(1, 1) {
            return Err(Error::InvalidVersion(version));
        }

        Ok(header_raw)
    }

    /// Get the size of the boot information blob spanning contiguous memory.
    ///
    /// This enables a consumer to map all of the boot information blob in its translation regime
    /// or copy it to another memory location without parsing each element in the boot information
    /// descriptor array.
    pub fn get_blob_size(buf: &[u8]) -> Result<usize, Error> {
        let header_raw = Self::get_header(buf)?;

        Ok(header_raw.boot_info_blob_size as usize)
    }
}

pub struct BootInfoIterator<'a> {
    buf: &'a [u8],
    offset: usize,
    desc_count: usize,
    desc_size: usize,
}

impl<'a> BootInfoIterator<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, Error> {
        let header_raw = BootInfo::get_header(buf)?;

        if buf.len() < header_raw.boot_info_blob_size as usize {
            return Err(Error::InvalidBufferSize);
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
            let Ok(desc_raw) = boot_info_descriptor::ref_from_bytes(
                &self.buf[self.offset..self.offset + self.desc_size],
            ) else {
                return Some(Err(Error::MalformedDescriptor));
            };

            if desc_raw.reserved != 0 {
                return Some(Err(Error::MalformedDescriptor));
            }

            let typ: BootInfoType = match desc_raw.typ.try_into() {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let flags: BootInfoFlags = match desc_raw.flags.try_into() {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let name = match flags.name_format {
                BootInfoNameFormat::String => {
                    let Ok(name_str) = CStr::from_bytes_with_nul(desc_raw.name.as_bytes()) else {
                        return Some(Err(Error::InvalidName));
                    };
                    BootInfoName::NullTermString(name_str)
                }
                BootInfoNameFormat::Uuid => BootInfoName::Uuid(Uuid::from_bytes_le(desc_raw.name)),
            };

            let contents = match flags.contents_format {
                BootInfoContentsFormat::Address => {
                    let offset = desc_raw.contents as usize - self.buf.as_ptr() as usize;
                    assert!(offset < self.buf.len());
                    assert!((offset + desc_raw.size as usize) < self.buf.len());
                    BootInfoContents::Address {
                        content_buf: &self.buf[offset..offset + desc_raw.size as usize],
                    }
                }

                BootInfoContentsFormat::Value => BootInfoContents::Value {
                    val: desc_raw.contents,
                    len: desc_raw.size as usize,
                },
            };

            self.offset += self.desc_size;
            self.desc_count -= 1;

            return Some(Ok(BootInfo {
                name,
                typ,
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

    // TODO: add tests with a known correct boot info blob

    #[test]
    fn boot_info() {
        let desc1 = BootInfo {
            name: BootInfoName::NullTermString(c"test1234test123"),
            typ: BootInfoType::Impdef(BootInfoImpdefType(0x2b)),
            contents: BootInfoContents::Value {
                val: 0xdeadbeef,
                len: 4,
            },
        };

        let fdt = [0u8; 0xff];
        let desc2 = BootInfo {
            name: BootInfoName::Uuid(uuid!("12345678-abcd-dcba-1234-123456789abc")),
            typ: BootInfoType::Std(BootInfoStdType::Fdt),
            contents: BootInfoContents::Address { content_buf: &fdt },
        };

        let mut buf = [0u8; 0x1ff];
        let buf_addr = buf.as_ptr() as usize;
        BootInfo::pack(&[desc1.clone(), desc2.clone()], &mut buf, Some(buf_addr));
        let mut descriptors = BootInfoIterator::new(&buf).unwrap();
        let desc1_check = descriptors.next().unwrap().unwrap();
        let desc2_check = descriptors.next().unwrap().unwrap();

        assert_eq!(desc1, desc1_check);
        assert_eq!(desc2, desc2_check);
    }
}
