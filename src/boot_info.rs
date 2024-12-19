// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ffa_v1_1::{boot_info_descriptor, boot_info_header};
use core::ffi::CStr;
use thiserror::Error;
use uuid::Uuid;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Parsing")]
    Parsing,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid version")]
    InvalidVersion,
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
            _ => Err(Error::Parsing),
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
            _ => Err(Error::Parsing),
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
pub enum BootInfoContents {
    Address { addr: usize, len: usize },
    Value { val: u64, len: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum BootInfoContentsFormat {
    Address = Self::ADDRESS << Self::SHIFT,
    Value = Self::VALUE << Self::SHIFT,
}

impl TryFrom<u16> for BootInfoContentsFormat {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::ADDRESS => Ok(BootInfoContentsFormat::Address),
            Self::VALUE => Ok(BootInfoContentsFormat::Value),
            _ => Err(Error::Parsing),
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
pub enum BootInfoNameFormat {
    String = Self::STRING << Self::SHIFT,
    Uuid = Self::UUID << Self::SHIFT,
}

impl TryFrom<u16> for BootInfoNameFormat {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value >> Self::SHIFT) & Self::MASK {
            Self::STRING => Ok(BootInfoNameFormat::String),
            Self::UUID => Ok(BootInfoNameFormat::Uuid),
            _ => Err(Error::Parsing),
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
pub struct BootInfoFlags {
    pub contents_format: BootInfoContentsFormat,
    pub name_format: BootInfoNameFormat,
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
            Err(Error::Parsing)
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
    pub contents: BootInfoContents,
}

impl BootInfo<'_> {
    pub fn pack(descriptors: &[BootInfo], buf: &mut [u8]) {
        // Offset from the base of the header to the first element in the boot info descriptor array
        // Must be 8 byte aligned, but otherwise we're free to choose any value here.
        // Let's just  pack the array right after the header.
        const DESC_ARRAY_OFFSET: usize = size_of::<boot_info_header>().next_multiple_of(8);
        const DESC_SIZE: usize = size_of::<boot_info_descriptor>();

        let desc_cnt = descriptors.len();

        // Add the already known fields, later we have to add the sizes referenced by the individual
        // descriptors
        let mut total_size = 0usize;
        total_size = total_size.checked_add(DESC_ARRAY_OFFSET).unwrap();
        total_size = total_size
            .checked_add(desc_cnt.checked_mul(DESC_SIZE).unwrap())
            .unwrap();

        // Fill the boot info descriptor array, all offset based from DESC_ARRAY_OFFSET
        let mut offset = DESC_ARRAY_OFFSET;

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
                BootInfoContents::Address { addr, len } => {
                    desc_raw.contents = addr as u64;
                    desc_raw.size = len as u32;

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

            desc_raw.write_to_prefix(&mut buf[offset..]).unwrap();
            offset += DESC_SIZE;
        }

        assert!(buf.len() <= u32::MAX as usize);
        assert!(total_size <= buf.len());

        // TODO: add padding between boot information referenced by the descriptors to total_size

        let header_raw = boot_info_header {
            signature: 0x0ffa,
            version: 0x0001_0001,
            boot_info_blob_size: total_size as u32,
            boot_info_desc_size: DESC_SIZE as u32,
            boot_info_desc_count: desc_cnt as u32,
            boot_info_array_offset: DESC_ARRAY_OFFSET as u32,
            reserved: 0,
        };

        header_raw.write_to_prefix(buf).unwrap();
    }

    /// Validate and return the boot information header
    fn get_header(buf: &[u8]) -> Result<&boot_info_header, Error> {
        let (header_raw, _) = boot_info_header::ref_from_prefix(buf).map_err(|_| Error::Parsing)?;

        if header_raw.signature != 0x0ffa {
            return Err(Error::InvalidSignature);
        }

        if header_raw.version != 0x0001_0001 {
            return Err(Error::InvalidVersion);
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
        let offset = header_raw.boot_info_array_offset as usize;
        let desc_count = header_raw.boot_info_desc_count as usize;
        let desc_size = header_raw.boot_info_desc_size as usize;

        Ok(Self {
            buf,
            offset,
            desc_count,
            desc_size,
        })
    }
}

impl<'a> Iterator for BootInfoIterator<'a> {
    type Item = BootInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.desc_count > 0 {
            let desc_raw = boot_info_descriptor::ref_from_bytes(
                &self.buf[self.offset..self.offset + self.desc_size],
            )
            .unwrap();

            assert_eq!(desc_raw.reserved, 0);

            let typ: BootInfoType = desc_raw.typ.try_into().unwrap();
            let flags: BootInfoFlags = desc_raw.flags.try_into().unwrap();

            let name = match flags.name_format {
                BootInfoNameFormat::String => BootInfoName::NullTermString(
                    CStr::from_bytes_with_nul(desc_raw.name.as_bytes()).unwrap(),
                ),
                BootInfoNameFormat::Uuid => BootInfoName::Uuid(Uuid::from_bytes_le(desc_raw.name)),
            };

            let contents = match flags.contents_format {
                BootInfoContentsFormat::Address => BootInfoContents::Address {
                    addr: desc_raw.contents as usize,
                    len: desc_raw.size as usize,
                },

                BootInfoContentsFormat::Value => BootInfoContents::Value {
                    val: desc_raw.contents,
                    len: desc_raw.size as usize,
                },
            };

            self.offset += self.desc_size;
            self.desc_count -= 1;

            return Some(BootInfo {
                name,
                typ,
                contents,
            });
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
            contents: BootInfoContents::Address {
                addr: &fdt as *const u8 as usize,
                len: 0xff,
            },
        };

        let mut buf = [0u8; 0x1ff];
        BootInfo::pack(&[desc1.clone(), desc2.clone()], &mut buf);
        let mut descriptors = BootInfoIterator::new(&buf).unwrap();
        let desc1_check = descriptors.next().unwrap();
        let desc2_check = descriptors.next().unwrap();

        assert_eq!(desc1, desc1_check);
        assert_eq!(desc2, desc2_check);
    }
}
