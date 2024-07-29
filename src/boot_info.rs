// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use uuid::Uuid;

pub enum BootInfoName {
    NullTermString(&'static str),
    Uuid(Uuid),
}

#[derive(Clone, Copy)]
pub enum BootInfoStdType {
    Fdt = 0,
    Hob = 1,
}

pub enum BootInfoType {
    Std(BootInfoStdType),
    Impdef(u8),
}

pub enum BootInfoContents {
    Address(usize),
    Value(u64),
}

pub struct BootInfoDescriptor {
    /// Name of boot information passed to the consumer
    pub name: BootInfoName,

    /// Type of boot information passed to the consumer
    pub typ: BootInfoType,

    /// Size (in bytes) of boot information identified by the Name and Type fields
    pub size: u32,

    pub contents: BootInfoContents,
}

impl BootInfoDescriptor {
    pub fn create(descriptors: &[BootInfoDescriptor], buf: &mut [u8]) {
        // Offset from the base of the header to the first element in the boot info descriptor array
        // Must be 8 byte aligned
        const DESC_ARRAY_OFFSET: usize = 32;

        /// In FF-A v1.1, Table 5.8: Boot information descriptor is 32 bytes long
        const DESC_SIZE: usize = 32;

        // assert!(descriptors.len() <= u32::MAX as usize);
        let desc_cnt = descriptors.len();

        // Add the already known fields, later we have to add the sizes referenced by the individual descriptors
        let mut total_size = 0usize;
        total_size = total_size.checked_add(DESC_ARRAY_OFFSET).unwrap();
        total_size = total_size
            .checked_add(desc_cnt.checked_mul(DESC_SIZE).unwrap())
            .unwrap();

        // Create the boot info header starting at offset 0 in the buffer
        // Offset 0, length 4: Hexadecimal value 0x0FFA to identify the header
        buf[0..4].copy_from_slice(&0x0ffa_u32.to_le_bytes());

        // Offset 4, length 4: Version of the boot information blob encoded as in FFA_VERSION_GET
        buf[4..8].copy_from_slice(&0x0001_0001_u32.to_le_bytes());

        // Offset 12, length 4: Size of each boot information descriptor in the array
        buf[12..16].copy_from_slice(&(DESC_SIZE as u32).to_le_bytes());

        // Offset 16, length 4: Count of boot information descriptors in the array
        buf[16..20].copy_from_slice(&(desc_cnt as u32).to_le_bytes());

        // Offset 20, length 4: Offset to array of boot information descriptors
        buf[20..24].copy_from_slice(&(DESC_ARRAY_OFFSET as u32).to_le_bytes());

        // Offset 24, length 8: Reserved (MBZ)
        buf[24..32].fill(0);

        // Fill the boot info descriptor array, all offset based from DESC_ARRAY_OFFSET
        let mut offset = DESC_ARRAY_OFFSET;
        for desc in descriptors {
            // Offset 0, length 16: Name of boot information passed to the consumer
            match &desc.name {
                BootInfoName::NullTermString(name) => {
                    assert!(name.is_ascii());
                    let name_len = name.len().min(15);
                    buf[offset..offset + name_len].copy_from_slice(&name.as_bytes()[..name_len]);
                    buf[offset + name_len..offset + 16].fill(0); // Make sure it's null terminated
                }
                BootInfoName::Uuid(uuid) => {
                    buf[offset..offset + 16].copy_from_slice(&uuid.to_bytes_le());
                }
            }

            // Offset 16, length 1: Type of boot information passed to the consumer
            let info_type = match desc.typ {
                BootInfoType::Std(std_type) => (std_type as u8) & 0b0111_1111,
                BootInfoType::Impdef(typ) => (0b1 << 7) | typ,
            };
            buf[offset + 16] = info_type;

            // Offset 17, length 1: Reserved (MBZ)
            buf[offset + 17] = 0;

            // Offset 18, length 2: Flags to describe properties of boot information associated with this descriptor
            let mut flags = 0u16;
            if let BootInfoName::Uuid(_) = &desc.name {
                flags |= 0b1;
            }
            if let BootInfoContents::Value(_) = desc.contents {
                flags |= 0b1 << 2;
            }
            buf[offset + 18..offset + 20].copy_from_slice(&flags.to_le_bytes());

            // Offset 20, length 4: Size (in bytes) of boot information identified by the Name and Type fields.
            match desc.contents {
                BootInfoContents::Address(_) => {
                    total_size = total_size.checked_add(desc.size as usize).unwrap();
                }
                BootInfoContents::Value(_) => {
                    assert!((1..=8).contains(&desc.size));
                }
            }
            buf[offset + 20..offset + 24].copy_from_slice(&desc.size.to_le_bytes());

            // Offset 24, length 8: Value or address of boot information identified by the Name and Type fields.
            // Value or address of boot information identified by the Name and Type fields.
            //
            // If in the Flags field, bit\[3:2\] = b'0,
            // * The address has the same attributes as the boot information blob address described in
            //   5.4.3 Boot information address.
            // * Size field contains the length (in bytes) of boot information at the specified address.
            //
            // If in the Flags field, bit\[3:2\] = b’1,
            // * Size field contains the exact size of the value specified in this field.
            // * Size is >=1 bytes and <= 8 bytes.
            let content = match desc.contents {
                BootInfoContents::Address(addr) => addr as u64,
                BootInfoContents::Value(val) => val,
            };
            buf[offset + 24..offset + 32].copy_from_slice(&content.to_le_bytes());

            offset += DESC_SIZE;
        }

        // TODO: add padding size between boot information referenced by the descriptors

        // Offset 8, length 4: Size of boot information blob spanning contiguous memory
        assert!(buf.len() <= u32::MAX as usize);
        assert!(total_size <= buf.len());
        buf[8..12].copy_from_slice(&(total_size as u32).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::uuid;

    #[test]
    fn boot_info() {
        let desc1 = BootInfoDescriptor {
            name: BootInfoName::NullTermString(&"test1234test1234"),
            typ: BootInfoType::Impdef(0xab),
            size: 4,
            contents: BootInfoContents::Value(0xbeef),
        };

        let fdt = [0u8; 0xff];
        let desc2 = BootInfoDescriptor {
            name: BootInfoName::Uuid(uuid!("12345678-1234-1234-1234-123456789abc")),
            typ: BootInfoType::Std(BootInfoStdType::Fdt),
            size: 0xff,
            contents: BootInfoContents::Address(&fdt as *const u8 as usize),
        };

        let mut buf = [0u8; 0x1ff];
        BootInfoDescriptor::create(&[desc1, desc2], &mut buf);

        println!("{:#x?}", &buf[0..0x0f]);
    }
}
