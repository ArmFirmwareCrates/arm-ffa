// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(non_camel_case_types)]

use zerocopy_derive::*;

/// Table 5.8: Boot information descriptor
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub(crate) struct boot_info_descriptor {
    /// Offset 0, length 16: Name of boot information passed to the consumer
    pub(crate) name: [u8; 16],
    /// Offset 16, length 1: Type of boot information passed to the consumer
    pub(crate) typ: u8,
    /// Offset 17, length 1: Reserved (MBZ)
    pub(crate) reserved: u8,
    /// Offset 18, length 2: Flags to describe properties of boot information associated with this
    /// descriptor
    pub(crate) flags: u16,
    /// Offset 20, length 4: Size (in bytes) of boot information identified by the Name and Type
    /// fields
    pub(crate) size: u32,
    /// Offset 24, length 8: Value or address of boot information identified by the Name and Type
    /// fields.
    ///
    /// If in the Flags field, bit\[3:2\] = b'0,
    /// * The address has the same attributes as the boot information blob address described in
    ///   5.4.3 Boot information address.
    /// * Size field contains the length (in bytes) of boot information at the specified address.
    ///
    /// If in the Flags field, bit\[3:2\] = b’1,
    /// * Size field contains the exact size of the value specified in this field.
    /// * Size is >=1 bytes and <= 8 bytes.
    pub(crate) contents: u64,
}

/// Table 5.9: Boot information header
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub(crate) struct boot_info_header {
    /// Offset 0, length 4: Hexadecimal value 0x0FFA to identify the header
    pub(crate) signature: u32,
    /// Offset 4, length 4: Version of the boot information blob encoded as in FFA_VERSION_GET
    pub(crate) version: u32,
    /// Offset 8, length 4: Size of boot information blob spanning contiguous memory
    pub(crate) boot_info_blob_size: u32,
    /// Offset 12, length 4: Size of each boot information descriptor in the array
    pub(crate) boot_info_desc_size: u32,
    /// Offset 16, length 4: Count of boot information descriptors in the array
    pub(crate) boot_info_desc_count: u32,
    /// Offset 20, length 4: Offset to array of boot information descriptors
    pub(crate) boot_info_array_offset: u32,
    /// Offset 24, length 8: Reserved (MBZ)
    pub(crate) reserved: u64,
}
