// SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(non_camel_case_types)]

use zerocopy_derive::*;

/// Table 5.8: Boot information descriptor
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub(crate) struct boot_info_descriptor {
    /// Offset 0, length 16: Name of boot information passed to the consumer.
    pub(crate) name: [u8; 16],
    /// Offset 16, length 1: Type of boot information passed to the consumer.
    /// - Bit\[7\]: Boot information type.
    ///   + b’0: Standard boot information.
    ///   + b’1: Implementation defined boot information.
    /// - Bits\[6:0\]: Boot information identifier.
    ///   + Standard boot information (bit\[7\] = b’0).
    ///     * 0: Flattened device tree (FDT).
    ///     * 1: Hand-Off Block (HOB) List.
    ///     * All other identifiers are reserved.
    ///   + Implementation defined identifiers (bit\[7\] = b’ 1).
    ///     * Identifier is defined by the implementation.
    pub(crate) typ: u8,
    /// Offset 17, length 1: Reserved (MBZ)
    pub(crate) reserved: u8,
    /// Offset 18, length 2: Flags to describe properties of boot information associated with this
    /// descriptor.
    /// - Bits\[15:4\]: Reserved (MBZ).
    /// - Bits\[3:2\]: Format of Contents field.
    ///   + b’0: Address of boot information identified by the Name and Type fields.
    ///   + b’1: Value of boot information identified by the Name and Type fields.
    ///   + All other bit encodings are reserved for future use.
    /// - Bits\[1:0\]: Format of Name field.
    ///   + b’0: Null terminated string.
    ///   + b’1: UUID encoded in little-endian byte order.
    ///   + All other bit encodings are reserved for future use.
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

/// Table 13.37: Partition information descriptor
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub(crate) struct partition_info_descriptor {
    /// Offset 0, length 2: 16-bit ID of the partition, stream or auxiliary endpoint.
    pub(crate) partition_id: u16,
    /// Offset 2, length 2:
    /// - Number of execution contexts implemented by this partition if Bit\[5:4\] = b’00 in the
    ///   Partition properties field.
    /// - ID of the proxy endpoint for a dependent peripheral device if Bit\[5:4\] = b’10 in the
    ///   Partition properties field.
    /// - Reserved and MBZ for all other encodings of the Partition properties field.
    pub(crate) exec_ctx_count_or_proxy_id: u16,
    /// Offset 4, length 4: Flags to determine partition properties.
    /// - Bit\[3:0\] has the following encoding if Bit\[5:4\] = b’00. It is Reserved and MBZ otherwise.
    ///   + Bit\[0\] has the following encoding:
    ///     * b’0: Does not support receipt of direct requests
    ///     * b’1: Supports receipt of direct requests. Count of execution contexts must be either 1
    ///       or equal to the number of PEs in the system.
    ///   + bit\[1\] has the following encoding:
    ///     * b’0: Cannot send direct requests.
    ///     * b’1: Can send direct requests.
    ///   + bit\[2\] has the following encoding:
    ///     * b’0: Cannot send and receive indirect messages.
    ///     * b’1: Can send and receive indirect messages.
    ///   + bit\[3\] has the following encoding:
    ///     * b’0: Does not support receipt of notifications.
    ///     * b’1: Supports receipt of notifications.
    /// - bit\[5:4\] has the following encoding:
    ///   + b’00: Partition ID is a PE endpoint ID.
    ///   + b’01: Partition ID is a SEPID for an independent peripheral device.
    ///   + b’10: Partition ID is a SEPID for an dependent peripheral device.
    ///   + b’11: Partition ID is an auxiliary ID.
    /// - bit\[6\] has the following encoding:
    ///   + b’0: Partition must not be informed about each VM that is created by the Hypervisor.
    ///   + b’1: Partition must be informed about each VM that is created by the Hypervisor.
    ///   + bit\[6\] is used only if the following conditions are true. It is Reserved (MBZ) in all
    ///     other scenarios.
    ///     * This ABI is invoked at the Non-secure physical FF-A instance.
    ///     * The partition is an SP that supports receipt of direct requests i.e. Bit\[0\] = b’1.
    /// - bit\[7\] has the following encoding:
    ///   + b’0: Partition must not be informed about each VM that is destroyed by the Hypervisor.
    ///   + b’1: Partition must be informed about each VM that is destroyed by the Hypervisor.
    ///   + bit\[7\] is used only if the following conditions are true. It is Reserved (MBZ) in all
    ///     other scenarios.
    ///     * This ABI is invoked at the Non-secure physical FF-A instance.
    ///     * The partition is an SP that supports receipt of direct requests i.e. Bit\[0\] = b’1.
    /// - bit\[8\] has the following encoding:
    ///   + b’0: Partition runs in the AArch32 execution state.
    ///   + b’1: Partition runs in the AArch64 execution state.
    /// - bit\[31:9\]: Reserved (MBZ).
    pub(crate) partition_props: u32,
    /// Offset 8, length 16:
    /// - UUID of the partition, stream or auxiliary endpoint if the Nil UUID was specified in w1-w4
    ///   as an input parameter.
    /// - This field is reserved and MBZ if a non-Nil UUID was was specified in w1-w4 as an input
    ///   parameter.
    pub(crate) uuid: [u8; 16],
}
