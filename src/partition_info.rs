// SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use uuid::Uuid;

pub enum PartitionIdType {
    PeEndpoint(u16),
    SepidIndep,
    SepidDep(u16),
    Aux,
}

pub struct PartInfoDesc {
    pub partition_id: u16,
    pub uuid: Uuid,
    pub id_type: PartitionIdType,
    pub support_direct_req_rec: bool,
    pub support_direct_req_send: bool,
    pub support_indirect_msg: bool,
    pub support_notif_rec: bool,
    pub subscribe_vm_created: bool,
    pub subscribe_vm_destroyed: bool,
    pub is_aarch64: bool,
}

impl PartInfoDesc {
    pub const SIZE: usize = 24;
}

pub fn create_partition_info(buf: &mut [u8], descriptors: &[PartInfoDesc], fill_uuid: bool) {
    let mut offset = 0;

    for desc in descriptors {
        // Offset 0, length 2: 16-bit ID of the partition, stream or auxiliary endpoint.
        buf[offset..offset + 2].copy_from_slice(&desc.partition_id.to_le_bytes());

        // Offset 2, length 2: Execution context count or Proxy partition ID
        match desc.id_type {
            PartitionIdType::PeEndpoint(exec_ctx_cnt) => {
                buf[offset + 2..offset + 4].copy_from_slice(&exec_ctx_cnt.to_le_bytes())
            }
            PartitionIdType::SepidDep(id) => {
                buf[offset + 2..offset + 4].copy_from_slice(&id.to_le_bytes())
            }
            _ => buf[offset + 2..offset + 4].fill(0),
        }

        // Offset 4, length 4: Flags to determine partition properties.
        let mut props = 0u32;
        match desc.id_type {
            PartitionIdType::PeEndpoint(_) => {
                if desc.support_direct_req_rec {
                    props |= 0b1;
                    if desc.subscribe_vm_created {
                        // TODO: check NS phys instance
                        props |= 0b1 << 6
                    }
                    if desc.subscribe_vm_destroyed {
                        // TODO: check NS phys instance
                        props |= 0b1 << 7
                    }
                }
                if desc.support_direct_req_send {
                    props |= 0b1 << 1
                }
                if desc.support_indirect_msg {
                    props |= 0b1 << 2
                }
                if desc.support_notif_rec {
                    props |= 0b1 << 3
                }
            }
            PartitionIdType::SepidIndep => props |= 0b01 << 4,
            PartitionIdType::SepidDep(_) => props |= 0b10 << 4,
            PartitionIdType::Aux => props |= 0b11 << 4,
        }
        if desc.is_aarch64 {
            props |= 0b1 << 8
        }
        buf[offset + 4..offset + 8].copy_from_slice(&props.to_le_bytes());

        // Offset 8, length 16: Partition UUID if the Nil UUID was specified. Reserved (MBZ) otherwise
        if fill_uuid {
            buf[offset + 8..offset + 24].copy_from_slice(desc.uuid.as_bytes());
        } else {
            buf[offset + 8..offset + 24].fill(0);
        }

        offset += PartInfoDesc::SIZE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::uuid;

    #[test]
    fn part_info() {
        let desc = PartInfoDesc {
            partition_id: 0x8001,
            uuid: uuid!("12345678-1234-1234-1234-123456789abc"),
            id_type: PartitionIdType::PeEndpoint(1),
            support_direct_req_rec: true,
            support_direct_req_send: true,
            support_indirect_msg: false,
            support_notif_rec: false,
            subscribe_vm_created: true,
            subscribe_vm_destroyed: true,
            is_aarch64: true,
        };

        let mut buf = [0u8; 0xff];
        create_partition_info(&mut buf, &[desc], true);

        println!("{:#x?}", &buf[0..0x0f]);

        assert_eq!(0x8001_u16, u16::from_le_bytes([buf[0], buf[1]]));
    }
}
