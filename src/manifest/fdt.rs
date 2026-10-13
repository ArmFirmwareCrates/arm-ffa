// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FF-A manifest parsing from the flattened device tree (FDT) format.
//!
//! Uses the [Trusted Firmware-A manifest bindings]. Available with the `manifest-fdt` feature.
//!
//! [Trusted Firmware-A manifest bindings]: https://trustedfirmware-a.readthedocs.io/en/latest/components/ffa-manifest-binding.html

use super::{ExecutionState, SpmcManifest};
use crate::{FFA_PAGE_SIZE_4K, Version};
use dtoolkit::{
    FromPropertyValue, Node, Property,
    error::{FdtParseError, PropertyError},
    fdt::{Fdt, FdtNode},
    standard::NodeStandard,
};
use thiserror::Error;

/// Errors returned when parsing a manifest from an FDT.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("Invalid FDT: {0}")]
    InvalidFdt(#[from] FdtParseError),
    #[error("Unsupported compatible string")]
    NotCompatible,
    #[error("Missing SPMC attribute node")]
    MissingAttributeNode,
    #[error("Missing property {0}")]
    MissingProperty(&'static str),
    #[error("Invalid property {property}: {source}")]
    InvalidProperty {
        property: &'static str,
        #[source]
        source: PropertyError,
    },
    #[error("Invalid value {value:#x} for property {property}: {reason}")]
    InvalidPropertyValue {
        property: &'static str,
        value: u64,
        reason: &'static str,
    },
}

impl SpmcManifest {
    /// Parses a device tree blob into an SPMC manifest.
    ///
    /// `maj_ver`, `min_ver`, and `exec_state` properties are required. `spmc_id`, `load_address`,
    /// and `entrypoint` properties are optional. This parser requires `load_address` when
    /// `entrypoint` is supplied so that the absolute entry point can be converted to an offset.
    /// A supplied load address must be aligned to 4 KiB.
    ///
    /// The binding does not define SPMC boot-information or cold-boot register properties, so those
    /// fields are returned as `None`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](enum@Error) if the FDT is malformed, the compatible string is not
    /// supported, required data is missing, or a property has the wrong size or an invalid value.
    pub fn new_from_fdt(data: &[u8]) -> Result<SpmcManifest, Error> {
        let fdt = Fdt::new(data)?;
        let root = fdt.root();

        let mut compatibles = root
            .compatible()
            .ok_or(Error::MissingProperty("compatible"))?;

        if !compatibles.any(|s| s == "arm,ffa-core-manifest-1.0") {
            return Err(Error::NotCompatible);
        }

        let attribute = root.child("attribute").ok_or(Error::MissingAttributeNode)?;

        let major_raw = mandatory_property::<u32>(&attribute, "maj_ver")?;
        let major_version = u16::try_from(major_raw).map_err(|_| Error::InvalidPropertyValue {
            property: "maj_ver",
            value: u64::from(major_raw),
            reason: "Major version exceeds 16 bits",
        })?;

        let minor_raw = mandatory_property::<u32>(&attribute, "min_ver")?;
        let minor_version = u16::try_from(minor_raw).map_err(|_| Error::InvalidPropertyValue {
            property: "min_ver",
            value: u64::from(minor_raw),
            reason: "Minor version exceeds 16 bits",
        })?;

        let version =
            Version::new(major_version, minor_version).ok_or(Error::InvalidPropertyValue {
                property: "maj_ver",
                value: major_version as u64,
                reason: "Invalid major version",
            })?;

        let execution_state = match mandatory_property::<u32>(&attribute, "exec_state")? {
            0 => Ok(ExecutionState::Aarch64),
            1 => Ok(ExecutionState::Aarch32),
            value => Err(Error::InvalidPropertyValue {
                property: "exec_state",
                value: value.into(),
                reason: "Invalid execution state",
            }),
        }?;

        let spmc_id = optional_property::<u32>(&attribute, "spmc_id")
            .transpose()?
            .map(|id| {
                u16::try_from(id).map_err(|_| Error::InvalidPropertyValue {
                    property: "spmc_id",
                    value: u64::from(id),
                    reason: "SPMC ID exceeds 16 bits",
                })
            })
            .transpose()?;

        let load_address = optional_property::<u64>(&attribute, "load_address").transpose()?;

        if let Some(address) = load_address
            && !address.is_multiple_of(FFA_PAGE_SIZE_4K as u64)
        {
            return Err(Error::InvalidPropertyValue {
                property: "load_address",
                value: address,
                reason: "Not aligned to 4 KiB",
            });
        };

        let entry_point = optional_property::<u64>(&attribute, "entrypoint").transpose()?;

        let entry_point_offset = match (entry_point, load_address) {
            (Some(ep), Some(base)) => {
                Some(ep.checked_sub(base).ok_or(Error::InvalidPropertyValue {
                    property: "entrypoint",
                    value: ep,
                    reason: "Entry point is before load address",
                })?)
            }
            (Some(_), None) => return Err(Error::MissingProperty("load_address")),
            (None, _) => None,
        };

        let binary_size = optional_property::<u32>(&attribute, "binary_size").transpose()?;

        if let Some(0) = binary_size {
            return Err(Error::InvalidPropertyValue {
                property: "binary_size",
                value: 0,
                reason: "Binary size must be non-zero",
            });
        }

        if let Some(load_address) = load_address
            && let Some(binary_size) = binary_size
        {
            let entry_point = entry_point.unwrap_or(load_address);

            let end_address = load_address.checked_add(binary_size as u64).ok_or(
                Error::InvalidPropertyValue {
                    property: "binary_size",
                    value: binary_size as u64,
                    reason: "Overflow when calculating end address",
                },
            )?;

            if end_address <= entry_point {
                return Err(Error::InvalidPropertyValue {
                    property: "entrypoint",
                    value: entry_point,
                    reason: "Entry point is after the end of the binary",
                });
            }
        }

        Ok(SpmcManifest {
            version,
            spmc_id,
            execution_state,
            load_address,
            entry_point_offset,
            ffa_boot_info_reg: None,
            cold_boot_reason_reg: None,
        })
    }
}

fn mandatory_property<'a, T: FromPropertyValue<'a>>(
    node: &'a FdtNode,
    name: &'static str,
) -> Result<T, Error> {
    node.property(name)
        .ok_or(Error::MissingProperty(name))?
        .value_as::<T>()
        .map_err(|e| Error::InvalidProperty {
            property: name,
            source: e,
        })
}

fn optional_property<'a, T: FromPropertyValue<'a>>(
    node: &'a FdtNode,
    name: &'static str,
) -> Option<Result<T, Error>> {
    node.property(name).map(|p| {
        p.value_as::<T>().map_err(|e| Error::InvalidProperty {
            property: name,
            source: e,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtoolkit::{
        ToPropertyValue,
        model::{DeviceTree, DeviceTreeNode, DeviceTreeProperty},
    };

    fn manifest_tree() -> DeviceTree {
        let mut tree = DeviceTree::new();
        tree.root.add_property(
            DeviceTreeProperty::new("compatible", "arm,ffa-core-manifest-1.0").unwrap(),
        );
        tree.root
            .add_child(DeviceTreeNode::new("attribute").unwrap());
        set_attribute(&mut tree, "maj_ver", 1u32);
        set_attribute(&mut tree, "min_ver", 3u32);
        set_attribute(&mut tree, "exec_state", 0u32);
        tree
    }

    fn set_attribute(tree: &mut DeviceTree, name: &str, value: impl ToPropertyValue) {
        tree.root
            .child_mut("attribute")
            .unwrap()
            .add_property(DeviceTreeProperty::new(name, value).unwrap());
    }

    #[test]
    fn parse_minimal_spmc_manifest() {
        for (value, state) in [
            (0u32, ExecutionState::Aarch64),
            (1, ExecutionState::Aarch32),
        ] {
            let mut tree = manifest_tree();
            set_attribute(&mut tree, "exec_state", value);

            let manifest = SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap();
            assert_eq!(manifest.version, Version::V1_3);
            assert_eq!(manifest.execution_state, state);
            assert_eq!(manifest.spmc_id, None);
            assert_eq!(manifest.load_address, None);
            assert_eq!(manifest.entry_point_offset, None);
            assert_eq!(manifest.ffa_boot_info_reg, None);
            assert_eq!(manifest.cold_boot_reason_reg, None);
        }
    }

    #[test]
    fn parse_spmc_manifest_with_optional_properties() {
        let mut tree = manifest_tree();
        set_attribute(&mut tree, "spmc_id", 0x8000u32);
        set_attribute(&mut tree, "load_address", 0x0600_0000u64);
        set_attribute(&mut tree, "entrypoint", 0x0600_1000u64);
        set_attribute(&mut tree, "binary_size", 0x8_0000u32);

        let manifest = SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap();
        assert_eq!(manifest.version, Version::V1_3);
        assert_eq!(manifest.execution_state, ExecutionState::Aarch64);
        assert_eq!(manifest.spmc_id, Some(0x8000));
        assert_eq!(manifest.load_address, Some(0x0600_0000));
        assert_eq!(manifest.entry_point_offset, Some(0x1000));
    }

    #[test]
    fn parse_spmc_manifest_entry_point_offsets() {
        let load_address = 0x0600_0000u64;
        for (entry_point, expected_offset) in [
            (None, None),
            (Some(load_address), Some(0)),
            (Some(load_address + 0x1000), Some(0x1000)),
        ] {
            let mut tree = manifest_tree();
            set_attribute(&mut tree, "load_address", load_address);
            if let Some(ep) = entry_point {
                set_attribute(&mut tree, "entrypoint", ep);
            }

            let manifest = SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap();
            assert_eq!(manifest.load_address, Some(load_address));
            assert_eq!(manifest.entry_point_offset, expected_offset);
        }
    }

    #[test]
    fn reject_zero_size_binary() {
        let mut tree = manifest_tree();
        set_attribute(&mut tree, "load_address", 0x0600_0000u64);
        set_attribute(&mut tree, "binary_size", 0u32);

        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::InvalidPropertyValue {
                property: "binary_size",
                value: 0,
                reason: "Binary size must be non-zero",
            }
        );
    }

    #[test]
    fn reject_entry_point_without_load_address() {
        for entry_point in [0u64, 0x0600_1000] {
            let mut tree = manifest_tree();
            set_attribute(&mut tree, "entrypoint", entry_point);

            assert_eq!(
                SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
                Error::MissingProperty("load_address")
            );
        }
    }

    #[test]
    fn reject_entry_point_before_load_address() {
        let mut tree = manifest_tree();
        set_attribute(&mut tree, "load_address", 0x0600_0000u64);
        set_attribute(&mut tree, "entrypoint", 0x05ff_ffffu64);

        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::InvalidPropertyValue {
                property: "entrypoint",
                value: 0x05ff_ffff,
                reason: "Entry point is before load address",
            }
        );
    }

    #[test]
    fn reject_entry_point_after_binary_end() {
        let mut tree = manifest_tree();
        set_attribute(&mut tree, "load_address", 0x0600_0000u64);
        set_attribute(&mut tree, "entrypoint", 0x0600_1000u64);
        set_attribute(&mut tree, "binary_size", 0x1000u32);

        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::InvalidPropertyValue {
                property: "entrypoint",
                value: 0x0600_1000,
                reason: "Entry point is after the end of the binary",
            }
        );
    }

    #[test]
    fn reject_spmc_id_overflow() {
        let mut tree = manifest_tree();
        set_attribute(&mut tree, "spmc_id", 0x1_8001u32);

        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::InvalidPropertyValue {
                property: "spmc_id",
                value: 0x1_8001,
                reason: "SPMC ID exceeds 16 bits",
            }
        );
    }

    #[test]
    fn reject_invalid_fdt() {
        assert!(matches!(
            SpmcManifest::new_from_fdt(&[]),
            Err(Error::InvalidFdt(_))
        ));

        let mut data = manifest_tree().to_dtb();

        // Corrupt the FDT magic number
        data[0] = 0;
        assert!(matches!(
            SpmcManifest::new_from_fdt(&data),
            Err(Error::InvalidFdt(_))
        ));
    }

    #[test]
    fn reject_missing_manifest_data() {
        let mut tree = manifest_tree();
        tree.root.remove_property("compatible");
        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::MissingProperty("compatible")
        );

        let mut tree = manifest_tree();
        tree.root.remove_child("attribute");
        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::MissingAttributeNode
        );

        for property in ["maj_ver", "min_ver", "exec_state"] {
            let mut tree = manifest_tree();
            tree.root
                .child_mut("attribute")
                .unwrap()
                .remove_property(property);
            assert_eq!(
                SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
                Error::MissingProperty(property)
            );
        }
    }

    #[test]
    fn reject_unsupported_compatible() {
        let mut tree = manifest_tree();
        tree.root
            .add_property(DeviceTreeProperty::new("compatible", "arm,ffa-manifest-1.0").unwrap());
        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::NotCompatible
        );
    }

    #[test]
    fn reject_invalid_property_sizes() {
        // Exercise both mandatory and optional property conversions.
        for property in ["maj_ver", "load_address"] {
            let mut tree = manifest_tree();
            set_attribute(&mut tree, property, [0u8; 2]);
            assert_eq!(
                SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
                Error::InvalidProperty {
                    property,
                    source: PropertyError::InvalidLength,
                }
            );
        }
    }

    #[test]
    fn reject_invalid_property_values() {
        let mut tree = manifest_tree();
        set_attribute(&mut tree, "exec_state", 2u32);
        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::InvalidPropertyValue {
                property: "exec_state",
                value: 2,
                reason: "Invalid execution state",
            }
        );

        let mut tree = manifest_tree();
        set_attribute(&mut tree, "load_address", 0x0600_0001u64);
        assert_eq!(
            SpmcManifest::new_from_fdt(&tree.to_dtb()).unwrap_err(),
            Error::InvalidPropertyValue {
                property: "load_address",
                value: 0x0600_0001,
                reason: "Not aligned to 4 KiB",
            }
        );
    }
}
