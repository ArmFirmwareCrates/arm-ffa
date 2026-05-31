// SPDX-FileCopyrightText: Copyright The arm-ffa Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FF-A manifest data structures.
//!
//! This module defines the data structures used to represent FF-A partition and SPMC manifests.

use crate::Version;
use uuid::Uuid;

/// Messaging methods supported by a partition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MessagingMethods {
    /// The partition can send requests using `FFA_MSG_SEND_DIRECT_REQ`.
    pub send_direct_req: bool,
    /// The partition can send requests using `FFA_MSG_SEND_DIRECT_REQ2`.
    pub send_direct_req2: bool,
    /// The partition can receive requests using `FFA_MSG_SEND_DIRECT_REQ`.
    pub receive_direct_req: bool,
    /// The partition can receive requests using `FFA_MSG_SEND_DIRECT_REQ2`.
    pub receive_direct_req2: bool,
    /// The partition can send and receive indirect messages.
    pub support_indirect_msg: bool,
}

/// Messaging methods associated with a protocol UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolMessagingMethods {
    /// UUID of the protocol to which the messaging methods apply.
    pub protocol_uuid: Uuid,
    /// Messaging methods through which the protocol is accessible.
    pub messaging_methods: MessagingMethods,
}

/// Inter-partition setup protocol messages supported by a partition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpspMessages {
    /// Whether notification registration messages are supported.
    pub notification_registration: bool,
    /// Whether notification unregistration messages are supported.
    pub notification_unregistration: bool,
}

/// Inter-partition setup protocol messages associated with a protocol UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolIpspMessages {
    /// UUID of the protocol to which the message support applies.
    pub protocol_uuid: Uuid,
    /// Inter-partition setup protocol messages used by the protocol.
    pub ipsp_messages: IpspMessages,
}

/// Exception level at which a partition runs.
///
/// In case of `El1`, the `primary_scheduler` field indicates whether the partition implements the
/// primary scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEl {
    SEl0,
    SEl1,
    El1 { primary_scheduler: bool },
}

/// Execution state of a partition or SPMC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionState {
    Aarch32,
    Aarch64,
}

/// Translation granule used by a partition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TranslationGranule {
    #[default]
    Granule4K = 4 * 1024,
    Granule16K = 16 * 1024,
    Granule64K = 64 * 1024,
}

/// Reference to memory region entries that describe the RX/TX buffers expected by the partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxTxInfo<'a> {
    /// Reference to the memory region describing the RX buffer.
    pub rx: &'a MemoryRegion<'a>,
    /// Reference to the memory region describing the TX buffer.
    pub tx: &'a MemoryRegion<'a>,
}

/// Number of notification IDs requested for the partition.
///
/// Default is 64, extended notification support allows up to 384 inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotificationCount(u16);

impl NotificationCount {
    const MIN: u16 = 64;
    const MAX: u16 = 384;

    /// Creates a notification count if `count` is within the permitted range.
    pub const fn new(count: u16) -> Option<Self> {
        if Self::MIN <= count && count <= Self::MAX {
            Some(Self(count))
        } else {
            None
        }
    }

    /// Returns the notification count.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for NotificationCount {
    fn default() -> Self {
        Self(Self::MIN)
    }
}

/// Notification support requested by the partition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotificationInfo {
    /// Number of VM notification IDs requested for the partition.
    pub vm_notification_count: NotificationCount,
    /// Number of SP notification IDs requested for the partition.
    pub sp_notification_count: NotificationCount,
}

/// Action taken by the SPMC in response to a physical Non-secure interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonSecureInterruptAction {
    Signal,
    ManagedExit,
    Queue,
}

/// Association between a stream endpoint ID and device stream IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEndpoint<'a> {
    /// Stream endpoint ID that this endpoint is a proxy for.
    ///
    /// The dependent device must not be assigned to this endpoint.
    pub sepid: u16,
    /// Identifier of the SMMU instance (on a system with multiple SMMUs).
    pub smmu_id: u32,
    /// Stream IDs that associate the device that generates them with the SEPID in the SMMU
    /// identified by `smmu_id`.
    pub stream_ids: &'a [u32],
    /// Optional name of the stream endpoint for debugging purposes.
    pub name: Option<&'a str>,
}

/// VM availability messages in which a secure partition is interested.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmAvailabilityMessages {
    /// Receive messages when a VM is created.
    pub created: bool,
    /// Receive messages when a VM is destroyed.
    pub destroyed: bool,
}

/// Power-management messages in which a secure partition is interested.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PowerManagementMessages<'a> {
    /// PSCI function IDs for the operations about which the partition must be informed.
    pub psci_function_ids: &'a [u32],
    /// Receive messages about warm boot operations.
    pub warm_boot: bool,
}

/// Parameter register used to pass the cold-boot reason.
///
/// The execution state determines whether the corresponding `w` or `x` register is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ColdBootReasonRegister {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
}

/// AArch64 parameter register used to pass live-activation status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LiveActivationRegister {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
}

/// Live-activation support information for a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveActivationInfo {
    /// Whether CPU rendezvous is required before live activation.
    pub cpu_rendezvous_required: bool,
    /// Register that describes if the partition is undergoing live activation when its first
    /// execution context enters the starting state.
    ///
    /// The register must be distinct from the following registers:
    /// - Cold boot reason register.
    /// - Boot information address register.
    pub live_activation_info_reg: LiveActivationRegister,
}

/// Properties of a partition described by its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionProperties<'a> {
    /// Version of FF-A expected by the partition at the FF-A instance it will execute.
    pub version: Version,
    /// Pre-allocated partition ID.
    pub partition_id: Option<u16>,
    /// List of protocol UUIDs associated with the partition.
    pub protocol_uuids: &'a [Uuid],
    /// The image UUID of this partition.
    pub image_uuid: Option<Uuid>,
    /// Messaging methods supported by the partition for each exported UUID.
    pub messaging_methods: MessagingMethods,
    /// Per-protocol messaging-method mappings.
    ///
    /// If the partition is associated with multiple protocol UUIDs and a subset of UUIDs are
    /// accessible by a specific messaging method, a mapping between a protocol UUID and messaging
    /// method can be provided via this field.
    pub protocol_messaging_methods: Option<&'a [ProtocolMessagingMethods]>,
    /// Inter-partition setup protocol messages supported by the partition for each exported UUID.
    pub ipsp_messages: IpspMessages,
    /// Per-protocol inter-partition setup protocol messages mapping.
    ///
    /// If the partition is associated with multiple protocol UUIDs and a subset of UUIDs are
    /// accessible by a specific inter-partition setup protocol messages, a mapping between a
    /// protocol UUID and supported protocol messages is provided via this field.
    pub protocol_ipsp_messages: Option<&'a [ProtocolIpspMessages]>,
    /// Pre-allocated auxiliary IDs.
    ///
    /// List of pre-allocated 16-bit IDs that could be used in memory management transactions to
    /// allow a partition manager to handle the transaction in an implementation-defined manner.
    pub auxiliary_ids: Option<&'a [u16]>,
    /// Optional partition name, for debugging purposes.
    pub name: Option<&'a str>,
    /// Number of execution contexts implemented by the partition.
    ///
    /// If value of this field = 1 and number of PEs > 1 then the partition is treated as UP and
    /// migrate capable. If the value of this field > 1 then the partition is treated as an MP
    /// capable partition irrespective of the number of PEs.
    pub execution_ctx_count: u16,
    /// Exception level at which the partition runs.
    pub runtime_el: RuntimeEl,
    /// Execution state of the partition.
    pub execution_state: ExecutionState,
    /// Address at which the partition image must be loaded.
    ///
    /// Absence indicates that the image is position-independent.
    pub load_address: Option<u64>,
    /// Entry-point offset from the base of the partition image.
    ///
    /// Absence means an offset of zero.
    pub entry_point_offset: Option<u64>,
    /// Translation granule used by the partition.
    ///
    /// Absence means 4 KiB is used.
    pub translation_granule: Option<TranslationGranule>,
    /// A unique number among all partitions that specifies if this partition must be booted before
    /// others.
    pub boot_order: Option<u16>,
    /// Reference to memory region entries in this manifest that describes the RX/TX buffers
    /// expected by the partition.
    ///
    /// The memory region entries must specify the base addresses of both buffers.
    pub rxtx_info: Option<RxTxInfo<'a>>,
    /// Specifies the count of VM and SP notifications requested for the partition.
    ///
    /// If the partition manager does not support the count requested, the partition manager does
    /// not boot the endpoint. Absence indicates that the partition cannot receive notifications.
    pub notification_support: Option<NotificationInfo>,
    /// Specifies the action that the SPMC must take in response to a non-secure physical interrupt.
    pub ns_interrupt_action: NonSecureInterruptAction,
    /// Stream endpoint associations for devices proxied by the partition.
    pub stream_endpoints: Option<&'a [StreamEndpoint<'a>]>,
    /// VM availability messages the partition is interested in receiving.
    pub vm_availability_messages: Option<VmAvailabilityMessages>,
    /// Power-management messages the partition is interested in receiving.
    pub power_management_messages: Option<PowerManagementMessages<'a>>,
    /// Parameter register in which the cold-boot reason is passed.
    ///
    /// Presence of this field indicates that the partition expects that the entry point offset
    /// field must be reused for a secondary cold boot.
    ///
    /// The specified register must be distinct from the register used to carry the address of the
    /// boot information blob specified in the manifest.
    pub cold_boot_reason_reg: Option<ColdBootReasonRegister>,
    /// Whether the partition can be live activated.
    ///
    /// The Image UUID field in the partition manifest is mandatory if it can be live activated.
    pub live_activation_supported: Option<LiveActivationInfo>,
    /// Whether the partition supports the SMC64 CPU cycle management function IDs.
    pub smc64_cpu_cycle_management: bool,
}

/// Location of a memory region assigned to a partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegionAddress {
    /// Physical, virtual, or intermediate physical base address of the region.
    BaseAddress(u64),
    /// Positive offset from the load address of an S-EL0 partition image.
    LoadRelativeOffset(u64),
}

/// Instruction access permission for a memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionAccessPermission {
    NotExecutable,
    Executable,
}

/// Data access permission for a memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataAccessPermission {
    ReadOnly,
    ReadWrite,
}

/// Security state of a memory region or interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityState {
    Secure,
    NonSecure,
}

/// Device memory type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceMemoryType {
    DevicenGnRnE,
    DevicenGnRE,
    DevicenGRE,
    DeviceGRE,
}

/// Cacheability of normal memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cacheability {
    NonCacheable,
    WriteThrough,
    WriteBack,
}

/// Shareability of normal memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shareability {
    NonShareable,
    InnerShareable,
    OuterShareable,
}

/// Type and cache attributes of a memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryType {
    Device(DeviceMemoryType),
    Normal {
        cacheability: Cacheability,
        shareability: Shareability,
    },
}

/// Access, type, and security attributes of a memory region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegionAttributes {
    /// Instruction access permission.
    pub instruction_access: InstructionAccessPermission,
    /// Data access permission.
    pub data_access: DataAccessPermission,
    /// Memory type and cache attributes.
    pub memory_type: MemoryType,
    /// Security state of the region.
    pub security_state: SecurityState,
}

/// An SMMU and the stream IDs associated with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmmuStreamIds<'a> {
    /// Identifier of the SMMU instance.
    pub smmu_id: u32,
    /// Stream IDs associated with the SMMU instance.
    pub stream_ids: &'a [u32],
}

/// Device access permissions for a stream ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamIdAccessPermissions {
    /// Stream ID to which the permissions apply.
    pub stream_id: u32,
    /// Instruction access permission for the stream.
    pub instruction_access: InstructionAccessPermission,
    /// Data access permission for the stream.
    pub data_access: DataAccessPermission,
}

/// Memory region assigned to a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion<'a> {
    /// Address or load-relative offset of the region.
    ///
    /// If absent, the partition manager chooses the address and describes it to the partition
    /// through an implementation-defined mechanism.
    pub address: Option<MemoryRegionAddress>,
    /// Size of the region as a count of 4 KiB pages.
    pub page_count: u32,
    /// Access, memory, and security attributes of the region.
    pub attributes: MemoryRegionAttributes,
    /// Whether the region is guarded using the Branch Target Identification mechanism.
    pub guarded: bool,
    /// Optional memory region name, for debugging purposes.
    pub name: Option<&'a str>,
    /// SMMU and stream IDs of devices that can access this region.
    pub stream_ids: Option<SmmuStreamIds<'a>>,
    /// Access permissions for each stream ID in `stream_ids`.
    pub stream_id_access_permissions: Option<&'a [StreamIdAccessPermissions]>,
    /// Whether the region is preserved during live activation.
    pub preserve_during_live_activation: bool,
}

/// Type of a physical interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptType {
    Spi,
    Ppi,
    Sgi,
}

/// Trigger configuration of a physical interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptTrigger {
    Edge,
    Level,
}

/// Physical interrupt assigned to a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interrupt {
    /// Physical interrupt ID.
    pub id: u32,
    /// Type of interrupt.
    pub interrupt_type: InterruptType,
    /// Trigger configuration.
    pub trigger: InterruptTrigger,
    /// Security state of the interrupt.
    pub security_state: SecurityState,
    /// Interrupt priority, or virtual priority for an S-EL1 partition under an S-EL2 SPMC.
    pub priority: u8,
    /// Target execution context for an SPI, if affinity is specified by the manifest.
    pub target_execution_context: Option<u16>,
}

/// Device MMIO region assigned to a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRegion<'a> {
    /// Physical base address of the contiguous MMIO region.
    pub base_address: u64,
    /// Size of the region as a count of 4 KiB pages.
    pub page_count: u32,
    /// Access and security attributes of the region. The memory type must be Device-nGnRnE and
    /// instruction access must be disabled.
    pub attributes: MemoryRegionAttributes,
    /// Physical interrupts assigned to the device.
    pub interrupts: &'a [Interrupt],
    /// SMMU instance upstream of the device, if any.
    pub smmu_id: Option<u32>,
    /// Stream IDs assigned to the device, if it is upstream of an SMMU.
    pub stream_ids: Option<&'a [u32]>,
    /// Whether the partition has exclusive access to and ownership of the MMIO region.
    pub exclusive_access: bool,
    /// Optional device region name, for debugging purposes.
    pub name: Option<&'a str>,
}

/// FF-A boot-information parameter register.
///
/// The execution state determines whether the corresponding `w` or `x` register is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootInfoRegister {
    R0,
    R1,
    R2,
    R3,
}

/// Manifest of a secure partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpManifest<'a> {
    /// Properties of the secure partition.
    pub properties: PartitionProperties<'a>,
    /// Memory regions assigned to the secure partition.
    pub memory_regions: &'a [MemoryRegion<'a>],
    /// Device regions assigned to the secure partition.
    pub device_regions: &'a [DeviceRegion<'a>],
    /// Parameter register in which the boot-information blob address is passed.
    pub ffa_boot_info_reg: Option<BootInfoRegister>,
}

/// Manifest of a Secure Partition Manager Core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpmcManifest {
    /// FF-A version implemented by the SPMC.
    pub version: Version,
    /// Pre-allocated SPMC ID, if any.
    pub spmc_id: Option<u16>,
    /// Execution state of the SPMC.
    pub execution_state: ExecutionState,
    /// Address at which the SPMC image must be loaded. Absence indicates that the image is
    /// position-independent.
    pub load_address: Option<u64>,
    /// Entry-point offset from the base of the SPMC image. Absence means an offset of zero.
    pub entry_point_offset: Option<u64>,
    /// Parameter register in which the boot-information blob address is passed.
    pub ffa_boot_info_reg: Option<BootInfoRegister>,
    /// Parameter register in which the cold-boot reason is passed.
    pub cold_boot_reason_reg: Option<ColdBootReasonRegister>,
}
