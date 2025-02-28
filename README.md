# Arm Firmware Framework for Arm A-profile (FF-A) support library

[Arm Firmware Framework for Arm A-profile (FF-A) specification](https://developer.arm.com/documentation/den0077/latest/)

[FF-A Memory Management Protocol specification](https://developer.arm.com/documentation/den0140/latest/)

Library for handling common FF-A related functionality, create and parse interfaces and descriptors
defined by FF-A.

## Design goals
  * Keep the code exception level agnostic by default. If exception level specific parts are
    inevitable, make it optional via a feature flag.
  * Keep the code no_std compatible. Use only core by default, make parts using alloc optional via
    a feature flag.
  * The interface towards the library's users should be ergonomic Rust and following Rust
    best-practices where possible.
    * Incorrect usage of this library when creating/packing/serializing data structures provided by
      this library is seen as a programmer error and the library will panic.
    * Parsing/unpacking/deserializing data structures provided by this library from a buffer is seen
      as runtime "user input data", and the library should make all necessary checks to validate the
      data. In this case the library should never panic, but return rich error types (preferably use
      `thiserror`) so the library user knows what's wrong.
  * The FF-A descriptors, packed structs and bit shifting magic should be private for the library,
    never exposed to the library user (i.e. `ffa_v1_1` and later modules).
    * The implementation of such data structures should strictly follow the FF-A specification.
    * Preferably write a doc comment for each such definition that specifies where it comes from in
      the spec (i.e. Table x.y or chapter x.y.z)
    * The data structures should derive the necessary `zerocopy` traits.

## FF-A version handling

The FF-A specification allows that in a system different components can use different versions of
the specification. The version used at a specific FF-A instance (i.e. an interface between two FF-A
components) is discovered at runtime, either by parsing FF-A manifests or using `FFA_VERSION`. An
FF-A component might have to use multiple versions at runtime on its different interfaces, therefore
this library must be able to support this and having a compile time fixed version is not possible.
Because of this, most of the functions to create or parse FF-A messages and data structures require
passing the FF-A version used at the instance where the serialized data was received from or will be
sent to.

## Implemented features

  * Supports converting FF-A interface types between Rust types and the FF-A register ABI.
  * Memory transaction descriptor handling for `FFA_MEM_*` interfaces (partial).
  * FF-A v1.1+ boot information protocol.
  * FF-A partiton information descriptor.

## Future plans

  * Implement missing features from FF-A v1.1 and later. Implementing FF-A v1.0 features that are
    deprecated by v1.1 are low priority for now.
  * Increase test coverage.
  * Create more detailed documentation to capture which parts of FF-A are currently supported.

## License

The project is MIT and Apache-2.0 dual licensed, see `LICENSE-APACHE` and `LICENSE-MIT`.

## Maintainers

arm-ffa is a trustedfirmware.org maintained project. All contributions are ultimately merged by the
maintainers listed below.

* Bálint Dobszay <balint.dobszay@arm.com>
  [balint-dobszay-arm](https://github.com/balint-dobszay-arm)
* Imre Kis <imre.kis@arm.com>
  [imre-kis-arm](https://github.com/imre-kis-arm)
* Sandrine Afsa <sandrine.afsa@arm.com>
  [sandrine-bailleux-arm](https://github.com/sandrine-bailleux-arm)

## Contributing

Please follow the directions of the [Trusted Firmware Processes](https://trusted-firmware-docs.readthedocs.io/en/latest/generic_processes/index.html)

Contributions are handled through [review.trustedfirmware.org](https://review.trustedfirmware.org/q/project:rust-spmc/arm-ffa).

## Reporting Security Issues

Please follow the directions of the [Trusted Firmware Security Center](https://trusted-firmware-docs.readthedocs.io/en/latest/security_center/index.html)

--------------

*Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>*

*Arm is a registered trademark of Arm Limited (or its subsidiaries or affiliates).*
