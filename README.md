# Arm Firmware Framework for Arm A-profile (FF-A) support library

[Arm Firmware Framework for Arm A-profile (FF-A) specification](https://developer.arm.com/documentation/den0077/latest/)

[FF-A Memory Management Protocol specification](https://developer.arm.com/documentation/den0140/latest/)

Library for handling common FF-A related functionality, create and parse interfaces and descriptors
defined by FF-A. Starting from FF-A v1.2 the memory management related parts of the specification
have been moved to a separate document (link above).

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
    never exposed to the library user (i.e. the `ffa_v1_3` module).
    * The implementation of such data structures should strictly follow the FF-A specification.
    * Preferably write a doc comment for each such definition that specifies where it comes from in
      the spec (i.e. Table x.y or chapter x.y.z)
    * The data structures should derive the necessary `zerocopy` traits.

## FF-A version handling

The FF-A specification allows different components of a system to use different versions of the
specification. The version used at a specific FF-A instance (i.e. an interface between two FF-A
components) is discovered at runtime, either by parsing FF-A manifests or using `FFA_VERSION`.

FF-A minor versions are generally specified in a backwards-compatible way for ABI encoding: existing
function IDs keep their register layout, while new behaviour is added through new function IDs, new
fields in descriptors, flags, or previously reserved values. Because of this, the crate does not
carry a negotiated FF-A version through every pack/unpack operation.

However, there were some significant changes prior to FF-A v1.3 because of SMCCC updates which added
support for using more registers for argument passing and also the standardisation of the FF-A
version renegotiation. To avoid adding complexity this crate implements the register usage
convention as defined in FF-A v1.3, which might not be compatible with earlier versions.

## Implemented features

  * Register ABI conversion for supported FF-A interfaces.
  * Common FF-A types: function ID, error code, version, endpoint and vCPU ID, feature ID, RX/TX
    buffer address, memory operation buffer address, UUID register conversion helpers, etc.
  * Status reporting interface encodings and success-argument helpers.
  * Setup and discovery interface encodings.
  * CPU cycle management interface encodings, including the FF-A v1.3 SMC64 function IDs.
  * Messaging interface encodings and framework message argument helpers for direct request/response.
  * Notification interface encodings and notification success-argument helpers.
  * Interrupt management interface encoding.
  * Secondary entry point registration interface encoding.
  * Partition information descriptor packing/parsing for the FF-A v1.3 descriptor format.
  * Boot information blob packing/parsing for the FF-A v1.3 boot information header and descriptor
    format.
  * Memory management transaction interface register encodings.
  * Memory management permission, fragmentation and time-slicing interface register encodings.
  * Memory management descriptor helpers for memory region attributes, memory access permissions,
    endpoint memory access descriptors, composite/constituent memory region descriptors, memory
    transaction descriptors and memory relinquish descriptors.

## Future plans

  * Implement missing interfaces and features of FF-A v1.3 and later.
  * Add typed memory management flag and descriptor fields, stricter per-ABI descriptor validation.
  * Increase test coverage.
  * Create more detailed documentation to capture which parts of FF-A are currently supported.

## Fuzzing

For running the fuzzers locally, make sure you have a nightly rust toolchain
and `cargo-fuzz` installed. The `fuzzer_corpus` binary target is used to
generate a seed corpus for fuzzing:

```sh
rustup install nightly
cargo install cargo-fuzz
cargo run --bin fuzzer_corpus
```

You can run individual fuzzers with `cargo +nightly fuzz run <fuzzer_name>`, or
run them all with `fuzz/run_all.sh`. A coverage report can be generated with
`fuzz/get_coverage.sh`, this requires `cargo-binutils` and `lcov` to be
installed. The report will be placed in `fuzz/lcov/index.html`.

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

Contributions are handled through [review.trustedfirmware.org](https://review.trustedfirmware.org/q/project:arm-firmware-crates/arm-ffa).

## Arm trademark notice

Arm is a registered trademark of Arm Limited (or its subsidiaries or affiliates).

This project uses some of the Arm product, service or technology trademarks, as listed in the
[Trademark List][1], in accordance with the [Arm Trademark Use Guidelines][2].

Subsequent uses of these trademarks throughout this repository do not need to be prefixed with the
Arm word trademark.

[1]: https://www.arm.com/company/policies/trademarks/arm-trademark-list
[2]: https://www.arm.com/company/policies/trademarks/guidelines-trademarks

--------------

*Copyright The arm-ffa Contributors.*
