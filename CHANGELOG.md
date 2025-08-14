# Changelog

## 0.3.1

- Move repository under arm-firmware-crates namespace.
- Adopt Linux Foundation's guidance on copyrights
- Apply Arm Trademark Guidance
- Remove security incident process

## 0.3.0

- Refactor FFA_CONSOLE_LOG handling.
- Add more types for the various encodings of FFA_SUCCESS.
- Add support for handling multiple endpoints in the FF-A memory relinquish descriptor.
- Add new types for flags in various FF-A interfaces.
- Minor fixes, add more trait derives, missing doc comments, etc.

## 0.2.1

Minor bugfixes for parse_console_log() function and VersionOut interface handling.

## 0.2.0

- Implement missing FF-A interfaces:
  - FFA_SECONDARY_EP_REGISTER,
  - FFA_PARTITION_INFO_GET_REGS,
  - FFA_EL3_INTR_HANDLE.
- Add types for the various encodings of FFA_SUCCESS.
- Add types to support FF-A framework messages.
- Additional checks and bugfixes.

## 0.1.0

Initial release.
