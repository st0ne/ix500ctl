# ix500ctl

**Native Linux Wi-Fi configuration for the Fujitsu ScanSnap iX500.**

`ix500ctl` is an open-source Rust command-line utility for configuring the Wi-Fi settings of the Fujitsu ScanSnap iX500 over USB, without requiring Windows or the proprietary ScanSnap Home software.

The project aims to provide a lightweight, reproducible, and fully native Linux alternative to the original ScanSnap Wireless Setup Tool.

> **Project status: Work in progress**
>
> The USB communication protocol is being reverse-engineered. Wi-Fi configuration functionality is not yet verified.

## Goals

- Configure Wi-Fi networks directly over USB
- Support WPA2-Personal network configuration
- Read scanner information and Wi-Fi status
- Communicate using `libusb` through the Rust `rusb` crate
- Run natively on Linux, including NixOS
- Require no Windows runtime, Wine, .NET, or proprietary drivers
- Document the reverse-engineered protocol

## Planned CLI

```console
ix500ctl devices
ix500ctl info
ix500ctl wifi status
ix500ctl wifi set --ssid "MyNetwork" --security WPA2-PSK --ask-password
```

These commands illustrate the intended interface and are not yet guaranteed to be implemented.

## Supported Hardware

| Scanner | USB VID:PID | Status |
|---|---|---|
| Fujitsu ScanSnap iX500 | `04c5:132b` | Protocol analysis in progress |

Support for additional ScanSnap models may be considered in the future.

## Technical Approach

The project is based on reverse engineering the original ScanSnap Wireless Setup Tool and studying the USB communication protocol used by the scanner.

The iX500 exposes a vendor-specific USB interface with two bulk endpoints:

- Bulk OUT: `0x02`
- Bulk IN: `0x81`

The implementation is written in Rust and will communicate with the scanner directly using `rusb`/`libusb`.

## Scope

This project focuses on scanner configuration, particularly Wi-Fi provisioning.

Document scanning, OCR, PDF generation, and scanner button integration are outside its initial scope. Existing solutions such as SANE already provide USB scanning functionality.

## Development

The project targets stable Rust and Cargo, with reproducible development environments for NixOS.

## Contributing

Contributions, testing, protocol analysis, and documentation improvements are welcome.

Especially useful are findings related to the iX500 USB protocol and compatibility testing across different firmware versions.

## Disclaimer

This is an independent, community-developed project and is not affiliated with, endorsed by, or supported by Fujitsu, PFU, or Ricoh.

ScanSnap and related product names are trademarks of their respective owners.

The project does not distribute proprietary firmware or binaries.

## License

Dual-licensed under MIT OR Apache-2.0.
