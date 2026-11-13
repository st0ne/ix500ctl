# ix500ctl

`ix500ctl` is a Linux command-line utility for configuring and inspecting Fujitsu ScanSnap iX500 scanners over USB. It does not provide scanning functionality. It is written in Rust and uses the system `libusb-1.0` library; it does not require Windows, Wine, .NET, or proprietary ScanSnap software.

A real-device test completed WPA2-Personal provisioning on an iX500, and the scanner subsequently joined the configured wireless network.

## Supported hardware

| Device | USB VID:PID | Firmware tested |
|---|---|---|
| Fujitsu ScanSnap iX500 | `04c5:132b` | `0U00` |

Firmware `0U00` is the only firmware currently tested for Wi-Fi provisioning and the device-info response. The network profile read fails closed unless the scanner identifies as an iX500 running firmware `0U00`; IP writes remain unavailable pending a complete no-duplicate retry/recovery policy and hardware validation.

## Features

- Read scanner identity and firmware information.
- Read the Wi-Fi hardware-switch status.
- Read and display the iX500 WLAN MAC address.
- Read the scanner-reported IPv4 profile values over USB; IP writes are currently unavailable.
- Configure a WPA2-PSK/AES wireless network through the scanner's USB interface.
- Prompt for the network password with terminal echo disabled; passwords are not accepted as command-line arguments.
- Provide optional protocol diagnostics with sensitive WLAN SET payload data redacted.

`device info` displays the scanner identity, firmware, and WLAN MAC without changing Wi-Fi settings. Before configuration, `wifi set` verifies the device, firmware, and hardware switch. It does not automatically resend WLAN settings when the result is uncertain.

## Requirements

- Linux with access to the scanner's USB interface.
- Rust and Cargo (stable toolchain recommended).
- `libusb-1.0` development files and `pkg-config` for a native build.
- For the Nix workflow, Nix with Flakes enabled.

## Build and test

With Rust and the native `libusb` development package installed:

```sh
cargo test --offline
cargo build --release --offline
```

The flake provides a reproducible development shell containing Rust, Cargo, `pkg-config`, and `libusb`:

```sh
nix develop
cargo test --offline
cargo build --offline
```

Build the Nix package directly with:

```sh
nix build
./result/bin/ix500ctl --help
```

## USB permissions

The repository includes a narrowly scoped udev rule for the iX500 USB ID. Install it and reload udev rules:

```sh
sudo install -Dm644 udev/70-ix500ctl.rules \
  /etc/udev/rules.d/70-ix500ctl.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb
```

Reconnect the scanner after installing the rule. The rule uses `uaccess` to grant access to the active local user session; access behavior may differ for headless or remote sessions.

## Commands

The following commands are implemented by the current CLI:

```sh
ix500ctl info
ix500ctl device info
ix500ctl firmware info
ix500ctl wifi status
ix500ctl wifi profile
ix500ctl network show
```

Configure a WPA2-Personal network by entering the password at the hidden prompt:

```sh
ix500ctl wifi set \
  --ssid 'NET-01' \
  --security WPA2-PSK \
  --ask-password
```

## IPv4 network configuration

The current CLI exposes only `network show`:

```sh
ix500ctl network show
```

The output contains scanner-reported profile values, not proof of the current runtime address or a DHCP lease. `0.0.0.0` in those fields alone does not establish DHCP failure. In the native result mapper, an application result of `0` produces API return `0`; `0x10` produces API return `1`; other values produce `91`. The C# wrapper passes these returns through (apart from its special recovery path for `90`), and the UI treats `0` and `-101` as success-like while reporting other values as errors. Thus the normal `0` result is consistent; poll status `0x10` and the application-result DWORD are separate layers. The DLL and EXE metadata show different build dates/PDB source paths, so exact release pairing remains unproven. IP writes remain removed from the executable CLI pending a complete no-duplicate retry/recovery policy and hardware validation.

## Optional protocol diagnostics

```sh
ix500ctl wifi set \
  --ssid 'NET-01' \
  --security WPA2-PSK \
  --ask-password \
  --debug-protocol
```

Do not pass the password as an argument. The command requires an interactive controlling terminal for the hidden prompt. `--debug-protocol` is optional; credential-bearing WLAN SET payload bytes are redacted from protocol diagnostics.

The scanner's application result reports whether it completed the configuration operation. `ix500ctl` does not independently inspect a router's DHCP or WLAN-client list, so verify network association separately when required.

## Scope and limitations

- Wi-Fi provisioning supports WPA2-PSK/AES only and has been tested on an iX500 running firmware `0U00`.
- Other models, firmware versions, WPA3, enterprise/802.1X, WPS, and scanning workflows are outside the verified scope.
- The tool configures and queries the scanner; it does not scan documents, control SANE scan jobs, create PDFs, or independently verify router-side association.
- This project is independent and is not affiliated with, endorsed by, or supported by Fujitsu, PFU, or Ricoh. ScanSnap and related product names are trademarks of their respective owners.

## Contributing

Contributions, bug reports, and additional compatibility testing on supported hardware are welcome. Please avoid sharing WLAN credentials, proprietary firmware, or sensitive device traces in issues and pull requests.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
