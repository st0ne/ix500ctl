# ix500ctl

`ix500ctl` is a Linux command-line utility for configuring and inspecting Fujitsu ScanSnap iX500 scanners over USB. It does not provide scanning functionality. It is written in Rust and uses the system `libusb-1.0` library; it does not require Windows, Wine, .NET, or proprietary ScanSnap software.

A real-device test completed WPA2-Personal provisioning on an iX500, and the scanner subsequently joined the configured wireless network.

## Supported hardware

| Device | USB VID:PID | Firmware tested |
|---|---|---|
| Fujitsu ScanSnap iX500 | `04c5:132b` | `0U00` |

Firmware `0U00` is the only firmware supported by Wi-Fi provisioning, device-info parsing, and network commands. IP-setting requests use a one-shot transfer followed only by Result-Poll reads; an uncertain result is not retried automatically. The IP-setting path has not been hardware-validated.

## Features

- Read scanner identity and firmware information.
- Read the Wi-Fi hardware-switch status.
- Read and display the iX500 WLAN MAC address.
- Read and display the scanner-reported IPv4 profile; set DHCP or static IPv4 configuration over USB with a single SET and no automatic SET retry.
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
ix500ctl network set --dhcp
ix500ctl network set --static --ip IPv4 --netmask IPv4 --gateway IPv4
```

Configure a WPA2-Personal network by entering the password at the hidden prompt:

```sh
ix500ctl wifi set \
  --ssid 'NET-01' \
  --security WPA2-PSK \
  --ask-password
```

## IPv4 network configuration

`network show` displays scanner-reported profile values. They are saved/reported configuration fields, not proof of a current runtime address, WLAN association, or DHCP lease. In particular, `0.0.0.0` by itself does not establish DHCP failure.

Set DHCP mode:

```sh
ix500ctl network set --dhcp
```

Set a static IPv4 address (the address, mask, and gateway must be valid host addresses in the same subnet):

```sh
ix500ctl network set --static \
  --ip 192.168.1.50 \
  --netmask 255.255.255.0 \
  --gateway 192.168.1.1
```

The command sends at most one IP-SET request. Result-Poll status and the application-result DWORD are interpreted separately. Application result `0` is success; `0x10` maps to native API error `1`; other application-result values map to API error `91`. A transport error, timeout, retry-signaling result, or unknown poll result stops without another SET and leaves the final device state unconfirmed. Even a reported application success does not prove that the scanner obtained a DHCP lease or is reachable on WLAN; verify association and runtime addressing separately.

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
