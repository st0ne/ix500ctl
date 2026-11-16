# ix500ctl

`ix500ctl` is a Linux USB configuration and diagnostic CLI for the Fujitsu ScanSnap iX500. It reads device and saved-profile information and configures the scanner's Wi-Fi or IPv4 settings over USB. It is written in Rust and uses `libusb-1.0`; it is not a document-scanning client and does not implement the scanner's network scan protocol.

## Supported hardware

| Scanner | USB VID:PID | Firmware tested |
|---|---|---|
| Fujitsu ScanSnap iX500 | `04c5:132b` | `0U00` |

Firmware `0U00` on the iX500 is the only model/firmware combination verified for the commands in this project. No compatibility claim is made for other models or firmware versions.

### Real-device Wi-Fi test

A user-confirmed test on a real ScanSnap iX500 running firmware `0U00` verified the Wi-Fi configuration: the scanner joined the configured WLAN, obtained a DHCP lease, received a valid IP address, responded to ping, and showed a blue WLAN indicator. This test validates the Wi-Fi configuration in that setup. It does **not** validate the separate `network set --dhcp` or `network set --static` IP-SET paths.

## Features

- Read USB device identity, SCSI INQUIRY information, and firmware information.
- Read Wi-Fi hardware-switch status and the saved Wi-Fi profile, including the WLAN MAC address.
- Configure an SSID with WPA2-PSK/AES over USB, using a hidden password prompt.
- Read or set the separate ScanSnap Connect/AirScap scanner-connection password over USB; `set` uses a hidden prompt and preserves the scanner's password-display setting.
- Compare a hidden candidate password with the saved key representation using `wifi verify-key`; output is limited to `MATCH`, `MISMATCH`, or `INCONCLUSIVE`.
- Show the scanner-reported IPv4 profile and submit one-shot DHCP or static IPv4 configuration requests over USB.
- Keep all device access on USB. The tool does not scan documents, call router APIs, or provide a network scan client.

## Linux requirements

- Linux with USB access to the scanner.
- Rust and Cargo (stable toolchain recommended) for a Cargo build.
- `libusb-1.0` development files and `pkg-config` for native builds.
- Nix with Flakes enabled for the optional Nix workflow.

The flake defines `x86_64-linux` and `aarch64-linux` development shells and packages.

## Build and installation

### Cargo

Install the native prerequisites, then build and install from the repository root:

```sh
cargo build --release
cargo install --path .
ix500ctl --help
```

Run the test suite with:

```sh
cargo test --offline
```

### Nix

Enter the development shell, or build the packaged executable directly:

```sh
nix develop
cargo test --offline
cargo build --release --offline
```

```sh
nix build
./result/bin/ix500ctl --help
```

## USB permissions

The repository includes `udev/70-ix500ctl.rules`, scoped to the iX500 USB vendor/product ID. Install it and reload the rules:

```sh
sudo install -Dm644 udev/70-ix500ctl.rules \
  /etc/udev/rules.d/70-ix500ctl.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb
```

Reconnect the scanner afterward. The rule uses `uaccess` for the active local user session; headless or remote sessions may need a separately managed access policy.

## Commands

```text
ix500ctl info
ix500ctl firmware info
ix500ctl device info
ix500ctl device password show
ix500ctl device password set --ask-password
ix500ctl wifi status
ix500ctl wifi profile
ix500ctl wifi verify-key --ask-password
ix500ctl wifi set --ssid SSID --security WPA2-PSK --ask-password [--debug-protocol]
ix500ctl network show
ix500ctl network set --dhcp
ix500ctl network set --static --ip IPv4 --netmask IPv4 --gateway IPv4
```

### Device information

`info`, `device info`, and `firmware info` read scanner identity, inquiry, or firmware details over USB. `wifi status` reads the hardware-switch state. `wifi profile` displays saved/reported profile fields; it is not a live WLAN association check and does not display the saved key.

### Scanner connection password

The scanner-connection password used by ScanSnap Connect/AirScap is distinct from the WPA2 passphrase used to join an access point:

1. **WLAN password** — the WPA2-PSK configured with `wifi set` and represented by the saved Wi-Fi profile's `SeqKey`.
2. **Scanner connection password** — the `PwdMode`/`PwdCode` setting read or written by `device password`; `show` reads the scanner's native configuration file and displays the decoded value when enabled, while `set` requests it through a hidden terminal prompt.
3. **Network pairing identity** — a separate value derived by the ScanSnap Connect/AirScap pairing flow. It is not the USB `PwdCode` representation and is not the WLAN passphrase.

```sh
ix500ctl device password show
ix500ctl device password set --ask-password
```

Password management is limited to the iX500 with firmware `0U00`. The SET sends the scanner name, enabled-password flag, native encoded password field, and the existing password-display flag in one USB request; it does not submit or rewrite the WLAN profile. The operation is sent at most once. A transport error, timeout, unknown result, or nonzero scanner result is reported without retry; after an acknowledged SET, the tool reads the configuration back and compares it before reporting success. `show` intentionally prints the existing scanner-connection password to the terminal, so treat that terminal output as sensitive.

### Wi-Fi configuration

Configure a WPA2-PSK/AES network by entering the password at the hidden prompt:

```sh
ix500ctl wifi set \
  --ssid 'YOUR_SSID' \
  --security WPA2-PSK \
  --ask-password
```

Passwords are never accepted as command-line arguments. Optional `--debug-protocol` diagnostics redact credential-bearing SET payload bytes. The scanner's USB application result reports configuration handling; by itself it does not establish a successful WPA2 handshake or a DHCP lease.

The iX500 key transformation is implemented to match the native default path used for firmware `0U00`. Other security modes and firmware paths are outside the verified scope.

### Saved-key check

```sh
ix500ctl wifi verify-key --ask-password
```

This performs a read-only Device_Info query and compares the hidden candidate with the saved `SeqKey` representation. Standard output is one of `MATCH`, `MISMATCH`, or `INCONCLUSIVE`; it never prints the candidate, encoded value, or decoded key. A `MATCH` confirms the saved profile value only, not live access-point authentication or association.

### IPv4 configuration

`network show` displays scanner-reported profile values. They are not proof of a current runtime address, WLAN association, or DHCP lease.

Request DHCP configuration:

```sh
ix500ctl network set --dhcp
```

Request a static address (the IP, netmask, and gateway must form a valid host configuration in one subnet):

```sh
ix500ctl network set --static \
  --ip 192.168.1.50 \
  --netmask 255.255.255.0 \
  --gateway 192.168.1.1
```

The implementation sends at most one IP-SET request and does not automatically retry it. Polling and application results are handled separately; a transport error, timeout, or unknown result leaves the final device state unconfirmed. The IP-SET commands are covered by tests but have **not** been validated with a successful hardware IP write. The DHCP lease observed after the separate Wi-Fi configuration test is not evidence that these IP-SET paths work.

## Scope and limitations

- Verified hardware scope is the Fujitsu ScanSnap iX500 with firmware `0U00`; other models and firmware versions are not claimed to be supported.
- Wi-Fi provisioning is limited to WPA2-PSK/AES.
- The scanner-connection-password `show`/READ path, AirScap WLAN pairing, scan-button operation, and document delivery to Paperless have been confirmed by the operator on an iX500 `0U00`. The `device password set` write and its post-SET readback have **not** been tested on real hardware.
- IPv4 SET behavior has not received a successful hardware write test.
- The project does not scan documents, control scan jobs, implement a network scan client, or inspect router-side state.
- The tool is independent and is not affiliated with or endorsed by Fujitsu, PFU, or Ricoh.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
