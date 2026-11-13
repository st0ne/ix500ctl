mod device_info;
mod network;
mod protocol;
mod scanner;
mod usb;
mod wifi;

use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::process::{Command, ExitCode, Stdio};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ix500ctl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--help" || flag == "-h" || flag == "help" => {
            print_usage();
            Ok(())
        }
        [cmd] if cmd == "info" => scanner::info(),
        [firmware, info] if firmware == "firmware" && info == "info" => scanner::firmware_info(),
        [device, info] if device == "device" && info == "info" => scanner::device_info(),
        [wifi, status] if wifi == "wifi" && status == "status" => wifi::read_status_from_scanner(),
        [wifi, profile] if wifi == "wifi" && profile == "profile" => wifi_profile(),
        [wifi, set, rest @ ..] if wifi == "wifi" && set == "set" => wifi_set(rest),
        [network, show] if network == "network" && show == "show" => network::show(),
        _ => {
            print_usage();
            Err("unsupported or incomplete command".into())
        }
    }
}

fn print_usage() {
    eprintln!("Usage:\n  ix500ctl info\n  ix500ctl firmware info\n  ix500ctl device info\n  ix500ctl wifi status\n  ix500ctl wifi profile\n  ix500ctl wifi set --ssid SSID --security WPA2-PSK --ask-password [--debug-protocol]\n  ix500ctl network show");
}

fn wifi_profile() -> Result<(), String> {
    let mut scanner = usb::Scanner::open()?;
    let identity = scanner::read_identity_from(&mut scanner)?;
    let profile = device_info::read_scanner_profile(&mut scanner, &identity.firmware)?;
    println!("{}", format_wifi_profile(&profile));
    Ok(())
}

fn format_wifi_profile(profile: &device_info::WifiProfile) -> String {
    [
        "WLAN-Profil (gespeicherte/gemeldete Profilinformationen; keine Aussage zur aktuellen WLAN-Verbindung):".to_string(),
        format!("SSID: {}", profile.ssid),
        format!("Sicherheitstyp: {}", profile.security),
        format!("Verschlüsselung: {}", profile.encryption),
        format!("Betriebsmodus: {}", profile.mode),
        format!("WLAN-MAC-Adresse: {}", profile.mac_address),
    ]
    .join(&char::from(10).to_string())
}

fn wifi_set(args: &[String]) -> Result<(), String> {
    let options = WifiSetOptions::parse(args)?;
    if options.security != "WPA2-PSK" {
        return Err("this build supports --security WPA2-PSK only".into());
    }

    // Complete all read-only checks before asking for a secret or sending START.
    let mut scanner = usb::Scanner::open()?;
    let identity = scanner::read_identity_from(&mut scanner)?;
    if identity.firmware != "0U00" {
        return Err(format!("Wi-Fi provisioning supports iX500 firmware 0U00 only (device reports {}); no state-changing command was sent", identity.firmware));
    }
    let firmware = scanner::read_firmware_record_from(&mut scanner)?;
    let firmware_marker = firmware.version_marker()?;
    if firmware_marker != "0U00" {
        return Err(format!("GET FIRMVERSION reports {firmware_marker}; only iX500 firmware 0U00 is supported; no state-changing command was sent"));
    }
    let hardware_status = wifi::status(&mut scanner)
        .map_err(|error| format!("read-only Wi-Fi hardware-status preflight failed ({error}); no state-changing command was sent"))?;
    require_wifi_switch_on(&hardware_status)?;

    println!(
        "Target: {} {} firmware {}",
        identity.vendor, identity.model, identity.firmware
    );
    println!(
        "Wi-Fi target: SSID {:?}, security WPA2-PSK/AES",
        options.ssid
    );
    let mut password = read_password_hidden()?;
    let request = wifi::prepare_wpa2_psk(options.ssid, &password.0)?;
    password.0.fill(0);

    println!("Starting the reference START → WLAN SET → Result-Poll sequence.");
    let mut trace = protocol::ProtocolTrace::new(options.debug_protocol);
    let result = wifi::provision_traced(
        &mut scanner,
        &request,
        std::time::Duration::from_secs(30),
        std::thread::sleep,
        &mut trace,
    );
    if options.debug_protocol {
        trace.print();
    }
    match result {
        Ok(_) => {
            println!("Scanner reported WLAN configuration success (application result 0). No END command was sent, matching Windows normal success.");
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn require_wifi_switch_on(response: &[u8]) -> Result<(), String> {
    match wifi::parse_wifi_switch_state(response)
        .map_err(|error| format!("cannot validate Wi-Fi switch state ({error}); no state-changing command was sent"))? {
        wifi::WifiSwitchState::On => Ok(()),
        wifi::WifiSwitchState::Off => Err("scanner Wi-Fi hardware switch reports OFF; turn it ON before provisioning. No password was read and no state-changing command was sent".into()),
    }
}

#[derive(Debug)]
struct WifiSetOptions<'a> {
    ssid: &'a str,
    security: &'a str,
    debug_protocol: bool,
}

impl<'a> WifiSetOptions<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let mut ssid: Option<&str> = None;
        let mut security: Option<&str> = None;
        let mut ask_password = false;
        let mut debug_protocol = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--ssid" => {
                    index += 1;
                    ssid = Some(args.get(index).ok_or("--ssid requires a value")?);
                }
                "--security" => {
                    index += 1;
                    security = Some(args.get(index).ok_or("--security requires a value")?);
                }
                "--ask-password" => ask_password = true,
                "--debug-protocol" => debug_protocol = true,
                "--password" => return Err("--password is not accepted; use --ask-password".into()),
                other => return Err(format!("unknown wifi set option: {other}")),
            }
            index += 1;
        }
        if !ask_password {
            return Err(
                "--ask-password is required; passwords are never accepted as process arguments"
                    .into(),
            );
        }
        Ok(Self {
            ssid: ssid.ok_or("missing --ssid")?,
            security: security.ok_or("missing --security")?,
            debug_protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn normal_wifi_set_arguments_parse_without_confirmation() {
        let values = args(&[
            "--ssid",
            "NET-01",
            "--security",
            "WPA2-PSK",
            "--ask-password",
        ]);
        let options = WifiSetOptions::parse(&values).unwrap();
        assert_eq!(options.ssid, "NET-01");
        assert_eq!(options.security, "WPA2-PSK");
        assert!(!options.debug_protocol);
    }

    #[test]
    fn protocol_debug_is_optional() {
        let values = args(&[
            "--ssid",
            "NET-01",
            "--security",
            "WPA2-PSK",
            "--ask-password",
            "--debug-protocol",
        ]);
        let options = WifiSetOptions::parse(&values).unwrap();
        assert!(options.debug_protocol);
    }

    #[test]
    fn wifi_set_rejects_password_process_argument() {
        let values = args(&[
            "--ssid",
            "Lab",
            "--security",
            "WPA2-PSK",
            "--ask-password",
            "--password",
            "unsafe",
        ]);
        let result = WifiSetOptions::parse(&values);
        assert!(result.unwrap_err().contains("use --ask-password"));
    }

    #[test]
    fn wifi_set_requires_ssid_security_and_hidden_password_flag() {
        assert!(
            WifiSetOptions::parse(&args(&["--security", "WPA2-PSK", "--ask-password"])).is_err()
        );
        assert!(WifiSetOptions::parse(&args(&["--ssid", "Lab", "--ask-password"])).is_err());
        assert!(
            WifiSetOptions::parse(&args(&["--ssid", "Lab", "--security", "WPA2-PSK"])).is_err()
        );
    }

    #[test]
    fn switch_preflight_allows_on_and_fails_closed_for_off_or_malformed_data() {
        let mut response = [0u8; 32];
        response[16] = 0x80;
        assert!(require_wifi_switch_on(&response).is_ok());
        response[16] = 0;
        assert!(require_wifi_switch_on(&response)
            .unwrap_err()
            .contains("reports OFF"));
        assert!(require_wifi_switch_on(&response[..16])
            .unwrap_err()
            .contains("cannot validate"));
    }

    #[test]
    fn profile_output_labels_stored_data_and_contains_only_allowed_fields() {
        let profile = device_info::WifiProfile {
            ssid: "NET-01".into(),
            security: "WPA2".into(),
            encryption: "AES".into(),
            mode: "Managed".into(),
            mac_address: "02:11:22:33:44:55".into(),
        };
        let output = format_wifi_profile(&profile);
        assert_eq!(
            output.lines().collect::<Vec<_>>(),
            [
                "WLAN-Profil (gespeicherte/gemeldete Profilinformationen; keine Aussage zur aktuellen WLAN-Verbindung):",
                "SSID: NET-01",
                "Sicherheitstyp: WPA2",
                "Verschlüsselung: AES",
                "Betriebsmodus: Managed",
                "WLAN-MAC-Adresse: 02:11:22:33:44:55",
            ]
        );
        assert!(!output.contains("key"));
        assert!(!output.contains("Schlüssel"));
    }
}

struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn read_password_hidden() -> Result<Secret, String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| format!("cannot open terminal for hidden password input: {error}"))?;
    let tty_for_stty = tty
        .try_clone()
        .map_err(|error| format!("cannot access terminal: {error}"))?;
    let echo_guard_file = tty
        .try_clone()
        .map_err(|error| format!("cannot access terminal: {error}"))?;
    let status = Command::new("stty")
        .arg("-echo")
        .stdin(Stdio::from(tty_for_stty))
        .status()
        .map_err(|error| format!("cannot disable terminal echo with stty: {error}"))?;
    if !status.success() {
        return Err("stty could not disable terminal echo".into());
    }
    let _echo = TerminalEchoGuard(echo_guard_file);
    let mut tty = tty;
    tty.write_all(b"WLAN password (hidden): ")
        .map_err(|error| format!("terminal write failed: {error}"))?;
    tty.flush()
        .map_err(|error| format!("terminal flush failed: {error}"))?;
    let mut input = Vec::with_capacity(64);
    loop {
        let mut byte = [0u8; 1];
        if tty.read_exact(&mut byte).is_err() {
            return Err("password input ended unexpectedly".into());
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            input.push(byte[0]);
        }
    }
    drop(_echo);
    tty.write_all(b"\n")
        .map_err(|error| format!("terminal write failed: {error}"))?;
    Ok(Secret(input))
}

struct TerminalEchoGuard(std::fs::File);
impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        if let Ok(stdin) = self.0.try_clone() {
            let _ = Command::new("stty")
                .arg("echo")
                .stdin(Stdio::from(stdin))
                .status();
        }
    }
}
