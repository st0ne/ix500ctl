use crate::{
    device_info,
    protocol::{self, BulkTransport},
    scanner,
    usb::Scanner,
    wifi::{self, PossessionSession, PossessionState},
};
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

const SETUP_NET_CMD: &[u8; 16] = b"SETUP NET CMD   ";
const REQUEST_HEADER_LEN: usize = 0x24;
const REQUEST_DATA_LEN: usize = 0x8c;
const REQUEST_LEN: usize = REQUEST_HEADER_LEN + REQUEST_DATA_LEN;
const IP_TYPE_OFFSET: usize = 0x1cc;
const IP_ADDRESS_OFFSET: usize = 0x1d0;
const NETMASK_OFFSET: usize = 0x1e0;
const GATEWAY_OFFSET: usize = 0x1f0;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const RESULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_RESULT_POLLS: usize = 360;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpConfigurationType {
    Static,
    Dhcp,
    Unknown(u32),
}

impl IpConfigurationType {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Static,
            1 => Self::Dhcp,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProfile {
    pub raw_type: u32,
    pub ip_type: IpConfigurationType,
    pub ip_address: String,
    pub netmask: String,
    pub gateway: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpConfiguration {
    Dhcp,
    Static {
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
    },
}

impl IpConfiguration {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut mode = None;
        let mut ip = None;
        let mut netmask = None;
        let mut gateway = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--dhcp" => {
                    if mode.replace(false).is_some() {
                        return Err("choose exactly one of --dhcp or --static".into());
                    }
                }
                "--static" => {
                    if mode.replace(true).is_some() {
                        return Err("choose exactly one of --dhcp or --static".into());
                    }
                }
                "--ip" => set_option(&mut ip, args, &mut index, "--ip")?,
                "--netmask" => set_option(&mut netmask, args, &mut index, "--netmask")?,
                "--gateway" => set_option(&mut gateway, args, &mut index, "--gateway")?,
                other => return Err(format!("unknown network set option: {other}")),
            }
            index += 1;
        }

        match mode {
            Some(false) => {
                if ip.is_some() || netmask.is_some() || gateway.is_some() {
                    return Err(
                        "--dhcp cannot be combined with --ip, --netmask, or --gateway".into(),
                    );
                }
                Ok(Self::Dhcp)
            }
            Some(true) => {
                let ip = parse_ipv4(ip.ok_or("--static requires --ip")?, "--ip")?;
                let netmask =
                    parse_ipv4(netmask.ok_or("--static requires --netmask")?, "--netmask")?;
                let gateway =
                    parse_ipv4(gateway.ok_or("--static requires --gateway")?, "--gateway")?;
                validate_static_ipv4(ip, netmask, gateway)?;
                Ok(Self::Static {
                    ip,
                    netmask,
                    gateway,
                })
            }
            None => Err("network set requires --dhcp or --static".into()),
        }
    }
}

fn set_option<'a>(
    target: &mut Option<&'a str>,
    args: &'a [String],
    index: &mut usize,
    option: &str,
) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{option} may be specified only once"));
    }
    *index += 1;
    *target = Some(
        args.get(*index)
            .ok_or_else(|| format!("{option} requires a value"))?,
    );
    Ok(())
}

fn parse_ipv4(value: &str, option: &str) -> Result<Ipv4Addr, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be a valid IPv4 address"))
}

fn validate_static_ipv4(ip: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> Result<(), String> {
    let mask = u32::from(netmask);
    let prefix_len = mask.leading_ones();
    if !(1..=30).contains(&prefix_len) || mask != (u32::MAX << (32 - prefix_len)) {
        return Err(
            "--netmask must be a contiguous IPv4 mask with prefix length /1 through /30".into(),
        );
    }
    for (name, address) in [("--ip", ip), ("--gateway", gateway)] {
        let first_octet = address.octets()[0];
        let classful_unicast =
            (1..=126).contains(&first_octet) || (128..=223).contains(&first_octet);
        if address.is_unspecified()
            || address == Ipv4Addr::BROADCAST
            || address.is_multicast()
            || !classful_unicast
        {
            return Err(format!("{name} must be a usable unicast IPv4 host address"));
        }
    }
    let ip_num = u32::from(ip);
    let gateway_num = u32::from(gateway);
    let network = ip_num & mask;
    let broadcast = network | !mask;
    if ip_num == network || ip_num == broadcast {
        return Err("--ip must not be the subnet network or broadcast address".into());
    }
    if gateway_num == network || gateway_num == broadcast {
        return Err("--gateway must not be the subnet network or broadcast address".into());
    }
    if ip == gateway {
        return Err("--gateway must differ from --ip".into());
    }
    if (gateway_num & mask) != network {
        return Err("--gateway must be in the same subnet as --ip".into());
    }
    Ok(())
}

pub fn build_ip_setting_request(config: &IpConfiguration) -> [u8; REQUEST_LEN] {
    let mut request = [0u8; REQUEST_LEN];
    request[..16].copy_from_slice(SETUP_NET_CMD);
    request[16..18].copy_from_slice(&0x9c00u16.to_le_bytes());
    request[20..24].copy_from_slice(&0x1003u32.to_le_bytes());
    request[32..36].copy_from_slice(&(REQUEST_DATA_LEN as u32).to_le_bytes());
    match config {
        IpConfiguration::Dhcp => {
            request[36..40].copy_from_slice(&1u32.to_le_bytes());
            copy_text_slot(&mut request[40..56], "0.0.0.0");
            copy_text_slot(&mut request[56..72], "0.0.0.0");
            copy_text_slot(&mut request[72..88], "0.0.0.0");
        }
        IpConfiguration::Static {
            ip,
            netmask,
            gateway,
        } => {
            request[36..40].copy_from_slice(&0u32.to_le_bytes());
            copy_ipv4_slot(&mut request[40..56], *ip);
            copy_ipv4_slot(&mut request[56..72], *netmask);
            copy_ipv4_slot(&mut request[72..88], *gateway);
        }
    }
    request
}

fn copy_ipv4_slot(slot: &mut [u8], address: Ipv4Addr) {
    copy_text_slot(slot, &address.to_string());
}

fn copy_text_slot(slot: &mut [u8], text: &str) {
    slot[..text.len()].copy_from_slice(text.as_bytes());
}

pub fn parse_network_profile(raw: &[u8]) -> Result<NetworkProfile, String> {
    if raw.len() != device_info::DEVICE_INFO_RESPONSE_LEN {
        return Err(format!(
            "Device_Info response has {} bytes; expected exactly {}",
            raw.len(),
            device_info::DEVICE_INFO_RESPONSE_LEN
        ));
    }
    if raw[0] != 0 {
        return Err(format!("Device_Info poll result is 0x{:02x}", raw[0]));
    }
    let application_result = u32::from_le_bytes(raw[8..12].try_into().expect("length checked"));
    if application_result != 0 {
        return Err(format!(
            "Device_Info application result is 0x{application_result:08x}"
        ));
    }
    let raw_type = u32::from_le_bytes(
        raw[IP_TYPE_OFFSET..IP_TYPE_OFFSET + 4]
            .try_into()
            .expect("field bounds checked"),
    );
    Ok(NetworkProfile {
        raw_type,
        ip_type: IpConfigurationType::from_raw(raw_type),
        ip_address: read_network_text(raw, IP_ADDRESS_OFFSET, NETMASK_OFFSET, "IP address")?,
        netmask: read_network_text(raw, NETMASK_OFFSET, GATEWAY_OFFSET, "subnet mask")?,
        gateway: read_network_text(raw, GATEWAY_OFFSET, GATEWAY_OFFSET + 0x10, "gateway")?,
    })
}

fn read_network_text(raw: &[u8], start: usize, end: usize, name: &str) -> Result<String, String> {
    let slot = raw
        .get(start..end)
        .ok_or_else(|| format!("Device_Info {name} field exceeds response bounds"))?;
    let length = slot
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("Device_Info {name} field lacks a NUL terminator"))?;
    if !slot[..length].is_ascii() || slot[..length].iter().any(u8::is_ascii_control) {
        return Err(format!("Device_Info {name} field is not printable ASCII"));
    }
    Ok(String::from_utf8(slot[..length].to_vec()).expect("ASCII is valid UTF-8"))
}

pub fn format_network_profile(profile: &NetworkProfile) -> String {
    let mapped = match profile.ip_type {
        IpConfigurationType::Static => "Static",
        IpConfigurationType::Dhcp => "DHCP",
        IpConfigurationType::Unknown(_) => "Unverified/unknown",
    };
    format!(
        "IP-Konfiguration (über USB gemeldete Profilwerte; kein Nachweis aktueller Laufzeitwerte oder einer DHCP-Lease):\nIP-Typ: {} (Rohwert {})\nIP-Adresse: {}\nSubnetzmaske: {}\nGateway: {}",
        mapped, profile.raw_type, profile.ip_address, profile.netmask, profile.gateway
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SetIpError {
    Unconfirmed {
        detail: String,
        native_code: Option<i32>,
    },
}

impl std::fmt::Display for SetIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfirmed {
                detail,
                native_code,
            } => {
                if let Some(code) = native_code {
                    write!(f, "IP configuration outcome unconfirmed (native status {code}); no retry was attempted: {detail}")
                } else {
                    write!(
                        f,
                        "IP configuration outcome unconfirmed; no retry was attempted: {detail}"
                    )
                }
            }
        }
    }
}

fn set_ip_configuration_once<T, F>(
    transport: &mut T,
    request: &[u8; REQUEST_LEN],
    timeout: Duration,
    mut sleep: F,
) -> Result<(), SetIpError>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    let cdb = wifi::diagnostic_cdb(0x1d, REQUEST_LEN)
        .expect("the statically sized IP request fits the SCSI transfer field");
    protocol::scsi_write(transport, &cdb, request).map_err(|error| SetIpError::Unconfirmed {
        detail: format!("USB command/data/status transfer failed: {error}"),
        native_code: None,
    })?;

    let started = Instant::now();
    for attempt in 0..MAX_RESULT_POLLS {
        let response =
            wifi::poll_result_once(transport).map_err(|error| SetIpError::Unconfirmed {
                detail: format!("Result-Poll transport failed after the single IP write: {error}"),
                native_code: None,
            })?;
        match response.result {
            wifi::ApplicationResult::Complete => return Ok(()),
            wifi::ApplicationResult::Pending => {
                let elapsed = started.elapsed();
                if elapsed >= timeout || attempt + 1 == MAX_RESULT_POLLS {
                    return Err(SetIpError::Unconfirmed {
                        detail: "Result-Poll timed out after the request transfer".into(),
                        native_code: Some(9),
                    });
                }
                sleep(RESULT_POLL_INTERVAL.min(timeout - elapsed));
            }
            wifi::ApplicationResult::DeviceError(0x83) => {
                return Err(SetIpError::Unconfirmed {
                    detail: "scanner returned Result-Poll status 0x83; the Windows path performs possession recovery and may reissue the IP command, but ix500ctl deliberately does not retry".into(),
                    native_code: None,
                });
            }
            wifi::ApplicationResult::DeviceError(code) => {
                let native_code = match code {
                    0x80 => 128,
                    0x81 => 7,
                    0x82 => 130,
                    _ => 91,
                };
                return Err(SetIpError::Unconfirmed {
                    detail: format!(
                        "scanner returned Result-Poll status 0x{code:02x}; native status {native_code} is not a successful completion"
                    ),
                    native_code: Some(native_code),
                });
            }
        }
    }
    Err(SetIpError::Unconfirmed {
        detail: "Result-Poll exhausted the native 360-poll limit".into(),
        native_code: Some(9),
    })
}

pub fn show() -> Result<(), String> {
    let mut scanner = Scanner::open()?;
    verify_supported_device(&mut scanner)?;
    println!("Target: Fujitsu ScanSnap iX500 firmware 0U00");
    let profile = read_profile_from(&mut scanner)?;
    println!("{}", format_network_profile(&profile));
    Ok(())
}

pub fn set(config: &IpConfiguration) -> Result<(), String> {
    let mut scanner = Scanner::open()?;
    verify_supported_device(&mut scanner)?;
    println!("Target: Fujitsu ScanSnap iX500 firmware 0U00");
    let request = build_ip_setting_request(config);
    set_ip_configuration_once(&mut scanner, &request, NETWORK_TIMEOUT, std::thread::sleep)
        .map_err(|error| error.to_string())?;
    println!("Scanner reported the IP configuration command completed successfully. A current DHCP lease is not established by this response.");
    Ok(())
}

fn verify_supported_device<T: BulkTransport>(transport: &mut T) -> Result<(), String> {
    let identity = scanner::read_identity_from(transport)?;
    if identity.model != "ScanSnap iX500" || identity.firmware != "0U00" {
        return Err(format!(
            "network configuration supports only ScanSnap iX500 firmware 0U00 (device reports {} firmware {}); no IP-setting command was sent",
            identity.model, identity.firmware
        ));
    }
    let firmware = scanner::read_firmware_record_from(transport)?;
    let marker = firmware.version_marker()?;
    if marker != "0U00" {
        return Err(format!(
            "GET FIRMVERSION reports {marker}; only iX500 firmware 0U00 is supported; no IP-setting command was sent"
        ));
    }
    Ok(())
}

fn read_profile_from<T: BulkTransport>(transport: &mut T) -> Result<NetworkProfile, String> {
    let session = PossessionSession::acquire(transport, NETWORK_TIMEOUT)?;
    if session.state() != PossessionState::Active {
        return Err(
            "scanner possession was not established; network profile was not queried".into(),
        );
    }
    let response = device_info::read_ix500_0u00_response(transport)?;
    parse_network_profile(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn ip_type_mapping_matches_windows_dhcp_and_manual_radio_values() {
        assert_eq!(IpConfigurationType::from_raw(1), IpConfigurationType::Dhcp);
        assert_eq!(
            IpConfigurationType::from_raw(0),
            IpConfigurationType::Static
        );
        assert_eq!(
            IpConfigurationType::from_raw(7),
            IpConfigurationType::Unknown(7)
        );
    }

    #[test]
    fn dhcp_request_serializes_exact_windows_command_and_zero_address_placeholders() {
        let request = build_ip_setting_request(&IpConfiguration::Dhcp);
        assert_eq!(request.len(), 0xb0);
        assert_eq!(&request[..16], b"SETUP NET CMD   ");
        assert_eq!(&request[16..18], &0x9c00u16.to_le_bytes());
        assert_eq!(&request[18..20], &[0, 0]);
        assert_eq!(&request[20..24], &0x1003u32.to_le_bytes());
        assert_eq!(&request[24..32], &[0; 8]);
        assert_eq!(&request[32..36], &0x8cu32.to_le_bytes());
        assert_eq!(&request[36..40], &1u32.to_le_bytes());
        for slot in [40..56, 56..72, 72..88] {
            assert_eq!(&request[slot.start..slot.start + 7], b"0.0.0.0");
            assert!(request[slot.start + 7..slot.end]
                .iter()
                .all(|byte| *byte == 0));
        }
        assert_eq!(&request[88..], &[0; 0x58]);
    }

    #[test]
    fn static_request_serializes_canonical_ipv4_strings_at_exact_offsets() {
        let config = IpConfiguration::parse(&values(&[
            "--static",
            "--ip",
            "192.168.1.50",
            "--netmask",
            "255.255.255.0",
            "--gateway",
            "192.168.1.1",
        ]))
        .unwrap();
        let request = build_ip_setting_request(&config);
        assert_eq!(&request[36..40], &0u32.to_le_bytes());
        assert_eq!(&request[40..56], b"192.168.1.50\0\0\0\0");
        assert_eq!(&request[56..72], b"255.255.255.0\0\0\0");
        assert_eq!(&request[72..88], b"192.168.1.1\0\0\0\0\0");
        assert_eq!(&request[88..], &[0; 0x58]);
    }

    #[test]
    fn static_configuration_requires_all_three_ipv4_values() {
        for args in [
            values(&[
                "--static",
                "--ip",
                "192.168.1.50",
                "--netmask",
                "255.255.255.0",
            ]),
            values(&[
                "--static",
                "--netmask",
                "255.255.255.0",
                "--gateway",
                "192.168.1.1",
            ]),
            values(&[
                "--static",
                "--ip",
                "192.168.1.50",
                "--gateway",
                "192.168.1.1",
            ]),
        ] {
            assert!(IpConfiguration::parse(&args).is_err());
        }
    }

    #[test]
    fn static_configuration_rejects_invalid_address_mask_and_subnet_relationships() {
        for (ip, netmask, gateway) in [
            ("192.168.1.999", "255.255.255.0", "192.168.1.1"),
            ("192.168.1.50", "255.0.255.0", "192.168.1.1"),
            ("192.168.1.50", "255.255.255.0", "192.168.2.1"),
            ("192.168.1.50", "255.255.255.0", "192.168.1.50"),
            ("192.168.1.0", "255.255.255.0", "192.168.1.1"),
            ("192.168.1.50", "255.255.255.0", "192.168.1.255"),
            ("127.0.0.1", "255.0.0.0", "127.0.0.2"),
            ("240.0.0.1", "255.0.0.0", "240.0.0.2"),
        ] {
            assert!(IpConfiguration::parse(&values(&[
                "--static",
                "--ip",
                ip,
                "--netmask",
                netmask,
                "--gateway",
                gateway,
            ]))
            .is_err());
        }
    }

    #[test]
    fn network_profile_parser_reads_only_confirmed_ip_slots_and_raw_type() {
        let mut raw = [0u8; crate::device_info::DEVICE_INFO_RESPONSE_LEN];
        raw[0x008..0x00c].copy_from_slice(&0u32.to_le_bytes());
        raw[0x1cc..0x1d0].copy_from_slice(&1u32.to_le_bytes());
        raw[0x1d0..0x1e0].copy_from_slice(b"0.0.0.0\0\0\0\0\0\0\0\0\0");
        raw[0x1e0..0x1f0].copy_from_slice(b"0.0.0.0\0\0\0\0\0\0\0\0\0");
        raw[0x1f0..0x200].copy_from_slice(b"0.0.0.0\0\0\0\0\0\0\0\0\0");
        let config = parse_network_profile(&raw).unwrap();
        assert_eq!(config.raw_type, 1);
        assert_eq!(config.ip_type, IpConfigurationType::Dhcp);
        assert_eq!(config.ip_address, "0.0.0.0");
        assert_eq!(config.netmask, "0.0.0.0");
        assert_eq!(config.gateway, "0.0.0.0");
    }

    #[test]
    fn formatted_unknown_ip_type_keeps_raw_value_and_disclaims_runtime_status() {
        let text = format_network_profile(&NetworkProfile {
            raw_type: 9,
            ip_type: IpConfigurationType::Unknown(9),
            ip_address: "0.0.0.0".into(),
            netmask: "0.0.0.0".into(),
            gateway: "0.0.0.0".into(),
        });
        assert!(text.contains("Unverified/unknown (Rohwert 9)"));
        assert!(text.contains("kein Nachweis aktueller Laufzeitwerte"));
    }

    #[test]
    fn setting_requires_one_mode_and_rejects_extra_or_duplicate_values() {
        assert!(IpConfiguration::parse(&[]).is_err());
        assert!(IpConfiguration::parse(&values(&["--dhcp", "--static"])).is_err());
        assert!(IpConfiguration::parse(&values(&["--dhcp", "--ip", "192.168.1.50"])).is_err());
        assert!(IpConfiguration::parse(&values(&["--dhcp", "--dhcp"])).is_err());
        assert!(IpConfiguration::parse(&values(&["--static", "--ip"])).is_err());
    }

    #[test]
    fn successful_ip_setting_is_acknowledged_once_after_poll_completion_status() {
        let mut response = [0u8; 20];
        response[8..12].copy_from_slice(&0u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap();
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn scanner_error_poll_status_is_mapped_and_not_retried() {
        let mut response = [0u8; 20];
        response[0] = 0x10;
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error = set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("native status 91"));
        assert!(message.contains("0x10"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn poll_timeout_after_one_write_is_reported_as_unconfirmed_without_retry() {
        let mut response = [0u8; 20];
        response[0] = 1;
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error = set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::ZERO,
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("unconfirmed"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn unknown_poll_status_after_write_is_unconfirmed_and_never_reissued() {
        let mut response = [0u8; 20];
        response[0] = 0x83;
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error = set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unconfirmed"));
        assert!(message.contains("0x83"));
        assert!(!message.contains("native status"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn transport_failure_after_request_transfer_is_unconfirmed_without_retry() {
        let mut fake = FakeTransport::with_read_error("USB read timeout");
        let error = set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("unconfirmed"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn scanner_return_poll_statuses_are_mapped_without_reissuing_the_write() {
        for (poll_status, expected_detail) in [
            (0x10, "native status 91"),
            (0x11, "native status 91"),
            (0x80, "native status 128"),
            (0x81, "native status 7"),
            (0x82, "native status 130"),
        ] {
            let mut response = [0u8; 20];
            response[0] = poll_status;
            let mut fake = FakeTransport::with_reads(vec![
                status_frame(0).to_vec(),
                response.to_vec(),
                status_frame(0).to_vec(),
            ]);
            let error = set_ip_configuration_once(
                &mut fake,
                &build_ip_setting_request(&IpConfiguration::Dhcp),
                Duration::from_secs(30),
                |_| {},
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected_detail));
            assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        }
    }

    #[test]
    fn completion_status_is_success_without_interpreting_opaque_result_bytes() {
        let mut response = [0u8; 20];
        response[8..12].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap();
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn check_condition_runs_request_sense_and_never_retries_ip_setting() {
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(2).to_vec(),
            vec![0; 18],
            status_frame(0).to_vec(),
        ]);
        let error = set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("unconfirmed"));
        assert!(error.to_string().contains("CHECK CONDITION"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        assert_eq!(&fake.writes[2][19..25], &[0x03, 0, 0, 0, 0x12, 0]);
    }

    #[test]
    fn pending_poll_then_success_repolls_only_the_result_not_the_ip_write() {
        let mut pending = [0u8; 20];
        pending[0] = 1;
        let mut complete = [0u8; 20];
        complete[8..12].copy_from_slice(&0u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            pending.to_vec(),
            status_frame(0).to_vec(),
            complete.to_vec(),
            status_frame(0).to_vec(),
        ]);
        set_ip_configuration_once(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::from_secs(30),
            |_| {},
        )
        .unwrap();
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        assert_eq!(
            fake.writes
                .iter()
                .filter(|write| write.get(19) == Some(&0x1c))
                .count(),
            2
        );
    }

    #[test]
    fn network_profile_parser_rejects_bad_result_and_unterminated_fields() {
        let mut raw = [0u8; crate::device_info::DEVICE_INFO_RESPONSE_LEN];
        raw[0] = 1;
        assert!(parse_network_profile(&raw)
            .unwrap_err()
            .contains("poll result"));
        raw[0] = 0;
        raw[0x008..0x00c].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_network_profile(&raw)
            .unwrap_err()
            .contains("application result"));
        raw[0x008..0x00c].copy_from_slice(&0u32.to_le_bytes());
        raw[0x1d0..0x1e0].fill(b'1');
        assert!(parse_network_profile(&raw)
            .unwrap_err()
            .contains("NUL terminator"));
    }

    fn status_frame(code: u8) -> [u8; 13] {
        let mut bytes = [0u8; 13];
        bytes[0] = 0x53;
        bytes[9] = code;
        bytes
    }

    struct FakeTransport {
        writes: Vec<Vec<u8>>,
        reads: std::collections::VecDeque<Result<Vec<u8>, String>>,
    }

    impl FakeTransport {
        fn with_reads(reads: Vec<Vec<u8>>) -> Self {
            Self {
                writes: Vec::new(),
                reads: reads.into_iter().map(Ok).collect(),
            }
        }

        fn with_read_error(error: &str) -> Self {
            Self {
                writes: Vec::new(),
                reads: vec![Err(error.to_owned())].into(),
            }
        }
    }

    impl BulkTransport for FakeTransport {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }

        fn read_bulk(&mut self, out: &mut [u8]) -> Result<usize, String> {
            let bytes = self
                .reads
                .pop_front()
                .ok_or_else(|| "no simulated USB response".to_string())??;
            if bytes.len() > out.len() {
                return Err("simulated response exceeds requested size".into());
            }
            out[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    fn count_ip_setting_payloads(writes: &[Vec<u8>]) -> usize {
        writes
            .iter()
            .filter(|write| write.len() == REQUEST_LEN)
            .count()
    }
}
