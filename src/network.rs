use crate::protocol;
use crate::{
    device_info,
    protocol::BulkTransport,
    scanner,
    usb::Scanner,
    wifi::{PossessionSession, PossessionState},
};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const SETUP_NET_CMD: &[u8; 16] = b"SETUP NET CMD   ";
const REQUEST_HEADER_LEN: usize = 0x24;
const REQUEST_DATA_LEN: usize = 0x8c;
const REQUEST_LEN: usize = REQUEST_HEADER_LEN + REQUEST_DATA_LEN;
// Usb_Device_Info passes response+0x14 to fcn1001bf20. The native formatter
// reads the raw type at +0x1b8 and 16-byte strings at +0x1bc/+0x1cc/+0x1dc.
// These are their absolute offsets in the 604-byte Result-Poll response.
const IP_TYPE_OFFSET: usize = 0x1cc;
const IP_ADDRESS_OFFSET: usize = 0x1d0;
const NETMASK_OFFSET: usize = 0x1e0;
const GATEWAY_OFFSET: usize = 0x1f0;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const IP_RESULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_IP_RESULT_POLLS: usize = 360;

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
enum IpConfiguration {
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

fn build_ip_setting_request(config: &IpConfiguration) -> [u8; REQUEST_LEN] {
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
    ApiFailure {
        poll_status: u8,
        application_result: u32,
        native_api_return: i32,
    },
    Unconfirmed {
        detail: String,
        native_api_return: Option<i32>,
    },
}

impl std::fmt::Display for SetIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiFailure {
                poll_status,
                application_result,
                native_api_return,
            } => write!(f, "scanner reported API failure: terminal Result-Poll status 0x{poll_status:02x}, application result 0x{application_result:08x} maps to native API return {native_api_return}; final device configuration remains unverified; no retry was attempted"),
            Self::Unconfirmed {
                detail,
                native_api_return,
            } => {
                if let Some(code) = native_api_return {
                    write!(f, "IP configuration outcome unconfirmed (native API return {code}); no retry was attempted: {detail}")
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

fn set_ip_configuration_once<T: BulkTransport>(
    transport: &mut T,
    request: &[u8; REQUEST_LEN],
) -> Result<(), SetIpError> {
    set_ip_configuration_once_with_sleep(transport, request, NETWORK_TIMEOUT, std::thread::sleep)
}

fn set_ip_configuration_once_with_sleep<T, F>(
    transport: &mut T,
    request: &[u8; REQUEST_LEN],
    timeout: Duration,
    mut sleep: F,
) -> Result<(), SetIpError>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    let cdb = [0x1d, 0, 0, 0, 0xb0, 0];
    protocol::scsi_write(transport, &cdb, request).map_err(|error| SetIpError::Unconfirmed {
        detail: format!("USB command/data/status transfer failed: {error}"),
        native_api_return: None,
    })?;

    let started = Instant::now();
    for attempt in 0..MAX_IP_RESULT_POLLS {
        let response =
            protocol::scsi_read_sti(transport, &[0x1c, 0, 0, 0, 0x14, 0], 20).map_err(|error| {
                SetIpError::Unconfirmed {
                    detail: format!(
                        "Result-Poll transport failed after the single IP write: {error}"
                    ),
                    native_api_return: None,
                }
            })?;
        let poll_status = response[0];
        match poll_status {
            0x00 | 0x10 => {
                let application_result =
                    u32::from_le_bytes(response[12..16].try_into().expect("response length is 20"));
                let native_api_return = match application_result {
                    0 => return Ok(()),
                    0x10 => 1,
                    _ => 91,
                };
                return Err(SetIpError::ApiFailure {
                    poll_status,
                    application_result,
                    native_api_return,
                });
            }
            0x01 => {
                let elapsed = started.elapsed();
                if elapsed >= timeout || attempt + 1 == MAX_IP_RESULT_POLLS {
                    return Err(SetIpError::Unconfirmed {
                        detail: format!(
                            "Result-Poll timed out after {} poll(s); final device configuration is unconfirmed",
                            attempt + 1
                        ),
                        native_api_return: None,
                    });
                }
                sleep(IP_RESULT_POLL_INTERVAL.min(timeout - elapsed));
            }
            0x80 | 0x82 => {
                let native_api_return = if poll_status == 0x80 { 128 } else { 130 };
                return Err(SetIpError::Unconfirmed {
                    detail: format!(
                        "Result-Poll status 0x{poll_status:02x} maps to native API return {native_api_return}; final device configuration is unverified"
                    ),
                    native_api_return: Some(native_api_return),
                });
            }
            0x11 | 0x81 | 0x83 => {
                return Err(SetIpError::Unconfirmed {
                    detail: format!(
                        "Result-Poll status 0x{poll_status:02x} does not confirm completion; no IP write was retried"
                    ),
                    native_api_return: None,
                });
            }
            other => {
                return Err(SetIpError::Unconfirmed {
                    detail: format!(
                        "unknown Result-Poll status 0x{other:02x}; final device configuration is unverified and no IP write was retried"
                    ),
                    native_api_return: None,
                });
            }
        }
    }
    Err(SetIpError::Unconfirmed {
        detail:
            "Result-Poll exceeded its bounded poll count; final device configuration is unconfirmed"
                .into(),
        native_api_return: None,
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
    // Windows' successful Scn_Possession_ConfigFile path reads Device_Info
    // without issuing Usb_Possession_Cancel; match that established sequence.
    let session = PossessionSession::acquire(transport, NETWORK_TIMEOUT)?;
    if session.state() != PossessionState::Active {
        return Err(
            "scanner possession was not established; network profile was not queried".into(),
        );
    }
    let response = device_info::read_ix500_0u00_response(transport)?;
    parse_network_profile(&response)
}

pub fn set(args: &[String]) -> Result<(), String> {
    let config = IpConfiguration::parse(args)?;
    let mut scanner = Scanner::open()?;
    verify_supported_device(&mut scanner)?;
    println!("Target: Fujitsu ScanSnap iX500 firmware 0U00");
    println!("Sending one IP-setting request; any uncertain result stops without retry.");
    set_ip_configuration_from(&mut scanner, &config)?;
    println!("Scanner reported IP-setting success (application result 0). This does not verify a live address or DHCP lease.");
    Ok(())
}

fn set_ip_configuration_from<T: BulkTransport>(
    transport: &mut T,
    config: &IpConfiguration,
) -> Result<(), String> {
    let request = build_ip_setting_request(config);
    let session = PossessionSession::acquire(transport, NETWORK_TIMEOUT)?;
    if session.state() != PossessionState::Active {
        return Err("scanner possession was not established; IP setting was not sent".into());
    }
    set_ip_configuration_once(transport, &request).map_err(|error| error.to_string())
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
    fn dhcp_request_matches_independent_native_reference_bytes() {
        let request = build_ip_setting_request(&IpConfiguration::Dhcp);
        let zero_address = b"0.0.0.0\0\0\0\0\0\0\0\0\0";
        let expected = [
            &b"SETUP NET CMD   "[..],
            &[0x00, 0x9c, 0, 0],
            &[0x03, 0x10, 0, 0],
            &[0; 8],
            &[0x8c, 0, 0, 0],
            &[1, 0, 0, 0],
            &zero_address[..],
            &zero_address[..],
            &zero_address[..],
            &[0; 88],
        ]
        .concat();
        assert_eq!(expected.len(), 0xb0);
        assert_eq!(request.as_slice(), expected);
    }

    #[test]
    fn static_request_matches_independent_native_reference_bytes() {
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
        let expected = [
            &b"SETUP NET CMD   "[..],
            &[0x00, 0x9c, 0, 0],
            &[0x03, 0x10, 0, 0],
            &[0; 8],
            &[0x8c, 0, 0, 0],
            &[0, 0, 0, 0],
            &b"192.168.1.50\0\0\0\0"[..],
            &b"255.255.255.0\0\0\0"[..],
            &b"192.168.1.1\0\0\0\0\0"[..],
            &[0; 88],
        ]
        .concat();
        assert_eq!(expected.len(), 0xb0);
        assert_eq!(request.as_slice(), expected);
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
    fn native_application_result_zero_maps_to_api_zero_and_matches_windows_success() {
        let mut response = [0u8; 20];
        response[0] = 0x10;
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
            .unwrap();
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn native_application_result_0x10_also_maps_to_wrapper_rejected_return_1() {
        let mut response = [0u8; 20];
        response[0] = 0x10;
        response[12..16].copy_from_slice(&0x10u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err()
                .to_string();
        assert!(error.contains("application result 0x00000010"));
        assert!(error.contains("API return 1"));
        assert!(error.contains("scanner reported API failure"));
        assert!(error.contains("final device configuration remains unverified"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn poll_status_zero_uses_application_result_for_native_return_mapping() {
        let mut response = [0u8; 20];
        response[0] = 0;
        response[12..16].copy_from_slice(&0x10u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("application result 0x00000010"));
        assert!(message.contains("API return 1"));
        assert!(message.contains("terminal Result-Poll status 0x00"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn native_status_0x01_is_not_assumed_complete_or_retried() {
        let mut response = [0u8; 20];
        response[0] = 1;
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error = set_ip_configuration_once_with_sleep(
            &mut fake,
            &build_ip_setting_request(&IpConfiguration::Dhcp),
            Duration::ZERO,
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("unconfirmed"));
        assert!(error.to_string().contains("timed out"));
        assert!(!error.to_string().contains("native API return"));
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
        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unconfirmed"));
        assert!(message.contains("0x83"));
        assert!(!message.contains("native API return"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn transport_failure_after_request_transfer_is_unconfirmed_without_retry() {
        let mut fake = FakeTransport::with_read_error("USB read timeout");
        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err();
        assert!(error.to_string().contains("unconfirmed"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn result_poll_transport_failure_after_set_is_unconfirmed_without_retry() {
        let mut fake = FakeTransport {
            writes: Vec::new(),
            reads: vec![Ok(status_frame(0).to_vec()), Err("USB read timeout".into())].into(),
        };

        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err()
                .to_string();

        assert!(error.contains("unconfirmed"));
        assert!(error.contains("USB read timeout"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        assert_eq!(
            fake.writes
                .iter()
                .filter(|write| write.get(19..25) == Some(&[0x1c, 0, 0, 0, 0x14, 0]))
                .count(),
            1
        );
    }

    #[test]
    fn scanner_return_poll_statuses_are_mapped_without_reissuing_the_write() {
        for (poll_status, expected_detail) in [
            (0x11, None),
            (0x80, Some("native API return 128")),
            (0x81, None),
            (0x82, Some("native API return 130")),
            (0x83, None),
            (0xfe, None),
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
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(&format!("0x{poll_status:02x}")));
            if let Some(expected_detail) = expected_detail {
                assert!(error.contains(expected_detail));
            } else {
                assert!(!error.contains("native API return"));
            }
            assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        }
    }

    #[test]
    fn unknown_native_application_result_maps_to_91_and_is_not_accepted() {
        let mut response = [0u8; 20];
        response[0] = 0x10;
        response[12..16].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            response.to_vec(),
            status_frame(0).to_vec(),
        ]);
        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err()
                .to_string();
        assert!(error.contains("application result 0xdeadbeef"));
        assert!(error.contains("API return 91"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
    }

    #[test]
    fn check_condition_runs_request_sense_and_never_retries_ip_setting() {
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(2).to_vec(),
            vec![0; 18],
            status_frame(0).to_vec(),
        ]);
        let error =
            set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
                .unwrap_err();
        assert!(error.to_string().contains("unconfirmed"));
        assert!(error.to_string().contains("CHECK CONDITION"));
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        assert_eq!(&fake.writes[2][19..25], &[0x03, 0, 0, 0, 0x12, 0]);
    }

    #[test]
    fn native_terminal_poll_0x10_is_20_bytes_and_never_reissues_the_ip_write() {
        let mut complete = [0u8; 20];
        complete[0] = 0x10;
        complete[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            complete.to_vec(),
            status_frame(0).to_vec(),
        ]);
        set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
            .unwrap();
        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        assert_eq!(
            fake.writes
                .iter()
                .filter(|write| write.get(19) == Some(&0x1c))
                .count(),
            1
        );
        assert!(fake
            .writes
            .iter()
            .any(|write| write.get(19..25) == Some(&[0x1c, 0, 0, 0, 0x14, 0])));
    }

    #[test]
    fn pending_ip_result_repolls_without_reissuing_the_single_set() {
        let mut pending = [0u8; 20];
        pending[0] = 1;
        let mut complete = [0u8; 20];
        complete[0] = 0;
        complete[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            pending.to_vec(),
            status_frame(0).to_vec(),
            complete.to_vec(),
            status_frame(0).to_vec(),
        ]);

        set_ip_configuration_once(&mut fake, &build_ip_setting_request(&IpConfiguration::Dhcp))
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
    fn full_ip_write_sequence_acquires_possession_then_sets_once_and_polls() {
        let mut complete = [0u8; 20];
        complete[0] = 0;
        complete[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            complete.to_vec(),
            status_frame(0).to_vec(),
            status_frame(0).to_vec(),
            complete.to_vec(),
            status_frame(0).to_vec(),
        ]);

        set_ip_configuration_from(&mut fake, &IpConfiguration::Dhcp).unwrap();

        assert_eq!(count_ip_setting_payloads(&fake.writes), 1);
        assert_eq!(
            fake.writes
                .iter()
                .filter(|write| write.get(19..25) == Some(&[0x1c, 0, 0, 0, 0x14, 0]))
                .count(),
            2
        );
        assert!(fake.writes.iter().any(|write| {
            write.as_slice() == crate::wifi::PossessionCommand::Start.payload().as_slice()
        }));
    }

    #[test]
    fn successful_network_show_read_does_not_send_an_unproven_end_command() {
        let mut complete = [0u8; 20];
        complete[0] = 0;
        let mut response = vec![0u8; device_info::DEVICE_INFO_RESPONSE_LEN];
        response[0] = 0;
        let mut fake = FakeTransport::with_reads(vec![
            status_frame(0).to_vec(),
            complete.to_vec(),
            status_frame(0).to_vec(),
            status_frame(0).to_vec(),
            response,
            status_frame(0).to_vec(),
        ]);

        read_profile_from(&mut fake).unwrap();

        assert!(fake.writes.iter().any(|write| {
            write.as_slice() == crate::wifi::PossessionCommand::Start.payload().as_slice()
        }));
        assert!(!fake.writes.iter().any(|write| {
            write.as_slice() == crate::wifi::PossessionCommand::End.payload().as_slice()
        }));
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
