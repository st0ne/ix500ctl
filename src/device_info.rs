//! Parser and read-only transport for the legacy iX500 `Usb_Device_Info` query.

use crate::{
    protocol::{self, BulkTransport},
    wifi::{PossessionSession, PossessionState},
};
use std::time::{Duration, Instant};

pub const DEVICE_INFO_RESPONSE_LEN: usize = 0x25c;
const DEVICE_INFO_HEADER_LEN: usize = 0x24;
const DEVICE_INFO_PROFILE_LEN: u32 = 0x248;
const DEVICE_INFO_MAC_OFFSET: usize = 0x158;
const DEVICE_INFO_PROFILE_BASE_OFFSET: usize = 0x14;
const DEVICE_INFO_SSID_REL_OFFSET: usize = 0x04c;
const DEVICE_INFO_SECURITY_REL_OFFSET: usize = 0x070;
const DEVICE_INFO_ENCRYPTION_REL_OFFSET: usize = 0x078;
const DEVICE_INFO_MAC_REL_OFFSET: usize = 0x144;
const DEVICE_INFO_MODE_REL_OFFSET: usize = 0x158;
const DEVICE_INFO_MODE_END_REL_OFFSET: usize = 0x16c;
const DEVICE_INFO_TIMEOUT: Duration = Duration::from_secs(30);
const RESULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_RESULT_POLLS: usize = 360;

pub fn build_ix500_0u00_request() -> [u8; DEVICE_INFO_HEADER_LEN] {
    let mut request = [0u8; DEVICE_INFO_HEADER_LEN];
    request[..16].copy_from_slice(b"SETUP NET CMD   ");
    request[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
    request[20..24].copy_from_slice(&4u32.to_le_bytes());
    request[32..36].copy_from_slice(&DEVICE_INFO_PROFILE_LEN.to_le_bytes());
    request
}

/// WLAN values reported by the scanner as profile data. These are not a
/// live-association check; secret/key fields are deliberately not represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiProfile {
    pub ssid: String,
    pub security: String,
    pub encryption: String,
    pub mode: String,
    pub mac_address: String,
}

/// Parse only the documented 0U00 profile slots from the complete 604-byte
/// Device_Info result. Unknown fields, including key material, are ignored.
pub fn parse_ix500_0u00_profile(raw: &[u8]) -> Result<WifiProfile, String> {
    if raw.len() != DEVICE_INFO_RESPONSE_LEN {
        return Err(format!(
            "Device_Info response has {} bytes; expected exactly {DEVICE_INFO_RESPONSE_LEN}",
            raw.len()
        ));
    }
    if raw[0] != 0 {
        return Err(format!(
            "Device_Info poll result is not complete (0x{:02x})",
            raw[0]
        ));
    }
    let application_result =
        u32::from_le_bytes(raw[8..12].try_into().expect("response length checked"));
    if application_result != 0 {
        return Err(format!(
            "Device_Info application result is 0x{application_result:08x}"
        ));
    }

    let ssid = read_profile_text(
        raw,
        DEVICE_INFO_SSID_REL_OFFSET,
        DEVICE_INFO_SECURITY_REL_OFFSET,
        "SSID",
    )?;
    let security = read_profile_text(
        raw,
        DEVICE_INFO_SECURITY_REL_OFFSET,
        DEVICE_INFO_ENCRYPTION_REL_OFFSET,
        "security type",
    )?;
    let encryption =
        read_profile_text(raw, DEVICE_INFO_ENCRYPTION_REL_OFFSET, 0x080, "encryption")?;
    let mac_address = read_profile_text(
        raw,
        DEVICE_INFO_MAC_REL_OFFSET,
        DEVICE_INFO_MODE_REL_OFFSET,
        "MAC",
    )?;
    if !valid_mac(&mac_address) {
        return Err("Device_Info MAC field is not a colon-separated 6-byte address".into());
    }
    let mode = read_profile_text(
        raw,
        DEVICE_INFO_MODE_REL_OFFSET,
        DEVICE_INFO_MODE_END_REL_OFFSET,
        "operating mode",
    )?;

    Ok(WifiProfile {
        ssid,
        security,
        encryption,
        mode,
        mac_address: mac_address.to_ascii_uppercase(),
    })
}

fn read_profile_text(
    raw: &[u8],
    start: usize,
    end: usize,
    field_name: &str,
) -> Result<String, String> {
    let absolute_start = DEVICE_INFO_PROFILE_BASE_OFFSET + start;
    let absolute_end = DEVICE_INFO_PROFILE_BASE_OFFSET + end;
    let slot = raw
        .get(absolute_start..absolute_end)
        .ok_or_else(|| format!("Device_Info {field_name} field bounds exceed the response"))?;
    let length = slot.iter().position(|byte| *byte == 0).ok_or_else(|| {
        format!("Device_Info {field_name} field is not NUL-terminated within its slot")
    })?;
    if length == 0 {
        return Err(format!("Device_Info {field_name} field is empty"));
    }
    let value = std::str::from_utf8(&slot[..length])
        .map_err(|_| format!("Device_Info {field_name} field is not valid UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(format!(
            "Device_Info {field_name} field contains a control character"
        ));
    }
    Ok(value.to_owned())
}

/// Extract field 6 from the 0U00 Device_Info response. The Windows formatter
/// emits several NUL-terminated fields from this record; a live iX500 response
/// identifies the MAC field at offset 0x158. Validate strictly before display.
pub fn extract_ix500_0u00_mac(raw: &[u8]) -> Result<String, String> {
    if raw.len() != DEVICE_INFO_RESPONSE_LEN {
        return Err(format!(
            "device-info response has {} bytes; expected {DEVICE_INFO_RESPONSE_LEN}",
            raw.len()
        ));
    }
    let tail = &raw[DEVICE_INFO_MAC_OFFSET..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "device-info MAC field 6 is not NUL-terminated".to_string())?;
    let text = std::str::from_utf8(&tail[..end])
        .map_err(|_| "device-info MAC field 6 is not valid ASCII".to_string())?;
    if !valid_mac(text) {
        let offsets = raw
            .windows(17)
            .enumerate()
            .filter_map(|(offset, window)| {
                std::str::from_utf8(window)
                    .ok()
                    .filter(|candidate| valid_mac(candidate))
                    .map(|_| offset)
            })
            .collect::<Vec<_>>();
        return Err(format!("device-info MAC field 6 at offset 0x{DEVICE_INFO_MAC_OFFSET:03x} is malformed; sanitized MAC-shaped field offsets: {offsets:x?}"));
    }
    Ok(text.to_ascii_uppercase())
}

/// Perform the reconstructed Device_Info query and return its complete 604-byte
/// application response. `scsi_read_sti` validates the separate transport frame.
pub fn read_ix500_0u00_response<T: BulkTransport>(transport: &mut T) -> Result<Vec<u8>, String> {
    let request = build_ix500_0u00_request();
    protocol::scsi_write(transport, &[0x1d, 0, 0, 0, 0x24, 0], &request)
        .map_err(|error| format!("Device_Info request failed: {error}"))?;

    let started = Instant::now();
    for attempt in 0..MAX_RESULT_POLLS {
        let response = protocol::scsi_read_sti(
            transport,
            &[0x1c, 0, 0, 0x02, 0x5c, 0],
            DEVICE_INFO_RESPONSE_LEN,
        )
        .map_err(|error| format!("Device_Info result poll failed: {error}"))?;
        match response[0] {
            0 => return Ok(response),
            1 => {
                let elapsed = started.elapsed();
                if elapsed >= DEVICE_INFO_TIMEOUT || attempt + 1 == MAX_RESULT_POLLS {
                    return Err("Device_Info result poll timed out".into());
                }
                std::thread::sleep(RESULT_POLL_INTERVAL.min(DEVICE_INFO_TIMEOUT - elapsed));
            }
            code => {
                return Err(format!(
                    "Device_Info returned application result 0x{code:02x}"
                ))
            }
        }
    }
    Err("Device_Info result poll timed out".into())
}

/// Perform the known read-only query and return only the validated MAC field.
pub fn read_ix500_0u00_mac<T: BulkTransport>(transport: &mut T) -> Result<String, String> {
    let response = read_ix500_0u00_response(transport)?;
    extract_ix500_0u00_mac(&response)
}

/// Acquire the scanner-side possession and read only the confirmed profile
/// fields. The profile is not an assertion about current WLAN association.
pub fn read_scanner_profile<T: BulkTransport>(
    transport: &mut T,
    firmware: &str,
) -> Result<WifiProfile, String> {
    if firmware != "0U00" {
        return Err(format!(
            "Device_Info profile query supports firmware 0U00 only (device reports {firmware})"
        ));
    }
    let session = PossessionSession::acquire(transport, DEVICE_INFO_TIMEOUT)?;
    if session.state() != PossessionState::Active {
        return Err("scanner possession was not established; Device_Info was not queried".into());
    }
    let response = read_ix500_0u00_response(transport)?;
    parse_ix500_0u00_profile(&response)
}

/// Compatibility entry point used by the existing `device info` command.
pub fn read_scanner_mac<T: BulkTransport>(
    transport: &mut T,
    firmware: &str,
) -> Result<String, String> {
    if firmware != "0U00" {
        return Err(format!(
            "Device_Info MAC query supports firmware 0U00 only (device reports {firmware})"
        ));
    }
    let session = PossessionSession::acquire(transport, DEVICE_INFO_TIMEOUT)?;
    if session.state() != PossessionState::Active {
        return Err("scanner possession was not established; Device_Info was not queried".into());
    }
    read_ix500_0u00_mac(transport)
}

fn valid_mac(value: &str) -> bool {
    value.len() == 17
        && value.as_bytes().iter().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                *b == b':'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyWifiDeviceInfo {
    pub scanner_name: String,
    pub scanner_version: String,
    pub ssid: String,
    pub security: String,
    pub encryption: String,
    pub mac_address: String,
}

#[cfg(test)]
pub fn parse_legacy_wifi_device_info(record: &str) -> Result<LegacyWifiDeviceInfo, String> {
    if record.len() > 350 {
        return Err("legacy device-info record exceeds the Windows output buffer size".into());
    }
    let fields: Vec<&str> = record.trim_end_matches('\0').split('\t').collect();
    if fields.len() < 21 {
        return Err(format!(
            "legacy device-info record has {} fields; expected at least 21",
            fields.len()
        ));
    }
    let mac = fields[6];
    if !valid_mac(mac) {
        return Err(
            "legacy device-info MAC field 6 is not a colon-separated 6-byte address".into(),
        );
    }
    Ok(LegacyWifiDeviceInfo {
        scanner_name: fields[0].to_owned(),
        scanner_version: fields[1].to_owned(),
        ssid: fields[2].to_owned(),
        security: fields[3].to_owned(),
        encryption: fields[4].to_owned(),
        mac_address: mac.to_ascii_uppercase(),
    })
}

#[cfg(test)]
pub fn parse_ix500_0u00_device_info(
    record: &str,
    firmware: &str,
) -> Result<LegacyWifiDeviceInfo, String> {
    if firmware != "0U00" {
        return Err(format!("Usb_Device_Info profile parser supports firmware 0U00 only (device reports {firmware})"));
    }
    parse_legacy_wifi_device_info(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reconstructed from the legacy 0U00 branch's 21-field C# mapping and
    // its in-source iX500 fixture; no real scanner profile or key is included.
    const FIXTURE: &str = "iX500-A09B000123\t01.01\tLabNetwork\tWPA2\tAES\t<redacted>\t00:01:02:03:04:05\tManaged\t2\t0\t3\t50\tIEEE802.11n\t1\t192.0.2.20\t255.255.255.0\t192.0.2.1\t1\t0000\t0\t\t";

    #[derive(Default)]
    struct FakeTransport {
        writes: Vec<Vec<u8>>,
        reads: std::collections::VecDeque<Vec<u8>>,
    }
    impl BulkTransport for FakeTransport {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }
        fn read_bulk(&mut self, output: &mut [u8]) -> Result<usize, String> {
            let input = self.reads.pop_front().ok_or("no fake transfer")?;
            if input.len() > output.len() {
                return Err("fake transfer exceeds read size".into());
            }
            output[..input.len()].copy_from_slice(&input);
            Ok(input.len())
        }
    }

    fn status() -> [u8; 13] {
        let mut bytes = [0; 13];
        bytes[0] = 0x53;
        bytes
    }

    #[test]
    fn device_info_reader_rejects_non_good_transport_status() {
        let raw = valid_profile_response();
        let mut bad_status = status();
        bad_status[9] = 8;
        let mut transport = FakeTransport {
            writes: Vec::new(),
            reads: vec![status().to_vec(), raw.to_vec(), bad_status.to_vec()].into(),
        };
        let error = read_ix500_0u00_response(&mut transport).unwrap_err();
        assert!(error.contains("SCSI BUSY"));
    }

    #[test]
    fn device_info_query_uses_reconstructed_header_cdb_and_604_byte_poll_without_dumping() {
        let mut raw = [0u8; DEVICE_INFO_RESPONSE_LEN];
        raw[0x158..0x158 + 17].copy_from_slice(b"02:11:22:33:44:55");
        let mut transport = FakeTransport {
            writes: Vec::new(),
            reads: vec![status().to_vec(), raw.to_vec(), status().to_vec()].into(),
        };
        assert_eq!(
            read_ix500_0u00_mac(&mut transport).unwrap(),
            "02:11:22:33:44:55"
        );
        assert_eq!(transport.writes.len(), 3);
        assert_eq!(&transport.writes[0][19..25], &[0x1d, 0, 0, 0, 0x24, 0]);
        assert_eq!(transport.writes[1], build_ix500_0u00_request());
        assert_eq!(&transport.writes[2][19..25], &[0x1c, 0, 0, 2, 0x5c, 0]);
        assert_eq!(transport.reads.len(), 0);
    }

    #[test]
    fn device_info_request_header_matches_windows_fields() {
        let request = build_ix500_0u00_request();
        assert_eq!(&request[..16], b"SETUP NET CMD   ");
        assert_eq!(
            u32::from_le_bytes(request[16..20].try_into().unwrap()),
            0x1000
        );
        assert_eq!(u32::from_le_bytes(request[20..24].try_into().unwrap()), 4);
        assert!(request[24..32].iter().all(|byte| *byte == 0));
        assert_eq!(
            u32::from_le_bytes(request[32..36].try_into().unwrap()),
            0x248
        );
    }

    #[test]
    fn legacy_wifi_info_extracts_mac_from_field_six_without_returning_key() {
        let parsed = parse_ix500_0u00_device_info(FIXTURE, "0U00").unwrap();
        assert_eq!(parsed.scanner_name, "iX500-A09B000123");
        assert_eq!(parsed.scanner_version, "01.01");
        assert_eq!(parsed.ssid, "LabNetwork");
        assert_eq!(parsed.mac_address, "00:01:02:03:04:05");
        assert!(parse_ix500_0u00_device_info(FIXTURE, "0E00").is_err());
    }

    #[test]
    fn raw_ix500_profile_extracts_only_documented_mac_slot() {
        let mut raw = [0u8; DEVICE_INFO_RESPONSE_LEN];
        raw[..16].copy_from_slice(b"ScannerName12345");
        raw[0x44..0x49].copy_from_slice(b"01.01");
        raw[0x4c..0x70].fill(b'x');
        raw[0x70..0x74].copy_from_slice(b"WPA2");
        raw[0x78..0x7b].copy_from_slice(b"AES");
        raw[0x80..0x83].copy_from_slice(b"key");
        raw[0x158..0x158 + 17].copy_from_slice(b"02:11:22:33:44:55");
        raw[0x158 + 17] = 0;
        assert_eq!(extract_ix500_0u00_mac(&raw).unwrap(), "02:11:22:33:44:55");
    }

    #[test]
    fn raw_ix500_profile_rejects_wrong_size_and_non_mac_slot_without_dumping_data() {
        assert!(extract_ix500_0u00_mac(&[0; DEVICE_INFO_RESPONSE_LEN - 1]).is_err());
        let mut raw = [0u8; DEVICE_INFO_RESPONSE_LEN];
        raw[0x158..0x158 + 11].copy_from_slice(b"ssid-secret");
        let error = extract_ix500_0u00_mac(&raw).unwrap_err();
        assert!(error.contains("field 6"));
        assert!(!error.contains("ssid-secret"));
    }

    #[test]
    fn wifi_profile_parser_reads_only_confirmed_slots() {
        let raw = valid_profile_response();
        let profile = parse_ix500_0u00_profile(&raw).unwrap();
        assert_eq!(profile.ssid, "NET-01");
        assert_eq!(profile.security, "WPA2");
        assert_eq!(profile.encryption, "AES");
        assert_eq!(profile.mode, "Managed");
        assert_eq!(profile.mac_address, "02:11:22:33:44:55");
    }

    #[test]
    fn wifi_profile_parser_rejects_short_response_and_nonzero_statuses() {
        let raw = valid_profile_response();
        assert!(
            parse_ix500_0u00_profile(&raw[..DEVICE_INFO_RESPONSE_LEN - 1])
                .unwrap_err()
                .contains("604")
        );

        let mut bad_poll = raw.clone();
        bad_poll[0] = 1;
        assert!(parse_ix500_0u00_profile(&bad_poll)
            .unwrap_err()
            .contains("poll"));

        let mut bad_result = raw;
        bad_result[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(parse_ix500_0u00_profile(&bad_result)
            .unwrap_err()
            .contains("result"));
    }

    #[test]
    fn wifi_profile_parser_rejects_missing_nul_inside_each_fixed_field() {
        for (start, end) in [(0x60, 0x84), (0x84, 0x8c), (0x8c, 0x94), (0x16c, 0x180)] {
            let mut raw = valid_profile_response();
            raw[start..end].fill(b'X');
            assert!(
                parse_ix500_0u00_profile(&raw).is_err(),
                "slot {start:#x} must be NUL-terminated"
            );
        }
        let mut raw = valid_profile_response();
        raw[0x158..0x16c].fill(b'X');
        assert!(
            parse_ix500_0u00_profile(&raw).is_err(),
            "MAC slot must be NUL-terminated"
        );
    }

    #[test]
    fn wifi_profile_parser_rejects_invalid_or_control_text_without_echoing_it() {
        let mut raw = valid_profile_response();
        raw[0x60] = 0xff;
        let error = parse_ix500_0u00_profile(&raw).unwrap_err();
        assert!(error.contains("SSID"));
        assert!(!error.contains("ff"));

        let mut raw = valid_profile_response();
        raw[0x60] = 10;
        assert!(parse_ix500_0u00_profile(&raw).unwrap_err().contains("SSID"));
    }

    fn valid_profile_response() -> [u8; DEVICE_INFO_RESPONSE_LEN] {
        let mut raw = [0u8; DEVICE_INFO_RESPONSE_LEN];
        raw[0] = 0;
        raw[8..12].copy_from_slice(&0u32.to_le_bytes());
        raw[0x60..0x66].copy_from_slice(b"NET-01");
        raw[0x84..0x88].copy_from_slice(b"WPA2");
        raw[0x8c..0x8f].copy_from_slice(b"AES");
        raw[0x158..0x169].copy_from_slice(b"02:11:22:33:44:55");
        raw[0x16c..0x173].copy_from_slice(b"Managed");
        raw
    }

    #[test]
    fn legacy_wifi_info_rejects_short_record_and_malformed_mac() {
        assert!(parse_legacy_wifi_device_info("too\tfew\tfields").is_err());
        let malformed = FIXTURE.replace("00:01:02:03:04:05", "000102030405");
        assert!(parse_legacy_wifi_device_info(&malformed).is_err());
    }
}
