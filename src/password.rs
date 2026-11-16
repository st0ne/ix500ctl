const IX500_CONNECTION_PASSWORD_TABLE: &[u8] =
    b"aQweSrTywuIoppAsFdfGuhjkslZxCcvBAnmqNweRstyuNiopaAsdPfghajKlPzxc";
const DEVICE_INFO_NAME_SLOT_LEN: usize = 0x44;
const PASSWORD_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn validate_supported_firmware(inquiry: &str, query_marker: &str) -> Result<(), String> {
    if inquiry != "0U00" {
        return Err(format!(
            "scanner connection-password management supports iX500 firmware 0U00 only (device reports {inquiry})"
        ));
    }
    if query_marker != inquiry {
        return Err(format!(
            "SCSI INQUIRY firmware {inquiry} does not match GET FIRMVERSION {query_marker}; no password operation was sent"
        ));
    }
    Ok(())
}

fn encode_connection_password(password: &[u8]) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Err("scanner connection password must not be empty".into());
    }
    if password.len() > 16 {
        return Err("scanner connection password must be at most 16 ASCII characters".into());
    }
    if !password.iter().all(|byte| (b'!'..=b'~').contains(byte)) {
        return Err(
            "scanner connection password accepts printable ASCII only, without spaces".into(),
        );
    }

    let mut encoded = Vec::with_capacity(password.len() * 3);
    for (index, byte) in password.iter().copied().enumerate() {
        let value = u16::from(byte) + u16::from(IX500_CONNECTION_PASSWORD_TABLE[index]) + 11;
        encoded.push(b'0' + (value / 100) as u8);
        encoded.push(b'0' + ((value / 10) % 10) as u8);
        encoded.push(b'0' + (value % 10) as u8);
    }
    Ok(encoded)
}

fn decode_connection_password(encoded: &[u8]) -> Result<Vec<u8>, String> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(3) || encoded.len() / 3 > 16 {
        return Err("scanner returned an invalid encoded connection password length".into());
    }

    let mut password = Vec::with_capacity(encoded.len() / 3);
    for (index, triplet) in encoded.chunks_exact(3).enumerate() {
        if !triplet.iter().all(u8::is_ascii_digit) {
            password.fill(0);
            return Err("scanner returned a non-decimal connection password code".into());
        }
        let value = u16::from(triplet[0] - b'0') * 100
            + u16::from(triplet[1] - b'0') * 10
            + u16::from(triplet[2] - b'0');
        let offset = u16::from(IX500_CONNECTION_PASSWORD_TABLE[index]) + 11;
        let Some(decoded) = value.checked_sub(offset) else {
            password.fill(0);
            return Err("scanner connection password code is outside the native range".into());
        };
        if !(u16::from(b'!')..=u16::from(b'~')).contains(&decoded) {
            password.fill(0);
            return Err(
                "scanner connection password code decodes outside the native character range"
                    .into(),
            );
        }
        password.push(decoded as u8);
    }
    Ok(password)
}

fn build_configfile_size_request() -> [u8; 36] {
    let mut request = [0u8; 36];
    request[..16].copy_from_slice(b"SETUP NET CMD   ");
    request[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
    request[20..24].copy_from_slice(&1u32.to_le_bytes());
    request
}

fn build_configfile_request(file_size: usize) -> Result<[u8; 36], String> {
    if !(1..=0xff0).contains(&file_size) {
        return Err("scanner config file size is outside the native 1..=4080 byte range".into());
    }
    let mut request = [0u8; 36];
    request[..16].copy_from_slice(b"SETUP NET CMD   ");
    request[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
    request[20..24].copy_from_slice(&2u32.to_le_bytes());
    request[32..36].copy_from_slice(&(file_size as u32).to_le_bytes());
    Ok(request)
}

fn parse_configfile_size_response(response: &[u8]) -> Result<Option<usize>, String> {
    if response.len() != 24 {
        return Err("scanner config-size response must be exactly 24 bytes".into());
    }
    match response[0] {
        1 => return Ok(None),
        0 => {}
        code => {
            return Err(format!(
                "scanner config-size poll returned status 0x{code:02x}"
            ))
        }
    }
    let application_result =
        u32::from_le_bytes(response[8..12].try_into().expect("length checked"));
    if application_result != 0 {
        return Err(format!(
            "scanner config-size request failed with native result 0x{application_result:08x}"
        ));
    }
    let file_size =
        u32::from_le_bytes(response[20..24].try_into().expect("length checked")) as usize;
    if !(1..=0xff0).contains(&file_size) {
        return Err(
            "scanner reported a config file size outside the native 1..=4080 byte range".into(),
        );
    }
    Ok(Some(file_size))
}

struct MobilePasswordSettings {
    password: Option<Vec<u8>>,
    password_display: u32,
}

impl Drop for MobilePasswordSettings {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.fill(0);
        }
    }
}

fn parse_mobile_config(config: &[u8]) -> Result<MobilePasswordSettings, String> {
    let config = &config[..config
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(config.len())];
    let mut password_mode = 0u8;
    let mut password_code: Option<&[u8]> = None;
    let mut password_display = 0u32;
    let mut seen_mode = false;
    let mut seen_code = false;
    let mut seen_display = false;

    for line in config.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(value) = line.strip_prefix(b"PwdMode=") {
            if seen_mode {
                return Err("scanner config contains duplicate PwdMode fields".into());
            }
            seen_mode = true;
            password_mode = match value {
                b"0" => 0,
                b"1" => 1,
                _ => return Err("scanner config contains an invalid PwdMode value".into()),
            };
        } else if let Some(value) = line.strip_prefix(b"PwdCode=") {
            if seen_code {
                return Err("scanner config contains duplicate PwdCode fields".into());
            }
            seen_code = true;
            password_code = Some(value);
        } else if let Some(value) = line.strip_prefix(b"PwdDisp=") {
            if seen_display {
                return Err("scanner config contains duplicate PwdDisp fields".into());
            }
            seen_display = true;
            password_display = match value {
                b"0" => 0,
                b"1" => 1,
                _ => return Err("scanner config contains an invalid PwdDisp value".into()),
            };
        }
    }

    if !seen_mode || !seen_display {
        return Err("scanner config is missing PwdMode or PwdDisp".into());
    }
    let password = match (password_mode, password_code) {
        (1, Some(code)) if !code.is_empty() => Some(decode_connection_password(code)?),
        (1, _) => {
            return Err("scanner config marks a password as enabled but has no PwdCode".into())
        }
        (0, _) => None,
        _ => unreachable!("PwdMode was validated while parsing"),
    };
    Ok(MobilePasswordSettings {
        password,
        password_display,
    })
}

fn parse_configfile_response(response: &[u8], file_size: usize) -> Result<Option<&[u8]>, String> {
    if response.len() != 0x1004 {
        return Err("scanner config-file response must be exactly 4100 bytes".into());
    }
    if !(1..=0xff0).contains(&file_size) {
        return Err("scanner config file size is outside the native 1..=4080 byte range".into());
    }
    match response[0] {
        1 => return Ok(None),
        0 => {}
        code => {
            return Err(format!(
                "scanner config-file poll returned status 0x{code:02x}"
            ))
        }
    }
    let application_result =
        u32::from_le_bytes(response[8..12].try_into().expect("length checked"));
    if application_result != 0 {
        return Err(format!(
            "scanner config-file request failed with native result 0x{application_result:08x}"
        ));
    }
    let end = 0x14 + file_size;
    Ok(Some(&response[0x14..end]))
}

fn read_mobile_config_from<T: crate::protocol::BulkTransport>(
    transport: &mut T,
) -> Result<MobilePasswordSettings, String> {
    const OUT_CDB: [u8; 6] = [0x1d, 0, 0, 0, 0x24, 0];
    const SIZE_CDB: [u8; 6] = [0x1c, 0, 0, 0, 0x18, 0];
    const CONFIG_CDB: [u8; 6] = [0x1c, 0, 0, 0x10, 0x04, 0];
    const POLL_COUNT: usize = 60;
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

    crate::protocol::scsi_write(transport, &OUT_CDB, &build_configfile_size_request())?;
    let mut file_size = None;
    for _ in 0..POLL_COUNT {
        let response = crate::protocol::scsi_read_sti(transport, &SIZE_CDB, 24)?;
        if let Some(size) = parse_configfile_size_response(&response)? {
            file_size = Some(size);
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let file_size = file_size.ok_or("timed out waiting for scanner config-file size")?;

    let request = build_configfile_request(file_size)?;
    crate::protocol::scsi_write(transport, &OUT_CDB, &request)?;
    let mut config_data = None;
    for _ in 0..POLL_COUNT {
        let response = crate::protocol::scsi_read_sti(transport, &CONFIG_CDB, 0x1004)?;
        if let Some(data) = parse_configfile_response(&response, file_size)? {
            config_data = Some(data.to_vec());
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let mut config_data = config_data.ok_or("timed out waiting for scanner config file")?;
    let result = parse_mobile_config(&config_data);
    config_data.fill(0);
    result
}

fn parse_scanner_name_response(response: &[u8]) -> Result<String, String> {
    if response.len() != crate::device_info::DEVICE_INFO_RESPONSE_LEN {
        return Err(format!(
            "Device_Info response must be exactly {} bytes",
            crate::device_info::DEVICE_INFO_RESPONSE_LEN
        ));
    }
    if response[0] != 0 {
        return Err(format!(
            "Device_Info poll returned result 0x{:02x}",
            response[0]
        ));
    }
    let application_result =
        u32::from_le_bytes(response[8..12].try_into().expect("length checked"));
    if application_result != 0 {
        return Err(format!(
            "Device_Info returned native result 0x{application_result:08x}"
        ));
    }

    let name_slot = &response[0x14..0x14 + DEVICE_INFO_NAME_SLOT_LEN];
    let name_len = name_slot
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("scanner name is not NUL-terminated in its native field")?;
    let name = &name_slot[..name_len];
    if name.is_empty()
        || name.len() > 64
        || !name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(
            "scanner returned a name outside the native 1..=64 alphanumeric/hyphen range".into(),
        );
    }
    Ok(std::str::from_utf8(name)
        .map_err(|_| "scanner name is not valid ASCII")?
        .to_owned())
}

fn read_scanner_name_from<T: crate::protocol::BulkTransport>(
    transport: &mut T,
) -> Result<String, String> {
    let response = crate::device_info::read_ix500_0u00_response(transport)
        .map_err(|error| format!("Device_Info scanner-name read failed: {error}"))?;
    parse_scanner_name_response(&response)
}

struct MobileSettings {
    scan_name: String,
    password: Option<Vec<u8>>,
    password_display: u32,
}

impl Drop for MobileSettings {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.fill(0);
        }
    }
}

fn read_mobile_settings_from<T: crate::protocol::BulkTransport>(
    transport: &mut T,
) -> Result<MobileSettings, String> {
    let mut password_settings = read_mobile_config_from(transport)?;
    let scan_name = read_scanner_name_from(transport)?;
    Ok(MobileSettings {
        scan_name,
        password: password_settings.password.take(),
        password_display: password_settings.password_display,
    })
}

fn send_mobile_setting_from<T: crate::protocol::BulkTransport>(
    transport: &mut T,
    request: &MobileSettingRequest,
    timeout: std::time::Duration,
) -> Result<(), String> {
    const OUT_CDB: [u8; 6] = [0x1d, 0, 0, 0, 0xac, 0];
    crate::protocol::scsi_write(transport, &OUT_CDB, &request.0).map_err(|error| {
        format!(
            "scanner connection-password SET transport failed; state is unconfirmed and no retry was sent: {error}"
        )
    })?;
    let response = crate::wifi::poll_result(transport, timeout).map_err(|error| {
        format!(
            "scanner connection-password SET was sent once but was not confirmed successful; no retry was sent: {error}"
        )
    })?;
    let native_result = u32::from_le_bytes(
        response.opaque[7..11]
            .try_into()
            .expect("20-byte result poll"),
    );
    if native_result != 0 {
        return Err(format!(
            "scanner connection-password SET returned native result 0x{native_result:08x}; no retry was sent"
        ));
    }
    Ok(())
}

pub fn show() -> Result<(), String> {
    let mut scanner = crate::usb::Scanner::open()?;
    let identity = crate::scanner::read_identity_from(&mut scanner)?;
    let firmware = crate::scanner::read_firmware_record_from(&mut scanner)?;
    validate_supported_firmware(&identity.firmware, firmware.version_marker()?)?;
    let _session =
        crate::wifi::PossessionSession::acquire(&mut scanner, PASSWORD_OPERATION_TIMEOUT)?;
    let settings = read_mobile_settings_from(&mut scanner)?;
    println!("Scanner name: {}", settings.scan_name);
    match settings.password.as_deref() {
        Some(password) => {
            let password = std::str::from_utf8(password)
                .map_err(|_| "scanner returned a non-ASCII connection password")?;
            println!("Scanner connection password: {password}");
        }
        None => println!("Scanner did not return a connection password value."),
    }
    Ok(())
}

pub fn set_interactive() -> Result<(), String> {
    let mut scanner = crate::usb::Scanner::open()?;
    let identity = crate::scanner::read_identity_from(&mut scanner)?;
    let firmware = crate::scanner::read_firmware_record_from(&mut scanner)?;
    validate_supported_firmware(&identity.firmware, firmware.version_marker()?)?;
    let _session =
        crate::wifi::PossessionSession::acquire(&mut scanner, PASSWORD_OPERATION_TIMEOUT)?;
    let current = read_mobile_settings_from(&mut scanner)?;
    let mut password = crate::read_scanner_connection_password_hidden()?;
    let request = build_mobile_setting_request(
        current.scan_name.as_bytes(),
        &password.0,
        current.password_display,
    )?;
    send_mobile_setting_from(&mut scanner, &request, PASSWORD_OPERATION_TIMEOUT)?;

    let readback = read_mobile_settings_from(&mut scanner).map_err(|error| {
        format!(
            "scanner acknowledged the connection-password SET, but USB readback failed; state is not independently confirmed: {error}"
        )
    })?;
    let matches = readback
        .password
        .as_deref()
        .is_some_and(|actual| constant_time_eq(actual, &password.0));
    if !matches {
        return Err(
            "scanner acknowledged the connection-password SET, but USB readback did not match; no retry was sent".into(),
        );
    }
    if readback.scan_name != current.scan_name
        || readback.password_display != current.password_display
    {
        return Err(
            "scanner connection-password readback succeeded, but an unrelated mobile setting changed; no retry was sent".into(),
        );
    }
    password.0.fill(0);
    println!("Scanner connection password set and independently confirmed over USB.");
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

struct MobileSettingRequest([u8; 0xac]);

impl Drop for MobileSettingRequest {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn build_mobile_setting_request(
    scan_name: &[u8],
    password: &[u8],
    password_display: u32,
) -> Result<MobileSettingRequest, String> {
    if scan_name.is_empty()
        || scan_name.len() > 64
        || !scan_name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err("scanner name must be 1..=64 ASCII letters, digits, or hyphens".into());
    }
    if password_display > 1 {
        return Err("scanner password display flag must be 0 or 1".into());
    }
    let mut encoded = encode_connection_password(password)?;

    let mut request = MobileSettingRequest([0u8; 0xac]);
    request.0[..16].copy_from_slice(b"SETUP NET CMD   ");
    request.0[16..18].copy_from_slice(&0x9800u16.to_le_bytes());
    request.0[20..24].copy_from_slice(&0x1002u32.to_le_bytes());
    request.0[32..36].copy_from_slice(&0x88u32.to_le_bytes());
    request.0[36..36 + scan_name.len()].copy_from_slice(scan_name);
    request.0[36 + 0x4c..36 + 0x50].copy_from_slice(&1u32.to_le_bytes());
    request.0[36 + 0x50..36 + 0x50 + encoded.len()].copy_from_slice(&encoded);
    request.0[36 + 0x84..36 + 0x88].copy_from_slice(&password_display.to_le_bytes());
    encoded.fill(0);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn firmware_preflight_requires_matching_ix500_markers() {
        assert!(validate_supported_firmware("0U00", "0U00").is_ok());
        assert!(validate_supported_firmware("0U00", "0U01").is_err());
        assert!(validate_supported_firmware("0U01", "0U01").is_err());
    }

    struct FakeUsb {
        writes: Vec<Vec<u8>>,
        reads: VecDeque<Vec<u8>>,
    }

    impl crate::protocol::BulkTransport for FakeUsb {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }

        fn read_bulk(&mut self, data: &mut [u8]) -> Result<usize, String> {
            let chunk = self.reads.pop_front().ok_or("no simulated response")?;
            if chunk.len() > data.len() {
                return Err("simulated response too large".into());
            }
            data[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    fn usb_status() -> Vec<u8> {
        let mut status = [0u8; 13];
        status[0] = 0x53;
        status.to_vec()
    }

    #[test]
    fn read_mobile_config_uses_only_native_get_commands() {
        let config_bytes = b"PwdMode=1\nPwdCode=173125178\nPwdDisp=0\n";
        let mut size_response = [0u8; 24];
        size_response[20..24].copy_from_slice(&(config_bytes.len() as u32).to_le_bytes());
        let mut config_response = vec![0u8; 0x1004];
        config_response[0x14..0x14 + config_bytes.len()].copy_from_slice(config_bytes);
        let mut fake = FakeUsb {
            writes: Vec::new(),
            reads: vec![
                usb_status(),
                size_response.to_vec(),
                usb_status(),
                usb_status(),
                config_response,
                usb_status(),
            ]
            .into(),
        };

        let settings = read_mobile_config_from(&mut fake).unwrap();
        assert_eq!(settings.password.as_deref(), Some(&b"A!0"[..]));
        assert_eq!(settings.password_display, 0);
        assert_eq!(fake.writes.len(), 6);
        assert_eq!(&fake.writes[0][19..25], &[0x1d, 0, 0, 0, 0x24, 0]);
        assert_eq!(&fake.writes[2][19..25], &[0x1c, 0, 0, 0, 0x18, 0]);
        assert_eq!(&fake.writes[3][19..25], &[0x1d, 0, 0, 0, 0x24, 0]);
        assert_eq!(&fake.writes[5][19..25], &[0x1c, 0, 0, 0x10, 0x04, 0]);
        assert_eq!(fake.writes[1].len(), 36);
        assert_eq!(fake.writes[4].len(), 36);
        assert!(fake.writes.iter().all(|write| write.len() != 0xac));
    }

    #[test]
    fn connection_password_encoder_matches_native_reference_triplets() {
        assert_eq!(encode_connection_password(b"A!0").unwrap(), b"173125178");
    }

    #[test]
    fn connection_password_decoder_matches_native_reference_triplets() {
        assert_eq!(decode_connection_password(b"173125178").unwrap(), b"A!0");
    }

    #[test]
    fn connection_password_decoder_rejects_invalid_triplets() {
        assert!(decode_connection_password(b"17x").is_err());
        assert!(decode_connection_password(b"000").is_err());
    }

    #[test]
    fn configfile_size_request_matches_native_header() {
        let request = build_configfile_size_request();
        let mut expected = [0u8; 36];
        expected[..16].copy_from_slice(b"SETUP NET CMD   ");
        expected[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        expected[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(request, expected);
    }

    #[test]
    fn configfile_read_request_carries_size_and_native_subcommand() {
        let request = build_configfile_request(0x300).unwrap();
        let mut expected = [0u8; 36];
        expected[..16].copy_from_slice(b"SETUP NET CMD   ");
        expected[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        expected[20..24].copy_from_slice(&2u32.to_le_bytes());
        expected[32..36].copy_from_slice(&0x300u32.to_le_bytes());
        assert_eq!(request, expected);
        assert!(build_configfile_request(0).is_err());
        assert!(build_configfile_request(0xff1).is_err());
    }

    #[test]
    fn configfile_size_response_checks_status_result_and_bounds() {
        let mut response = [0u8; 24];
        response[20..24].copy_from_slice(&0x300u32.to_le_bytes());
        assert_eq!(
            parse_configfile_size_response(&response).unwrap(),
            Some(0x300)
        );
        response[0] = 1;
        assert_eq!(parse_configfile_size_response(&response).unwrap(), None);
        response[0] = 0;
        response[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_configfile_size_response(&response).is_err());
        response[8..12].copy_from_slice(&0u32.to_le_bytes());
        response[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_configfile_size_response(&response).is_err());
        response[20..24].copy_from_slice(&0xff1u32.to_le_bytes());
        assert!(parse_configfile_size_response(&response).is_err());
    }

    #[test]
    fn mobile_config_decodes_connection_password_and_preserves_display_flag() {
        let config = parse_mobile_config(
            b"PwdMode=1\nPwdCode=173125178\nPwdDisp=1\nReadyNotificationPort=49321\n",
        )
        .unwrap();
        assert_eq!(config.password.as_deref(), Some(&b"A!0"[..]));
        assert_eq!(config.password_display, 1);
    }

    #[test]
    fn mobile_config_reports_no_password_when_code_is_absent_or_disabled() {
        let unset = parse_mobile_config(b"PwdMode=0\nPwdDisp=0\n").unwrap();
        assert!(unset.password.is_none());
        assert!(parse_mobile_config(b"PwdMode=1\nPwdDisp=0\n").is_err());
        let disabled = parse_mobile_config(b"PwdMode=0\nPwdCode=173125178\nPwdDisp=0\n").unwrap();
        assert!(disabled.password.is_none());
    }

    #[test]
    fn mobile_config_rejects_duplicate_and_malformed_sensitive_fields() {
        let duplicate = b"PwdMode=1\nPwdCode=173125178\nPwdCode=173125178\nPwdDisp=0\n";
        let error = parse_mobile_config(duplicate).err().unwrap();
        assert!(!error.contains("173125178"));
        assert!(parse_mobile_config(b"PwdMode=2\nPwdDisp=0\n").is_err());
        assert!(parse_mobile_config(b"PwdMode=1\nPwdCode=17x\nPwdDisp=0\n").is_err());
        assert!(parse_mobile_config(b"PwdMode=1\nPwdCode=173125178\nPwdDisp=2\n").is_err());
    }

    #[test]
    fn configfile_response_extracts_data_at_native_offset_and_exact_size() {
        let mut response = vec![0u8; 0x1004];
        response[20..20 + 4].copy_from_slice(b"abc\n");
        assert_eq!(
            parse_configfile_response(&response, 4).unwrap(),
            Some(&b"abc\n"[..])
        );
        response[0] = 1;
        assert_eq!(parse_configfile_response(&response, 4).unwrap(), None);
    }

    #[test]
    fn configfile_response_rejects_native_errors_and_short_data() {
        let mut response = vec![0u8; 0x1004];
        response[8..12].copy_from_slice(&0x10u32.to_le_bytes());
        assert!(parse_configfile_response(&response, 4).is_err());
        response[8..12].fill(0);
        assert!(parse_configfile_response(&response[..24], 4).is_err());
        assert!(parse_configfile_response(&response, 0).is_err());
        assert!(parse_configfile_response(&response, 0xff1).is_err());
    }

    #[test]
    fn scanner_name_uses_the_native_device_info_request() {
        let request = crate::device_info::build_ix500_0u00_request();
        let mut expected = [0u8; 36];
        expected[..16].copy_from_slice(b"SETUP NET CMD   ");
        expected[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        expected[20..24].copy_from_slice(&4u32.to_le_bytes());
        expected[32..36].copy_from_slice(&0x248u32.to_le_bytes());
        assert_eq!(request, expected);
    }

    #[test]
    fn scanner_info_response_extracts_the_native_scan_name_field() {
        let mut response = vec![0u8; crate::device_info::DEVICE_INFO_RESPONSE_LEN];
        response[0x14..0x14 + b"Saved-Scanner1".len()].copy_from_slice(b"Saved-Scanner1");
        assert_eq!(
            parse_scanner_name_response(&response).unwrap(),
            "Saved-Scanner1"
        );
    }

    #[test]
    fn scanner_info_response_rejects_bad_results_and_names() {
        let mut response = vec![0u8; crate::device_info::DEVICE_INFO_RESPONSE_LEN];
        response[0x14..0x14 + 13].copy_from_slice(b"Saved Scanner");
        assert!(parse_scanner_name_response(&response).is_err());
        response.fill(0);
        response[0] = 0x11;
        assert!(parse_scanner_name_response(&response).is_err());
        response.fill(0);
        response[8..12].copy_from_slice(&0x83u32.to_le_bytes());
        assert!(parse_scanner_name_response(&response).is_err());
        assert!(parse_scanner_name_response(&response[..0x25b]).is_err());
    }

    #[test]
    fn mobile_set_does_not_retry_for_known_or_unknown_native_results() {
        let request = build_mobile_setting_request(b"Saved-Scanner1", b"A!0", 0).unwrap();
        for code in [0x11, 0x83, 0xfe] {
            let mut result = [0u8; 20];
            result[0] = code;
            let mut fake = FakeUsb {
                writes: Vec::new(),
                reads: vec![usb_status(), result.to_vec(), usb_status()].into(),
            };
            let error =
                send_mobile_setting_from(&mut fake, &request, std::time::Duration::from_secs(1))
                    .unwrap_err();
            assert!(error.contains(&format!("0x{code:02x}")));
            assert_eq!(
                &fake.writes[0][19..25],
                &[0x1d, 0, 0, 0, 0xac, 0],
                "native SEND DIAGNOSTIC length must cover the entire 0xac-byte request"
            );
            assert_eq!(
                fake.writes
                    .iter()
                    .filter(|write| write.len() == 0xac)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn mobile_set_rejects_nonzero_native_application_result_without_retry() {
        let request = build_mobile_setting_request(b"Saved-Scanner1", b"A!0", 0).unwrap();
        for code in [0x11u32, 0x83, 0xfe] {
            let mut result = [0u8; 20];
            result[8..12].copy_from_slice(&code.to_le_bytes());
            let mut fake = FakeUsb {
                writes: Vec::new(),
                reads: vec![usb_status(), result.to_vec(), usb_status()].into(),
            };
            let error =
                send_mobile_setting_from(&mut fake, &request, std::time::Duration::from_secs(1))
                    .unwrap_err();
            assert!(error.contains(&format!("0x{code:08x}")));
            assert_eq!(
                fake.writes
                    .iter()
                    .filter(|write| write.len() == 0xac)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn mobile_setting_request_matches_native_reference_offsets_and_lengths() {
        let request = build_mobile_setting_request(b"ScanSnap-iX500", b"A!0", 1).unwrap();
        let mut expected = [0u8; 0xac];
        expected[..16].copy_from_slice(b"SETUP NET CMD   ");
        expected[16..18].copy_from_slice(&0x9800u16.to_le_bytes());
        expected[20..24].copy_from_slice(&0x1002u32.to_le_bytes());
        expected[32..36].copy_from_slice(&0x88u32.to_le_bytes());
        expected[36..36 + b"ScanSnap-iX500".len()].copy_from_slice(b"ScanSnap-iX500");
        expected[36 + 0x4c..36 + 0x50].copy_from_slice(&1u32.to_le_bytes());
        expected[36 + 0x50..36 + 0x50 + 9].copy_from_slice(b"173125178");
        expected[36 + 0x84..36 + 0x88].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(request.0.as_slice(), expected);
    }

    #[test]
    fn mobile_setting_rejects_scanner_names_disallowed_by_native_validation() {
        assert!(build_mobile_setting_request(b"ScanSnap iX500", b"A!0", 0).is_err());
    }
}
