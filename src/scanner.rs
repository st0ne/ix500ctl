use crate::{protocol, usb::Scanner};

pub const FIRMWARE_QUERY_PAYLOAD: [u8; 16] = *b"GET FIRMVERSION ";
pub const FIRMWARE_QUERY_RESPONSE_LEN: usize = 80;
pub const FIRMWARE_QUERY_TIMEOUT_MS: u32 = 2000;

/// The Windows API copies these 80 bytes to its caller but only compares the
/// first four bytes with "0U00". Keep the remaining bytes opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareRecord(pub [u8; FIRMWARE_QUERY_RESPONSE_LEN]);

impl FirmwareRecord {
    pub fn version_marker(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.0[..4]).map_err(|_| "firmware marker is not ASCII".to_string())
    }
}

pub fn read_firmware_record_from<T: protocol::BulkTransport>(
    transport: &mut T,
) -> Result<FirmwareRecord, String> {
    protocol::scsi_write(
        transport,
        &[0x1d, 0, 0, 0, 0x10, 0],
        &FIRMWARE_QUERY_PAYLOAD,
    )?;
    let response = protocol::scsi_read_sti(
        transport,
        &[0x1c, 0, 0, 0, 0x50, 0],
        FIRMWARE_QUERY_RESPONSE_LEN,
    )?;
    let bytes: [u8; FIRMWARE_QUERY_RESPONSE_LEN] = response
        .try_into()
        .map_err(|_| "GET FIRMVERSION returned an unexpected response length".to_string())?;
    Ok(FirmwareRecord(bytes))
}

pub fn firmware_info() -> Result<(), String> {
    let mut scanner = Scanner::open_with_timeout(FIRMWARE_QUERY_TIMEOUT_MS)?;
    let record = read_firmware_record_from(&mut scanner)?;
    println!("Firmware marker (bytes 0..4): {}", record.version_marker()?);
    println!(
        "Marker bytes: {:02x?}; response length: {} bytes",
        &record.0[..4],
        record.0.len()
    );
    println!("Remaining response bytes are not interpreted or displayed.");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerIdentity {
    pub vendor: String,
    pub model: String,
    pub firmware: String,
}

pub fn read_identity() -> Result<ScannerIdentity, String> {
    let mut scanner = Scanner::open()?;
    read_identity_from(&mut scanner)
}

pub fn read_identity_from<T: protocol::BulkTransport>(
    scanner: &mut T,
) -> Result<ScannerIdentity, String> {
    let data = protocol::inquiry(scanner)?;
    parse_inquiry(&data)
}

pub fn parse_inquiry(data: &[u8]) -> Result<ScannerIdentity, String> {
    if data.len() < 36 {
        return Err(format!(
            "SCSI INQUIRY response is too short: {} bytes",
            data.len()
        ));
    }
    let vendor = String::from_utf8_lossy(&data[8..16]).trim().to_string();
    let product = String::from_utf8_lossy(&data[16..32]).trim().to_string();
    let firmware = String::from_utf8_lossy(&data[32..36]).trim().to_string();
    if vendor != "FUJITSU" || product != "ScanSnap iX500" {
        return Err(format!(
            "unexpected SCSI inquiry: {vendor} {product} {firmware}"
        ));
    }
    Ok(ScannerIdentity {
        vendor,
        model: product,
        firmware,
    })
}

pub fn info() -> Result<(), String> {
    let identity = read_identity()?;
    println!(
        "Model: {}\nVendor: {}\nFirmware: {}",
        identity.model, identity.vendor, identity.firmware
    );
    Ok(())
}

pub fn device_info() -> Result<(), String> {
    let mut scanner = Scanner::open()?;
    let identity = read_identity_from(&mut scanner)?;
    println!(
        "Model: {}\nVendor: {}\nFirmware: {}",
        identity.model, identity.vendor, identity.firmware
    );
    let firmware = read_firmware_record_from(&mut scanner)?;
    let firmware_marker = firmware.version_marker()?;
    if firmware_marker != identity.firmware {
        return Err(format!("SCSI INQUIRY firmware {} does not match GET FIRMVERSION {firmware_marker}; refusing profile parse", identity.firmware));
    }
    let mac = crate::device_info::read_scanner_mac(&mut scanner, firmware_marker)?;
    println!("Wi-Fi MAC: {mac}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ix500_fixture() -> [u8; 96] {
        let mut response = [0u8; 96];
        response[8..16].copy_from_slice(b"FUJITSU ");
        response[16..32].copy_from_slice(b"ScanSnap iX500  ");
        response[32..36].copy_from_slice(b"0U00");
        response
    }

    #[test]
    fn inquiry_fixture_identifies_the_expected_ix500_firmware() {
        let identity = parse_inquiry(&ix500_fixture()).unwrap();
        assert_eq!(identity.vendor, "FUJITSU");
        assert_eq!(identity.model, "ScanSnap iX500");
        assert_eq!(identity.firmware, "0U00");
    }

    #[test]
    fn inquiry_fixture_rejects_short_and_wrong_model_responses() {
        assert!(parse_inquiry(&[0; 35]).is_err());
        let mut wrong = ix500_fixture();
        wrong[16..32].copy_from_slice(b"ScanSnap iX100  ");
        assert!(parse_inquiry(&wrong).is_err());
    }

    #[derive(Default)]
    struct FirmwareFake {
        writes: Vec<Vec<u8>>,
        reads: std::collections::VecDeque<Vec<u8>>,
    }
    impl protocol::BulkTransport for FirmwareFake {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }
        fn read_bulk(&mut self, out: &mut [u8]) -> Result<usize, String> {
            let data = self.reads.pop_front().ok_or("no fake response")?;
            if data.len() > out.len() {
                return Err("fake response exceeds requested size".into());
            }
            out[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }
    }

    fn status_frame(code: u8) -> [u8; 13] {
        let mut frame = [0; 13];
        frame[0] = 0x53;
        frame[9] = code;
        frame
    }

    #[test]
    fn firmware_query_uses_exact_payload_cdbs_lengths_and_preserves_opaque_record() {
        let mut record = [0x5a; FIRMWARE_QUERY_RESPONSE_LEN];
        record[..4].copy_from_slice(b"0U00");
        let mut fake = FirmwareFake {
            writes: vec![],
            reads: vec![
                status_frame(0).to_vec(),
                record.to_vec(),
                status_frame(0).to_vec(),
            ]
            .into(),
        };
        let result = read_firmware_record_from(&mut fake).unwrap();
        assert_eq!(result.version_marker().unwrap(), "0U00");
        assert_eq!(result.0, record);
        assert_eq!(
            fake.writes,
            vec![
                {
                    let mut frame = [0; 31];
                    frame[0] = 0x43;
                    frame[19..25].copy_from_slice(&[0x1d, 0, 0, 0, 0x10, 0]);
                    frame.to_vec()
                },
                FIRMWARE_QUERY_PAYLOAD.to_vec(),
                {
                    let mut frame = [0; 31];
                    frame[0] = 0x43;
                    frame[19..25].copy_from_slice(&[0x1c, 0, 0, 0, 0x50, 0]);
                    frame.to_vec()
                }
            ]
        );
    }

    #[test]
    fn firmware_query_rejects_transport_check_condition_and_short_application_data() {
        let mut check = FirmwareFake {
            writes: vec![],
            reads: vec![
                status_frame(2).to_vec(),
                vec![0; 18],
                status_frame(0).to_vec(),
            ]
            .into(),
        };
        let error = read_firmware_record_from(&mut check).unwrap_err();
        assert!(error.contains("CHECK CONDITION"));
        assert_eq!(
            check.writes.len(),
            3,
            "REQUEST SENSE follows CHECK CONDITION"
        );

        let mut short = FirmwareFake {
            writes: vec![],
            reads: vec![
                status_frame(0).to_vec(),
                vec![0; 79],
                status_frame(0).to_vec(),
            ]
            .into(),
        };
        assert!(read_firmware_record_from(&mut short)
            .unwrap_err()
            .contains("short application data"));
    }
}
