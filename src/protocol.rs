use crate::usb::Scanner;

/// SANE's documented-by-capture Fujitsu USB wrapper: 31-byte command frame,
/// optional data phase, then a 13-byte status. The same framing carries the
/// reconstructed START, Wi-Fi SET, and Result-Poll commands.
pub trait BulkTransport {
    fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String>;
    fn read_bulk(&mut self, data: &mut [u8]) -> Result<usize, String>;
}

/// Opt-in, secret-safe trace for the reconstructed diagnostic transactions.
/// SET data bytes are never included; callers must explicitly permit the
/// constant START bytes when invoking `scsi_write_traced`.
#[derive(Debug, Default)]
pub struct ProtocolTrace {
    enabled: bool,
    sequence: usize,
    pub lines: Vec<String>,
}

impl ProtocolTrace {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            sequence: 0,
            lines: Vec::new(),
        }
    }
    fn record(&mut self, phase: &str, detail: impl AsRef<str>) {
        if self.enabled {
            self.sequence += 1;
            self.lines.push(format!(
                "protocol[{}] {phase}: {}",
                self.sequence,
                detail.as_ref()
            ));
        }
    }
    pub fn note(&mut self, phase: &str, detail: impl AsRef<str>) {
        self.record(phase, detail);
    }
    pub fn print(&self) {
        for line in &self.lines {
            eprintln!("{line}");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiStatusCode {
    Good,
    CheckCondition,
    Busy,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbStatusResponse {
    pub bytes: [u8; 13],
    pub code: ScsiStatusCode,
}

impl UsbStatusResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let bytes: [u8; 13] = bytes
            .try_into()
            .map_err(|_| "USB status must be exactly 13 bytes".to_string())?;
        if bytes[0] != 0x53 {
            return Err(format!("unexpected SCSI status marker 0x{:02x}", bytes[0]));
        }
        if bytes[1..9].iter().any(|b| *b != 0) || bytes[10..].iter().any(|b| *b != 0) {
            return Err("SCSI status reserved bytes were nonzero".into());
        }
        let code = match bytes[9] {
            0 => ScsiStatusCode::Good,
            2 => ScsiStatusCode::CheckCondition,
            8 => ScsiStatusCode::Busy,
            code => ScsiStatusCode::Other(code),
        };
        Ok(Self { bytes, code })
    }

    fn ensure_good(&self) -> Result<(), String> {
        match self.code {
            ScsiStatusCode::Good => Ok(()),
            ScsiStatusCode::CheckCondition => {
                Err("scanner reported SCSI CHECK CONDITION (request-sense required)".into())
            }
            ScsiStatusCode::Busy => Err("scanner reported SCSI BUSY".into()),
            ScsiStatusCode::Other(code) => {
                Err(format!("scanner reported SCSI status 0x{code:02x}"))
            }
        }
    }
}

impl BulkTransport for Scanner {
    fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
        Scanner::bulk_out(self, data)
    }
    fn read_bulk(&mut self, data: &mut [u8]) -> Result<usize, String> {
        Scanner::bulk_in(self, data)
    }
}

pub fn inquiry<T: BulkTransport>(scanner: &mut T) -> Result<[u8; 96], String> {
    let ready = [0x43u8; 1]
        .into_iter()
        .chain(std::iter::repeat_n(0, 30))
        .collect::<Vec<_>>();
    scanner.write_bulk(&ready)?;
    let mut ready_status = [0u8; 13];
    read_exact_bulk(scanner, &mut ready_status)?;
    UsbStatusResponse::parse(&ready_status)?.ensure_good()?;

    let data = scsi_read(scanner, &[0x12, 0, 0, 0, 96, 0], 96)?;
    data.try_into()
        .map_err(|_| "INQUIRY returned an unexpected length".to_string())
}

/// Execute a SCSI command using the iX500 31-byte 0x43 framing verified in
/// both the Fujitsu STI minidriver and SANE transport.
pub fn scsi_read<T: BulkTransport>(
    scanner: &mut T,
    cdb: &[u8],
    length: usize,
) -> Result<Vec<u8>, String> {
    if cdb.is_empty() || cdb.len() > 12 {
        return Err("CDB must contain 1..=12 bytes".into());
    }
    let mut frame = [0u8; 31];
    frame[0] = 0x43;
    frame[19..19 + cdb.len()].copy_from_slice(cdb);
    write_exact_bulk(scanner, &frame)?;
    let mut data = vec![0u8; length];
    if length != 0 {
        read_exact_bulk(scanner, &mut data)?;
    }
    read_status(scanner)?;
    Ok(data)
}

/// Read one data phase with the STI driver's short-read status fallback.
/// The normal result-poll path is 20 bytes of application data followed by a
/// separate 13-byte transport status. The driver also recognizes a 13-byte
/// status returned in place of the requested data, so keep USB transfers
/// separate instead of filling a short read from the next protocol phase.
#[allow(dead_code)] // Non-tracing facade retained for direct callers/tests.
pub fn scsi_read_sti<T: BulkTransport>(
    scanner: &mut T,
    cdb: &[u8],
    length: usize,
) -> Result<Vec<u8>, String> {
    let mut trace = ProtocolTrace::default();
    scsi_read_sti_traced(scanner, cdb, length, "read", &mut trace)
}

pub fn scsi_read_sti_traced<T: BulkTransport>(
    scanner: &mut T,
    cdb: &[u8],
    length: usize,
    phase: &str,
    trace: &mut ProtocolTrace,
) -> Result<Vec<u8>, String> {
    if cdb.is_empty() || cdb.len() > 12 {
        return Err("CDB must contain 1..=12 bytes".into());
    }
    if length == 0 {
        return Err("STI data phase must not be empty".into());
    }
    let mut frame = [0u8; 31];
    frame[0] = 0x43;
    frame[19..19 + cdb.len()].copy_from_slice(cdb);
    trace.record(phase, format!("OUT command frame len=31 CDB={:02x?}", cdb));
    write_exact_bulk(scanner, &frame)?;

    let mut data = vec![0u8; length];
    let count = scanner.read_bulk(&mut data)?;
    trace.record(
        phase,
        format!("IN application data requested={length} actual={count}"),
    );
    if count > length {
        return Err(format!(
            "USB returned impossible data length {count}/{length}"
        ));
    }
    if count == 13 {
        if let Ok(status) = UsbStatusResponse::parse(&data[..13]) {
            trace.record(
                phase,
                format!("IN 13-byte transport status={:02x?}", status.bytes),
            );
            ensure_good_with_sense(scanner, status, trace, phase)?;
            return Err(
                "scanner returned only a transport status; application data is absent".into(),
            );
        }
    }
    if count != length {
        // Match the minidriver: non-status short data is followed by a
        // distinct transport-status read. Drain/check it before reporting.
        read_status_with_sense(scanner, trace, phase)?;
        return Err(format!(
            "short application data transfer: {count}/{length} bytes"
        ));
    }
    read_status_with_sense(scanner, trace, phase)?;
    trace.record(phase, format!("application response={:02x?}", data));
    Ok(data)
}

/// Execute the minidriver's confirmed command + separate OUT-data + status path.
/// Callers must supply a fully reconstructed command and payload.
pub fn scsi_write<T: BulkTransport>(
    scanner: &mut T,
    cdb: &[u8],
    payload: &[u8],
) -> Result<(), String> {
    let mut trace = ProtocolTrace::default();
    scsi_write_traced(scanner, cdb, payload, "write", false, &mut trace)
}

pub fn scsi_write_traced<T: BulkTransport>(
    scanner: &mut T,
    cdb: &[u8],
    payload: &[u8],
    phase: &str,
    show_payload: bool,
    trace: &mut ProtocolTrace,
) -> Result<(), String> {
    if cdb.is_empty() || cdb.len() > 12 {
        return Err("CDB must contain 1..=12 bytes".into());
    }
    if payload.is_empty() {
        return Err("OUT data phase must not be empty".into());
    }
    let mut frame = [0u8; 31];
    frame[0] = 0x43;
    frame[19..19 + cdb.len()].copy_from_slice(cdb);
    trace.record(phase, format!("OUT command frame len=31 CDB={:02x?}", cdb));
    write_exact_bulk(scanner, &frame)?;
    trace.record(
        phase,
        if show_payload {
            format!("OUT data len={} bytes={:02x?}", payload.len(), payload)
        } else {
            format!("OUT data len={} bytes=<redacted>", payload.len())
        },
    );
    write_exact_bulk(scanner, payload)?;
    read_status_with_sense(scanner, trace, phase)
}

fn write_exact_bulk<T: BulkTransport>(scanner: &mut T, data: &[u8]) -> Result<(), String> {
    let written = scanner.write_bulk(data)?;
    if written != data.len() {
        return Err(format!("short USB write: {written}/{} bytes", data.len()));
    }
    Ok(())
}

fn read_status<T: BulkTransport>(scanner: &mut T) -> Result<(), String> {
    let mut status = [0u8; 13];
    read_exact_bulk(scanner, &mut status)?;
    UsbStatusResponse::parse(&status)?.ensure_good()
}

fn read_status_with_sense<T: BulkTransport>(
    scanner: &mut T,
    trace: &mut ProtocolTrace,
    phase: &str,
) -> Result<(), String> {
    let mut bytes = [0u8; 13];
    let count = scanner.read_bulk(&mut bytes)?;
    if count != bytes.len() {
        return Err(format!("short USB status transfer: {count}/13 bytes"));
    }
    let status = UsbStatusResponse::parse(&bytes)?;
    trace.record(
        phase,
        format!(
            "IN transport status len=13 bytes={:02x?} parsed={:?}",
            status.bytes, status.code
        ),
    );
    ensure_good_with_sense(scanner, status, trace, phase)
}

fn ensure_good_with_sense<T: BulkTransport>(
    scanner: &mut T,
    status: UsbStatusResponse,
    trace: &mut ProtocolTrace,
    phase: &str,
) -> Result<(), String> {
    match status.code {
        ScsiStatusCode::Good => Ok(()),
        ScsiStatusCode::CheckCondition => {
            let cdb = [0x03, 0, 0, 0, 0x12, 0];
            let mut frame = [0u8; 31];
            frame[0] = 0x43;
            frame[19..25].copy_from_slice(&cdb);
            trace.record(
                phase,
                format!("OUT REQUEST SENSE frame len=31 CDB={:02x?}", cdb),
            );
            write_exact_bulk(scanner, &frame)?;
            let mut sense = [0u8; 18];
            let count = scanner.read_bulk(&mut sense)?;
            if count != sense.len() {
                return Err(format!("short REQUEST SENSE data: {count}/18 bytes"));
            }
            trace.record(
                phase,
                format!("IN REQUEST SENSE data len=18 bytes={:02x?}", sense),
            );
            let mut sense_status = [0u8; 13];
            let count = scanner.read_bulk(&mut sense_status)?;
            if count != sense_status.len() {
                return Err(format!("short REQUEST SENSE status: {count}/13 bytes"));
            }
            let sense_status = UsbStatusResponse::parse(&sense_status)?;
            trace.record(
                phase,
                format!(
                    "IN REQUEST SENSE transport status len=13 bytes={:02x?} parsed={:?}",
                    sense_status.bytes, sense_status.code
                ),
            );
            if sense_status.code != ScsiStatusCode::Good {
                return Err(format!(
                    "REQUEST SENSE ended with transport status {:?}; sense={:02x?}",
                    sense_status.code, sense
                ));
            }
            Err(format!(
                "scanner reported SCSI CHECK CONDITION; sense={:02x?}",
                sense
            ))
        }
        ScsiStatusCode::Busy => Err("scanner reported SCSI BUSY".into()),
        ScsiStatusCode::Other(code) => Err(format!("scanner reported SCSI status 0x{code:02x}")),
    }
}

fn read_exact_bulk<T: BulkTransport>(
    scanner: &mut T,
    mut remaining: &mut [u8],
) -> Result<(), String> {
    while !remaining.is_empty() {
        let n = scanner.read_bulk(remaining)?;
        if n == 0 {
            return Err("USB endpoint returned an empty transfer".into());
        }
        remaining = &mut remaining[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct FakeUsb {
        writes: Vec<Vec<u8>>,
        reads: VecDeque<Vec<u8>>,
    }
    impl BulkTransport for FakeUsb {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }
        fn read_bulk(&mut self, data: &mut [u8]) -> Result<usize, String> {
            let chunk = self.reads.pop_front().ok_or("no simulated USB response")?;
            if chunk.len() > data.len() {
                return Err("simulated response too large".into());
            }
            data[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    #[test]
    fn inquiry_uses_only_captured_read_command_and_checks_markers() {
        let mut response = [0u8; 96];
        response[8..16].copy_from_slice(b"FUJITSU ");
        response[16..32].copy_from_slice(b"ScanSnap iX500  ");
        response[32..36].copy_from_slice(b"0U00");
        let mut initial_status = [0u8; 13];
        initial_status[0] = 0x53;
        let mut final_status = [0u8; 13];
        final_status[0] = 0x53;
        let mut fake = FakeUsb {
            writes: vec![],
            reads: vec![
                initial_status.to_vec(),
                response.to_vec(),
                final_status.to_vec(),
            ]
            .into(),
        };
        let got = inquiry(&mut fake).unwrap();
        assert_eq!(&got[8..16], b"FUJITSU ");
        assert_eq!(fake.writes.len(), 2);
        assert_eq!(fake.writes[0][0], 0x43);
        assert!(fake.writes[0][1..].iter().all(|b| *b == 0));
        assert_eq!(&fake.writes[1][19..25], &[0x12, 0, 0, 0, 96, 0]);
    }

    #[test]
    fn inquiry_stops_on_invalid_initial_status_without_sending_cdb() {
        let mut bad_status = [0u8; 13];
        bad_status[0] = 0;
        let mut fake = FakeUsb {
            writes: vec![],
            reads: vec![bad_status.to_vec()].into(),
        };
        let error = inquiry(&mut fake).unwrap_err();
        assert!(error.contains("unexpected SCSI status marker"));
        assert_eq!(fake.writes.len(), 1);
    }

    #[test]
    fn inquiry_rejects_bad_final_status_after_read_data() {
        let response = [0u8; 96];
        let mut ready = [0u8; 13];
        ready[0] = 0x53;
        let mut bad_final = [0u8; 13];
        bad_final[0] = 0;
        let mut fake = FakeUsb {
            writes: vec![],
            reads: vec![ready.to_vec(), response.to_vec(), bad_final.to_vec()].into(),
        };
        let error = inquiry(&mut fake).unwrap_err();
        assert!(error.contains("unexpected SCSI status marker"));
        assert_eq!(fake.writes.len(), 2);
    }

    #[test]
    fn write_sends_exact_command_then_separate_data_then_status() {
        let mut status = [0u8; 13];
        status[0] = 0x53;
        let mut fake = FakeUsb {
            writes: vec![],
            reads: vec![status.to_vec()].into(),
        };
        let payload: Vec<u8> = (0..=255).cycle().take(284).collect();
        scsi_write(&mut fake, &[0x1d, 0, 0, 1, 0x1c, 0], &payload).unwrap();
        assert_eq!(fake.writes.len(), 2);
        assert_eq!(fake.writes[0].len(), 31);
        assert_eq!(fake.writes[0][0], 0x43);
        assert!(fake.writes[0][1..19].iter().all(|b| *b == 0));
        assert_eq!(&fake.writes[0][19..25], &[0x1d, 0, 0, 1, 0x1c, 0]);
        assert!(fake.writes[0][25..].iter().all(|b| *b == 0));
        assert_eq!(fake.writes[1], payload);
    }

    #[test]
    fn write_does_not_send_data_after_short_frame_write() {
        struct ShortFrame;
        impl BulkTransport for ShortFrame {
            fn write_bulk(&mut self, _: &[u8]) -> Result<usize, String> {
                Ok(30)
            }
            fn read_bulk(&mut self, _: &mut [u8]) -> Result<usize, String> {
                unreachable!()
            }
        }
        let error = scsi_write(&mut ShortFrame, &[0x1d, 0, 0, 0, 1, 0], b"x").unwrap_err();
        assert!(error.contains("short USB write"));
    }

    #[test]
    fn status_parser_checks_shape_and_maps_driver_status_codes() {
        let mut status = [0u8; 13];
        status[0] = 0x53;
        assert_eq!(
            UsbStatusResponse::parse(&status).unwrap().code,
            ScsiStatusCode::Good
        );
        status[9] = 8;
        assert_eq!(
            UsbStatusResponse::parse(&status).unwrap().code,
            ScsiStatusCode::Busy
        );
        assert!(UsbStatusResponse::parse(&status)
            .unwrap()
            .ensure_good()
            .unwrap_err()
            .contains("BUSY"));
        status[1] = 1;
        assert!(UsbStatusResponse::parse(&status)
            .unwrap_err()
            .contains("reserved bytes"));
    }
}
