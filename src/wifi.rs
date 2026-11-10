use crate::protocol::{self, BulkTransport};
use crate::usb::Scanner;
use std::time::{Duration, Instant};

/// The original Usb_Wifi_Status path sends a 10-byte command beginning with
/// 0xC2 and requests 0x20 bytes of hardware-status data.
pub const HARDWARE_STATUS_CDB: [u8; 10] = [0xc2, 0, 0, 0, 0, 0, 0, 0, 0x20, 0];
pub const IX500_WIFI_SWITCH_STATUS_OFFSET: usize = 0x10;
pub const RESULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const MAX_RESULT_POLLS: usize = 360;
const MAX_START_ATTEMPTS: usize = 15;
const START_RETRY_INTERVAL: Duration = Duration::from_millis(200);
const WIFI_SET_CDB: [u8; 6] = [0x1d, 0, 0, 1, 0x1c, 0];

/// Offline-only states for the provisioner. The current CLI intentionally has
/// no executor that can advance these states by sending device commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // State model is additionally exercised by protocol tests.
pub enum ProvisionState {
    Validated,
    UsbInitialized,
    ScannerIdentified,
    ProtocolReady,
    PossessionActive,
    RequestSent,
    Polling,
    ResultReady,
    Completed,
    Failed,
    CleanedUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // State model is additionally exercised by protocol tests.
pub enum ProvisionEvent {
    UsbReady,
    FirmwareIx5000U00,
    UnsupportedFirmware,
    ProtocolUnchanged,
    PossessionGranted,
    RequestAccepted,
    PollPending,
    PollComplete,
    PossessionBusy(u8),
    PossessionDenied,
    WifiResult(u8),
    PollTimeout,
    UsbDisconnected,
    ProtocolError,
    ExplicitCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionError {
    WifiApi(u8),
    PollTimeout,
    UsbDisconnected,
    Protocol,
    Possession(u8),
    InvalidFirmware,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionFailure {
    StartTransport(String),
    StartDeviceResult(u8),
    WifiSetTransport(String),
    ResultPollTimeout,
    ResultPollTransport(String),
    WifiApplicationResult(u8),
}

impl std::fmt::Display for ProvisionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartTransport(e) => write!(f, "START transport failed; no WLAN SET sent; scanner possession state is uncertain: {e}"),
            Self::StartDeviceResult(code) => write!(f, "START failed with Result-Poll application byte {code} (0x{code:02x}); no WLAN SET sent"),
            Self::WifiSetTransport(e) => write!(f, "WLAN SET transport failed; it was sent at most once and scanner configuration state is uncertain: {e}"),
            Self::ResultPollTimeout => f.write_str("WLAN SET was sent once, but Result-Poll timed out; scanner configuration state is unknown; do not retry automatically"),
            Self::ResultPollTransport(e) => write!(f, "WLAN SET was sent once, but Result-Poll transport failed; scanner configuration state is unknown; do not retry: {e}"),
            Self::WifiApplicationResult(code) => write!(f, "scanner completed WLAN operation with application result {code}; configuration outcome is not confirmed successful; original code preserved"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionSuccess;

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WifiApi(code) => write!(
                f,
                "scanner Wi-Fi API error {code} (0x{code:02x}); request was not retried"
            ),
            Self::PollTimeout => f.write_str("scanner Result-Poll timed out"),
            Self::UsbDisconnected => f.write_str("scanner USB connection was lost"),
            Self::Protocol => f.write_str("scanner protocol or preflight error"),
            Self::Possession(code) => write!(f, "scanner possession failed with result {code}"),
            Self::InvalidFirmware => {
                f.write_str("unsupported scanner firmware; only iX500 0U00 is accepted")
            }
        }
    }
}

/// Deterministic, fail-closed reducer for the Windows-observed control flow.
/// It preserves API errors (including 90) and never retries a Wi-Fi SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // State model is additionally exercised by protocol tests.
pub struct ProvisionMachine {
    state: ProvisionState,
    possession_attempts: u8,
    error: Option<ProvisionError>,
}

#[allow(dead_code)] // Offline plan only; no USB executor calls this reducer.
impl ProvisionMachine {
    pub fn new() -> Self {
        Self {
            state: ProvisionState::Validated,
            possession_attempts: 0,
            error: None,
        }
    }
    pub fn state(self) -> ProvisionState {
        self.state
    }
    pub fn error(self) -> Option<ProvisionError> {
        self.error
    }

    pub fn transition(&mut self, event: ProvisionEvent) -> Result<ProvisionState, &'static str> {
        use ProvisionEvent as E;
        use ProvisionState as S;
        let next = match (self.state, event) {
            (S::Validated, E::UsbReady) => S::UsbInitialized,
            (S::UsbInitialized, E::FirmwareIx5000U00) => S::ScannerIdentified,
            (S::UsbInitialized, E::UnsupportedFirmware) => {
                self.error = Some(ProvisionError::InvalidFirmware);
                S::Failed
            }
            (S::ScannerIdentified, E::ProtocolUnchanged) => S::ProtocolReady,
            (S::ProtocolReady, E::PossessionGranted) => S::PossessionActive,
            (S::ProtocolReady, E::PossessionBusy(code @ (2 | 10))) => {
                self.possession_attempts = self.possession_attempts.saturating_add(1);
                if self.possession_attempts >= 15 || (code == 10 && self.possession_attempts >= 6) {
                    self.error = Some(ProvisionError::Possession(code));
                    S::Failed
                } else {
                    S::ProtocolReady
                }
            }
            (S::ProtocolReady, E::PossessionDenied) => {
                self.error = Some(ProvisionError::Possession(0xff));
                S::Failed
            }
            // FunctionalVersion and Device_Info are Windows profile/UI
            // preflight. The native Wi-Fi setter does not consume their
            // outputs; they are deliberately not protocol prerequisites here.
            (S::PossessionActive, E::RequestAccepted) => S::RequestSent,
            (S::RequestSent, E::PollPending) | (S::Polling, E::PollPending) => S::Polling,
            (S::RequestSent, E::PollComplete) | (S::Polling, E::PollComplete) => S::ResultReady,
            (S::ResultReady, E::WifiResult(0)) => S::Completed,
            (S::ResultReady, E::WifiResult(code)) => {
                self.error = Some(ProvisionError::WifiApi(code));
                S::Failed
            }
            (S::RequestSent | S::Polling, E::PollTimeout) => {
                self.error = Some(ProvisionError::PollTimeout);
                S::Failed
            }
            (
                S::Validated
                | S::UsbInitialized
                | S::ScannerIdentified
                | S::ProtocolReady
                | S::PossessionActive
                | S::RequestSent
                | S::Polling
                | S::ResultReady,
                E::UsbDisconnected,
            ) => {
                self.error = Some(ProvisionError::UsbDisconnected);
                S::Failed
            }
            (
                S::Validated
                | S::UsbInitialized
                | S::ScannerIdentified
                | S::ProtocolReady
                | S::PossessionActive
                | S::RequestSent
                | S::Polling
                | S::ResultReady,
                E::ProtocolError,
            ) => {
                self.error = Some(ProvisionError::Protocol);
                S::Failed
            }
            (S::Completed | S::Failed, E::ExplicitCleanup) => S::CleanedUp,
            _ => return Err("event is invalid for the current provisioning state"),
        };
        self.state = next;
        Ok(next)
    }
}

impl Default for ProvisionMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Prepared only; possession commands are not issued by the CLI.
pub enum PossessionCommand {
    Start,
    End,
}

impl PossessionCommand {
    /// Exact 16-byte strings copied by the SCApi into SETUP_NET_START/END.
    #[allow(dead_code)]
    pub fn payload(self) -> [u8; 16] {
        match self {
            Self::Start => *b"SETUP NET START ",
            Self::End => *b"SETUP NET END   ",
        }
    }

    #[allow(dead_code)]
    pub fn cdb(self) -> [u8; 6] {
        [0x1d, 0, 0, 0, 0x10, 0]
    }
}

#[allow(dead_code)] // Used by the offline request builder; USB sending is gated.
pub const SETUP_NET_CMD: &[u8; 16] = b"SETUP NET CMD   ";
#[allow(dead_code)]
pub const WIFI_SETTING_OPERATION: u16 = 0x0801;
#[allow(dead_code)]
pub const WIFI_SETTING_COMMAND: u32 = 0x1006;
#[allow(dead_code)]
pub const WIFI_SETTING_PAYLOAD_LEN: usize = 0xf8;
#[allow(dead_code)]
const WIFI_SETTING_HEADER_LEN: usize = 0x24;
#[allow(dead_code)]
const IX500_KEY_TABLE: &[u8] = b"pFusCANsNapFiPfu";

/// Diagnostic SCSI CDB generated by the application's STI descriptor builder.
/// Length is represented as a big-endian CDB field.
#[allow(dead_code)]
pub fn diagnostic_cdb(opcode: u8, length: usize) -> Result<[u8; 6], String> {
    let length = u16::try_from(length).map_err(|_| "diagnostic transfer exceeds 65535 bytes")?;
    Ok([opcode, 0, 0, (length >> 8) as u8, length as u8, 0])
}

/// Application-level 20-byte result, distinct from the 13-byte USB status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ResultPollRequest;

impl ResultPollRequest {
    pub const RESPONSE_LEN: usize = 20;

    pub fn cdb(self) -> [u8; 6] {
        [0x1c, 0, 0, 0, Self::RESPONSE_LEN as u8, 0]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ApplicationResult {
    Complete,
    Pending,
    DeviceError(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ResultPollResponse {
    /// First byte checked by FUN_10016ec0. Bytes 1..19 are retained but unused
    /// by that poll parser (they may be operation-specific to the device).
    pub result: ApplicationResult,
    pub code: u8,
    pub opaque: [u8; 19],
}

impl ResultPollResponse {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let bytes: [u8; ResultPollRequest::RESPONSE_LEN] = data
            .try_into()
            .map_err(|_| "Result-Poll application result must be exactly 20 bytes".to_string())?;
        let mut opaque = [0; 19];
        opaque.copy_from_slice(&bytes[1..]);
        let code = bytes[0];
        let result = match code {
            0 => ApplicationResult::Complete,
            1 => ApplicationResult::Pending,
            other => ApplicationResult::DeviceError(other),
        };
        Ok(Self {
            result,
            code,
            opaque,
        })
    }
}

/// Execute one read-only Result-Poll: command frame, 20 result bytes, then the
/// separate 13-byte USB status (plus REQUEST SENSE on CHECK CONDITION).
#[allow(dead_code)] // Public protocol helper retained for tests and diagnostics.
pub fn poll_result_once<T: BulkTransport>(transport: &mut T) -> Result<ResultPollResponse, String> {
    let bytes = protocol::scsi_read_sti(
        transport,
        &ResultPollRequest.cdb(),
        ResultPollRequest::RESPONSE_LEN,
    )?;
    ResultPollResponse::parse(&bytes)
}

fn poll_result_once_traced<T: BulkTransport>(
    transport: &mut T,
    phase: &str,
    trace: &mut protocol::ProtocolTrace,
) -> Result<ResultPollResponse, String> {
    let bytes = protocol::scsi_read_sti_traced(
        transport,
        &ResultPollRequest.cdb(),
        ResultPollRequest::RESPONSE_LEN,
        phase,
        trace,
    )?;
    let response = ResultPollResponse::parse(&bytes)?;
    trace.note(
        phase,
        format!(
            "application response byte0=0x{:02x} parsed={:?}; bytes1..20 retained opaque",
            response.code, response.result
        ),
    );
    Ok(response)
}

/// Original SCApi cadence: poll immediately, wait 500 ms between pending
/// results, honor the caller timeout, and cap at 360 polls.
#[allow(dead_code)] // Not used by Wi-Fi writes while possession remains unverified.
pub fn poll_result<T: BulkTransport>(
    transport: &mut T,
    timeout: Duration,
) -> Result<ResultPollResponse, String> {
    let response = poll_result_terminal(transport, timeout)?;
    match response.result {
        ApplicationResult::DeviceError(code) => {
            Err(format!("scanner application result 0x{code:02x}"))
        }
        _ => Ok(response),
    }
}

/// Return the terminal application byte without collapsing device result codes.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum PollFailure {
    Timeout,
    Transport(String),
    DeviceResult(ResultPollResponse),
}

fn poll_result_terminal_with_sleep<T, F>(
    transport: &mut T,
    timeout: Duration,
    mut sleep: F,
) -> Result<ResultPollResponse, PollFailure>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    let mut trace = protocol::ProtocolTrace::default();
    poll_result_terminal_traced(transport, timeout, &mut sleep, "result-poll", &mut trace)
}

fn poll_result_terminal_traced<T, F>(
    transport: &mut T,
    timeout: Duration,
    mut sleep: F,
    phase: &str,
    trace: &mut protocol::ProtocolTrace,
) -> Result<ResultPollResponse, PollFailure>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    let started = Instant::now();
    for index in 0..MAX_RESULT_POLLS {
        let response =
            poll_result_once_traced(transport, phase, trace).map_err(PollFailure::Transport)?;
        match response.result {
            ApplicationResult::Complete => return Ok(response),
            ApplicationResult::DeviceError(_) => return Err(PollFailure::DeviceResult(response)),
            ApplicationResult::Pending => {
                let elapsed = started.elapsed();
                if elapsed >= timeout || index + 1 == MAX_RESULT_POLLS {
                    return Err(PollFailure::Timeout);
                }
                sleep(RESULT_POLL_INTERVAL.min(timeout - elapsed));
            }
        }
    }
    Err(PollFailure::Timeout)
}

fn poll_result_terminal<T: BulkTransport>(
    transport: &mut T,
    timeout: Duration,
) -> Result<ResultPollResponse, String> {
    poll_result_terminal_with_sleep(transport, timeout, std::thread::sleep).map_err(|error| {
        match error {
            PollFailure::Timeout => "Result-Poll timed out".to_string(),
            PollFailure::Transport(e) => e,
            PollFailure::DeviceResult(response) => {
                format!("scanner application result 0x{:02x}", response.code)
            }
        }
    })
}

/// Execute the reference USB path: START plus one poll (retrying the mapped
/// iX500 `0x81` possession response), one WLAN SET, then Result-Poll. No END is sent implicitly:
/// Windows leaves possession active on ordinary success and its Wi-Fi error
/// paths do not have a generic END handler. The USB handle is always released
/// by `Scanner::drop` at the caller.
#[allow(dead_code)] // Non-tracing facade retained for test callers.
pub fn provision<T, F>(
    transport: &mut T,
    request: &WifiSettingRequest,
    timeout: Duration,
    mut sleep: F,
) -> Result<ProvisionSuccess, ProvisionFailure>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    let mut trace = protocol::ProtocolTrace::default();
    provision_traced(transport, request, timeout, &mut sleep, &mut trace)
}

/// Same sequence as `provision`, with optional protocol diagnostics. The SET
/// payload is always redacted, even when tracing is enabled.
pub fn provision_traced<T, F>(
    transport: &mut T,
    request: &WifiSettingRequest,
    timeout: Duration,
    mut sleep: F,
    trace: &mut protocol::ProtocolTrace,
) -> Result<ProvisionSuccess, ProvisionFailure>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    let mut start_attempts = 0usize;
    loop {
        start_attempts += 1;
        trace.note("state", format!("phase START attempt={start_attempts}"));
        if let Err(error) = protocol::scsi_write_traced(
            transport,
            &PossessionCommand::Start.cdb(),
            &PossessionCommand::Start.payload(),
            "START",
            true,
            trace,
        ) {
            return Err(ProvisionFailure::StartTransport(error));
        }
        let response = match poll_result_once_traced(transport, "START Result-Poll", trace) {
            Ok(response) => response,
            Err(error) => return Err(ProvisionFailure::StartTransport(error)),
        };
        match response.code {
            0 => break,
            0x81 if start_api_result(response.code) == 2 => {
                let code = start_api_result(response.code);
                trace.note("parser START", format!("application byte 0x{:02x} maps to Windows possession status {code}; bounded retry branch", response.code));
                if start_attempts >= MAX_START_ATTEMPTS {
                    return Err(ProvisionFailure::StartDeviceResult(response.code));
                }
                sleep(START_RETRY_INTERVAL);
            }
            other => {
                trace.note("parser START", format!("application byte 0x{:02x} has no iX500 retry mapping; stop without WLAN SET", response.code));
                return Err(ProvisionFailure::StartDeviceResult(other));
            }
        }
    }

    trace.note(
        "state",
        "phase WLAN SET attempt=1; credential-bearing payload redacted",
    );
    if let Err(error) = protocol::scsi_write_traced(
        transport,
        &WIFI_SET_CDB,
        &request.bytes,
        "WLAN SET",
        false,
        trace,
    ) {
        return Err(ProvisionFailure::WifiSetTransport(error));
    }
    match poll_result_terminal_traced(transport, timeout, sleep, "WLAN Result-Poll", trace) {
        Ok(_) => Ok(ProvisionSuccess),
        Err(PollFailure::Timeout) => Err(ProvisionFailure::ResultPollTimeout),
        Err(PollFailure::Transport(error)) => Err(ProvisionFailure::ResultPollTransport(error)),
        Err(PollFailure::DeviceResult(response)) => {
            Err(ProvisionFailure::WifiApplicationResult(response.code))
        }
    }
}

/// FUN_1000f1a0 maps Result-Poll application byte 0x81 to possession status
/// 2 for the iX500-compatible model flag. The Windows wrapper retries API
/// status 2 by repeating START+one poll. Other raw application bytes are not
/// API retry codes; the raw byte remains preserved on failure.
fn start_api_result(application_byte: u8) -> u8 {
    match application_byte {
        0x81 => 2,
        other => other,
    }
}

/// Scanner-side possession state. Windows STI LockDevice is deliberately not
/// represented here; it is a separate host-side lock handled by libusb claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PossessionState {
    Active,
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct PossessionSession {
    state: PossessionState,
}

#[allow(dead_code)]
impl PossessionSession {
    /// Reproduce Usb_Init_Possession's scanner sequence. Account strings are
    /// cached locally by the Windows DLL; the physical START payload is fixed.
    pub fn acquire<T: BulkTransport>(transport: &mut T, timeout: Duration) -> Result<Self, String> {
        Self::acquire_with_sleep(transport, timeout, std::thread::sleep)
    }

    fn acquire_with_sleep<T, F>(
        transport: &mut T,
        timeout: Duration,
        mut sleep: F,
    ) -> Result<Self, String>
    where
        T: BulkTransport,
        F: FnMut(Duration),
    {
        for attempt in 0..15 {
            let response = execute_possession_command_with_sleep(
                transport,
                PossessionCommand::Start,
                timeout,
                &mut sleep,
            )?;
            match response.code {
                0 => {
                    return Ok(Self {
                        state: PossessionState::Active,
                    })
                }
                2 | 10 => {
                    // Native init returns after the sixth result 10; result 2
                    // and 10 otherwise repeat START + result poll after 200 ms.
                    if (response.code == 10 && attempt == 5) || attempt == 14 {
                        return Err(format!(
                            "scanner possession did not complete (result {})",
                            response.code
                        ));
                    }
                    sleep(Duration::from_millis(200));
                }
                code => return Err(format!("scanner possession result 0x{code:02x}")),
            }
        }
        Err("scanner possession did not complete after 15 attempts".into())
    }

    pub fn state(self) -> PossessionState {
        self.state
    }

    /// Mirrors Usb_Possession_Cancel. This is explicit because Windows does
    /// not issue SETUP_NET_END on every successful path.
    pub fn cancel<T: BulkTransport>(
        &mut self,
        transport: &mut T,
        timeout: Duration,
    ) -> Result<(), String> {
        if self.state == PossessionState::Ended {
            return Ok(());
        }
        let result = execute_possession_command(transport, PossessionCommand::End, timeout)?;
        if result.result != ApplicationResult::Complete {
            return Err(format!(
                "scanner possession end result 0x{:02x}",
                result.code
            ));
        }
        self.state = PossessionState::Ended;
        Ok(())
    }
}

fn execute_possession_command<T: BulkTransport>(
    transport: &mut T,
    command: PossessionCommand,
    timeout: Duration,
) -> Result<ResultPollResponse, String> {
    protocol::scsi_write(transport, &command.cdb(), &command.payload())?;
    poll_result_terminal(transport, timeout)
}

fn execute_possession_command_with_sleep<T, F>(
    transport: &mut T,
    command: PossessionCommand,
    timeout: Duration,
    sleep: F,
) -> Result<ResultPollResponse, String>
where
    T: BulkTransport,
    F: FnMut(Duration),
{
    protocol::scsi_write(transport, &command.cdb(), &command.payload())?;
    match poll_result_terminal_with_sleep(transport, timeout, sleep) {
        Ok(response) | Err(PollFailure::DeviceResult(response)) => Ok(response),
        Err(PollFailure::Timeout) => Err("Result-Poll timed out".into()),
        Err(PollFailure::Transport(error)) => Err(error),
    }
}

/// Pure state-machine helper mirroring the iX500's observed 0/1 results.
/// Caller supplies timing and I/O for deterministic tests.
#[allow(dead_code)]
pub fn poll_result_bounded<F>(max_polls: usize, mut poll: F) -> Result<ResultPollResponse, String>
where
    F: FnMut() -> Result<ResultPollResponse, String>,
{
    for _ in 0..max_polls {
        let response = poll()?;
        match response.result {
            ApplicationResult::Complete => return Ok(response),
            ApplicationResult::Pending => continue,
            ApplicationResult::DeviceError(code) => {
                return Err(format!("scanner application result 0x{code:02x}"));
            }
        }
    }
    Err("Result-Poll timed out".into())
}

/// Application-level request reconstructed from PfuSsWifiToolSCApi.dll.
/// It is the OUT data phase of the verified diagnostic SCSI transaction.
#[derive(Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct WifiSettingRequest {
    pub bytes: [u8; WIFI_SETTING_HEADER_LEN + WIFI_SETTING_PAYLOAD_LEN],
}

impl Drop for WifiSettingRequest {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Build the Windows application's SETUP_NET_CMD object in memory. The
/// provisioner sends it only after START returns application result zero.
#[allow(dead_code)]
pub fn prepare_wpa2_psk(ssid: &str, password: &[u8]) -> Result<WifiSettingRequest, String> {
    let ssid = ssid.as_bytes();
    if ssid.is_empty() || ssid.len() > 32 || ssid.contains(&0) || !ssid.is_ascii() {
        return Err("SSID must contain 1..=32 ASCII non-NUL bytes".into());
    }
    if !(8..=63).contains(&password.len()) || !password.is_ascii() || password.contains(&0) {
        return Err("WPA2-PSK password must contain 8..=63 ASCII bytes".into());
    }

    let mut request = WifiSettingRequest {
        bytes: [0; WIFI_SETTING_HEADER_LEN + WIFI_SETTING_PAYLOAD_LEN],
    };
    request.bytes[..16].copy_from_slice(SETUP_NET_CMD);
    request.bytes[16..18].copy_from_slice(&WIFI_SETTING_OPERATION.to_le_bytes());
    request.bytes[20..24].copy_from_slice(&WIFI_SETTING_COMMAND.to_le_bytes());
    request.bytes[32..36].copy_from_slice(&(WIFI_SETTING_PAYLOAD_LEN as u32).to_le_bytes());
    let payload = &mut request.bytes[WIFI_SETTING_HEADER_LEN..];
    payload[..ssid.len()].copy_from_slice(ssid);
    payload[0x24..0x28].copy_from_slice(b"WPA2");
    payload[0x2c..0x2f].copy_from_slice(b"AES");
    for (i, &key_byte) in password.iter().enumerate() {
        let encoded = (IX500_KEY_TABLE[i % IX500_KEY_TABLE.len()] as u16) + key_byte as u16 + 0x0b;
        let digits = format!("{encoded:03}");
        let start = 0x34 + 3 * i;
        payload[start..start + 3].copy_from_slice(digits.as_bytes());
    }
    Ok(request)
}

pub fn status<T: BulkTransport>(transport: &mut T) -> Result<[u8; 32], String> {
    let data = protocol::scsi_read(transport, &HARDWARE_STATUS_CDB, 32)?;
    data.try_into()
        .map_err(|_| "hardware-status response was not 32 bytes".to_string())
}

/// The Windows iX500 `Usb_Wifi_Status` parser reads response byte 16 and
/// returns API status 7 when its sign bit is clear. The setup UI treats status
/// 7 as the Wi-Fi switch-off condition. A set sign bit maps to -1 (the
/// non-switch-off path). Other C2 bytes remain opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiSwitchState {
    On,
    Off,
}

pub fn parse_wifi_switch_state(response: &[u8]) -> Result<WifiSwitchState, String> {
    let byte = *response
        .get(IX500_WIFI_SWITCH_STATUS_OFFSET)
        .ok_or("C2 hardware-status response is too short to contain iX500 switch state")?;
    Ok(if byte & 0x80 != 0 {
        WifiSwitchState::On
    } else {
        WifiSwitchState::Off
    })
}

pub fn read_status_from_scanner() -> Result<(), String> {
    let mut scanner = Scanner::open()?;
    let response = status(&mut scanner)?;
    let switch = parse_wifi_switch_state(&response)?;
    println!(
        "Wi-Fi hardware switch (C2 response byte 16, bit 7): {}",
        match switch {
            WifiSwitchState::On => "ON",
            WifiSwitchState::Off => "OFF",
        }
    );
    println!(
        "C2 response byte 16: {:02x}; other response bytes are not interpreted",
        response[IX500_WIFI_SWITCH_STATUS_OFFSET]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_state_machine_success_and_explicit_cleanup() {
        let mut m = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
            ProvisionEvent::PossessionGranted,
            ProvisionEvent::RequestAccepted,
            ProvisionEvent::PollPending,
            ProvisionEvent::PollComplete,
            ProvisionEvent::WifiResult(0),
            ProvisionEvent::ExplicitCleanup,
        ] {
            m.transition(event).unwrap();
        }
        assert_eq!(m.state(), ProvisionState::CleanedUp);
    }

    #[test]
    fn provisioning_error_90_fails_closed_and_preserves_original_code() {
        let mut machine = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
            ProvisionEvent::PossessionGranted,
            ProvisionEvent::RequestAccepted,
            ProvisionEvent::PollComplete,
        ] {
            machine.transition(event).unwrap();
        }
        assert_eq!(
            machine.transition(ProvisionEvent::WifiResult(90)).unwrap(),
            ProvisionState::Failed
        );
        assert_eq!(machine.error(), Some(ProvisionError::WifiApi(90)));
        assert!(machine.transition(ProvisionEvent::RequestAccepted).is_err());
        machine.transition(ProvisionEvent::ExplicitCleanup).unwrap();
        assert_eq!(machine.error(), Some(ProvisionError::WifiApi(90)));
    }

    #[test]
    fn unsupported_firmware_is_rejected_before_possession() {
        let mut machine = ProvisionMachine::new();
        machine.transition(ProvisionEvent::UsbReady).unwrap();
        assert_eq!(
            machine
                .transition(ProvisionEvent::UnsupportedFirmware)
                .unwrap(),
            ProvisionState::Failed
        );
        assert_eq!(machine.error(), Some(ProvisionError::InvalidFirmware));
        machine.transition(ProvisionEvent::ExplicitCleanup).unwrap();
        assert!(machine
            .transition(ProvisionEvent::PossessionGranted)
            .is_err());
    }

    #[test]
    fn functional_version_and_profile_reads_are_not_set_prerequisites() {
        let mut machine = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
            ProvisionEvent::PossessionGranted,
        ] {
            machine.transition(event).unwrap();
        }
        assert_eq!(
            machine.transition(ProvisionEvent::RequestAccepted).unwrap(),
            ProvisionState::RequestSent
        );
    }

    #[test]
    fn provisioning_failures_are_terminal_and_cleanup_is_explicit() {
        for failure in [
            ProvisionEvent::PollTimeout,
            ProvisionEvent::UsbDisconnected,
            ProvisionEvent::ProtocolError,
        ] {
            let mut m = ProvisionMachine::new();
            for event in [
                ProvisionEvent::UsbReady,
                ProvisionEvent::FirmwareIx5000U00,
                ProvisionEvent::ProtocolUnchanged,
                ProvisionEvent::PossessionGranted,
                ProvisionEvent::RequestAccepted,
            ] {
                m.transition(event).unwrap();
            }
            m.transition(failure).unwrap();
            assert_eq!(m.state(), ProvisionState::Failed);
            assert!(m.error().is_some());
            m.transition(ProvisionEvent::ExplicitCleanup).unwrap();
            assert_eq!(m.state(), ProvisionState::CleanedUp);
        }

        let mut operation_error = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
            ProvisionEvent::PossessionGranted,
            ProvisionEvent::RequestAccepted,
            ProvisionEvent::PollComplete,
        ] {
            operation_error.transition(event).unwrap();
        }
        assert_eq!(
            operation_error
                .transition(ProvisionEvent::WifiResult(2))
                .unwrap(),
            ProvisionState::Failed
        );
        assert_eq!(operation_error.error(), Some(ProvisionError::WifiApi(2)));
    }

    #[test]
    fn provisioning_rejects_out_of_order_operations() {
        let mut m = ProvisionMachine::new();
        assert!(m.transition(ProvisionEvent::PossessionGranted).is_err());
        assert_eq!(m.state(), ProvisionState::Validated);
    }

    #[test]
    fn provisioning_possession_retries_are_explicitly_bounded() {
        let mut retry_two = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
        ] {
            retry_two.transition(event).unwrap();
        }
        for _ in 0..14 {
            assert_eq!(
                retry_two
                    .transition(ProvisionEvent::PossessionBusy(2))
                    .unwrap(),
                ProvisionState::ProtocolReady
            );
        }
        assert_eq!(
            retry_two
                .transition(ProvisionEvent::PossessionBusy(2))
                .unwrap(),
            ProvisionState::Failed
        );
        assert_eq!(retry_two.error(), Some(ProvisionError::Possession(2)));
        retry_two
            .transition(ProvisionEvent::ExplicitCleanup)
            .unwrap();

        let mut retry_ten = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
        ] {
            retry_ten.transition(event).unwrap();
        }
        for _ in 0..5 {
            assert_eq!(
                retry_ten
                    .transition(ProvisionEvent::PossessionBusy(10))
                    .unwrap(),
                ProvisionState::ProtocolReady
            );
        }
        assert_eq!(
            retry_ten
                .transition(ProvisionEvent::PossessionBusy(10))
                .unwrap(),
            ProvisionState::Failed
        );
        assert_eq!(retry_ten.error(), Some(ProvisionError::Possession(10)));
        retry_ten
            .transition(ProvisionEvent::ExplicitCleanup)
            .unwrap();

        let mut denied = ProvisionMachine::new();
        for event in [
            ProvisionEvent::UsbReady,
            ProvisionEvent::FirmwareIx5000U00,
            ProvisionEvent::ProtocolUnchanged,
        ] {
            denied.transition(event).unwrap();
        }
        assert_eq!(
            denied.transition(ProvisionEvent::PossessionDenied).unwrap(),
            ProvisionState::Failed
        );
        assert!(denied.error().is_some());
        denied.transition(ProvisionEvent::ExplicitCleanup).unwrap();
    }
    use std::collections::VecDeque;

    struct MockUsb {
        writes: Vec<Vec<u8>>,
        reads: VecDeque<Vec<u8>>,
    }
    impl BulkTransport for MockUsb {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }
        fn read_bulk(&mut self, data: &mut [u8]) -> Result<usize, String> {
            let response = self.reads.pop_front().ok_or("no simulated response")?;
            let n = response.len().min(data.len());
            data[..n].copy_from_slice(&response[..n]);
            if n < response.len() {
                self.reads.push_front(response[n..].to_vec());
            }
            Ok(n)
        }
    }

    struct StageMock {
        writes: Vec<Vec<u8>>,
        reads: VecDeque<Vec<u8>>,
        read_sizes: Vec<usize>,
    }
    impl BulkTransport for StageMock {
        fn write_bulk(&mut self, data: &[u8]) -> Result<usize, String> {
            self.writes.push(data.to_vec());
            Ok(data.len())
        }
        fn read_bulk(&mut self, data: &mut [u8]) -> Result<usize, String> {
            self.read_sizes.push(data.len());
            let response = self.reads.pop_front().ok_or("missing simulated transfer")?;
            if response.len() > data.len() {
                return Err("simulated transfer exceeds buffer".into());
            }
            data[..response.len()].copy_from_slice(&response);
            Ok(response.len())
        }
    }

    fn result_transfer(code: u8) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[0] = code;
        bytes
    }

    fn good_usb_status() -> Vec<u8> {
        let mut bytes = vec![0; 13];
        bytes[0] = 0x53;
        bytes
    }

    fn usb_status(code: u8) -> Vec<u8> {
        let mut bytes = good_usb_status();
        bytes[9] = code;
        bytes
    }

    fn stage_mock(reads: Vec<Vec<u8>>) -> StageMock {
        StageMock {
            writes: vec![],
            reads: reads.into(),
            read_sizes: vec![],
        }
    }

    fn append_app_result(reads: &mut Vec<Vec<u8>>, code: u8) {
        reads.push(result_transfer(code));
        reads.push(good_usb_status());
    }

    fn append_out_success(reads: &mut Vec<Vec<u8>>) {
        reads.push(good_usb_status());
    }

    #[test]
    fn hardware_status_uses_confirmed_c2_read_command() {
        let mut response = [0u8; 32];
        response[0] = 0xa5;
        let mut status_packet = [0u8; 13];
        status_packet[0] = 0x53;
        let mut mock = MockUsb {
            writes: vec![],
            reads: vec![response.to_vec(), status_packet.to_vec()].into(),
        };
        assert_eq!(status(&mut mock).unwrap(), response);
        assert_eq!(mock.writes.len(), 1);
        assert_eq!(mock.writes[0].len(), 31);
        assert_eq!(mock.writes[0][0], 0x43);
        assert_eq!(&mock.writes[0][19..29], &HARDWARE_STATUS_CDB);
    }

    #[test]
    fn c2_byte_16_sign_bit_matches_windows_switch_status_mapping() {
        let mut response = [0u8; 32];
        response[IX500_WIFI_SWITCH_STATUS_OFFSET] = 0x00;
        assert_eq!(parse_wifi_switch_state(&response), Ok(WifiSwitchState::Off));
        response[IX500_WIFI_SWITCH_STATUS_OFFSET] = 0x80;
        assert_eq!(parse_wifi_switch_state(&response), Ok(WifiSwitchState::On));
        response[IX500_WIFI_SWITCH_STATUS_OFFSET] = 0xff;
        assert_eq!(parse_wifi_switch_state(&response), Ok(WifiSwitchState::On));
    }

    #[test]
    fn c2_switch_parser_rejects_short_data() {
        assert!(parse_wifi_switch_state(&[0u8; 16]).is_err());
    }

    #[test]
    fn prepares_wpa2_request_with_confirmed_application_offsets() {
        let request = prepare_wpa2_psk("TestNet", b"abcdefgh").unwrap();
        assert_eq!(&request.bytes[..16], SETUP_NET_CMD);
        assert_eq!(&request.bytes[16..18], &[0x01, 0x08]);
        assert_eq!(&request.bytes[20..24], &[0x06, 0x10, 0, 0]);
        assert_eq!(&request.bytes[28..32], &[0, 0, 0, 0]);
        assert_eq!(&request.bytes[32..36], &[0xf8, 0, 0, 0]);
        let payload = &request.bytes[36..];
        assert_eq!(&payload[..7], b"TestNet");
        assert_eq!(&payload[0x24..0x28], b"WPA2");
        assert_eq!(&payload[0x2c..0x2f], b"AES");
        assert_eq!(&payload[0x34..0x34 + 9], b"220179227");
        assert!(payload[0x34 + 3 * 8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn rejects_invalid_wifi_credentials_without_constructing_a_request() {
        assert!(prepare_wpa2_psk("", b"abcdefgh").is_err());
        assert!(prepare_wpa2_psk("x", b"short").is_err());
        assert!(prepare_wpa2_psk("x", &[0xff; 8]).is_err());
    }

    #[test]
    fn diagnostic_cdbs_encode_transfer_length_big_endian() {
        assert_eq!(
            diagnostic_cdb(0x1d, 0x11c).unwrap(),
            [0x1d, 0, 0, 1, 0x1c, 0]
        );
        assert_eq!(
            diagnostic_cdb(0x1c, 0x14).unwrap(),
            [0x1c, 0, 0, 0, 0x14, 0]
        );
        assert!(diagnostic_cdb(0x1d, 0x1_0000).is_err());
    }

    #[test]
    fn result_poll_request_and_response_have_exact_application_layout() {
        assert_eq!(ResultPollRequest.cdb(), [0x1c, 0, 0, 0, 0x14, 0]);
        let mut bytes = [0xffu8; 20];
        bytes[..4].copy_from_slice(&[0x81, b'U', b'0', b'0']);
        let parsed = ResultPollResponse::parse(&bytes).unwrap();
        assert_eq!(parsed.code, 0x81);
        assert_eq!(parsed.result, ApplicationResult::DeviceError(0x81));
        assert_eq!(&parsed.opaque[..3], b"U00");
        assert!(parsed.opaque[3..].iter().all(|byte| *byte == 0xff));
        assert!(ResultPollResponse::parse(&bytes[..19]).is_err());
    }

    #[test]
    fn possession_payloads_are_exact_and_prepared_without_sending() {
        assert_eq!(PossessionCommand::Start.payload(), *b"SETUP NET START ");
        assert_eq!(PossessionCommand::End.payload(), *b"SETUP NET END   ");
        assert_eq!(PossessionCommand::Start.cdb(), [0x1d, 0, 0, 0, 0x10, 0]);
        assert_eq!(PossessionCommand::End.cdb(), [0x1d, 0, 0, 0, 0x10, 0]);
    }

    #[test]
    fn possession_session_start_poll_end_poll_sequence_is_mocked() {
        let mut mock = StageMock {
            writes: vec![],
            reads: vec![
                good_usb_status(),
                result_transfer(0),
                good_usb_status(),
                good_usb_status(),
                result_transfer(0),
                good_usb_status(),
            ]
            .into(),
            read_sizes: vec![],
        };
        let mut session =
            PossessionSession::acquire_with_sleep(&mut mock, Duration::from_secs(1), |_| {})
                .unwrap();
        assert_eq!(session.state(), PossessionState::Active);
        session.cancel(&mut mock, Duration::from_secs(1)).unwrap();
        assert_eq!(session.state(), PossessionState::Ended);
        assert_eq!(mock.writes.len(), 6);
        assert_eq!(mock.writes[0].len(), 31);
        assert_eq!(&mock.writes[0][19..25], &[0x1d, 0, 0, 0, 0x10, 0]);
        assert_eq!(mock.writes[1], b"SETUP NET START ");
        assert_eq!(&mock.writes[2][19..25], &[0x1c, 0, 0, 0, 0x14, 0]);
        assert_eq!(mock.writes[4], b"SETUP NET END   ");
        assert_eq!(&mock.writes[5][19..25], &[0x1c, 0, 0, 0, 0x14, 0]);
        assert_eq!(mock.read_sizes, [13, 20, 13, 13, 20, 13]);
    }

    #[test]
    fn mocked_start_wifi_request_and_poll_never_resends_set_or_ends_on_success() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut mock = StageMock {
            writes: vec![],
            reads: vec![
                good_usb_status(), // START transport status
                result_transfer(0),
                good_usb_status(), // START result
                good_usb_status(), // Wi-Fi SET transport status
                result_transfer(1),
                good_usb_status(), // pending poll
                result_transfer(0),
                good_usb_status(), // completed poll
            ]
            .into(),
            read_sizes: vec![],
        };
        protocol::scsi_write(
            &mut mock,
            &PossessionCommand::Start.cdb(),
            &PossessionCommand::Start.payload(),
        )
        .unwrap();
        assert_eq!(
            poll_result_once(&mut mock).unwrap().result,
            ApplicationResult::Complete
        );
        protocol::scsi_write(&mut mock, &[0x1d, 0, 0, 1, 0x1c, 0], &request.bytes).unwrap();
        assert_eq!(
            poll_result_once(&mut mock).unwrap().result,
            ApplicationResult::Pending
        );
        assert_eq!(
            poll_result_once(&mut mock).unwrap().result,
            ApplicationResult::Complete
        );

        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 1);
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET END   ")
                .count(),
            0
        );
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.len() == 31 && w[19..25] == [0x1c, 0, 0, 0, 0x14, 0])
                .count(),
            3
        );
    }

    #[test]
    fn provision_executes_start_once_then_one_set_and_pending_only_repolls() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = vec![];
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0); // START complete
        append_out_success(&mut reads);
        append_app_result(&mut reads, 1); // SET pending
        append_app_result(&mut reads, 0); // SET success
        let mut mock = stage_mock(reads);
        let mut delays = Vec::new();
        assert_eq!(
            provision(&mut mock, &request, Duration::from_secs(2), |d| delays
                .push(d)),
            Ok(ProvisionSuccess)
        );
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET START ")
                .count(),
            1
        );
        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 1);
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET END   ")
                .count(),
            0
        );
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.len() == 31 && w[19..25] == ResultPollRequest.cdb())
                .count(),
            3
        );
        assert_eq!(delays, [RESULT_POLL_INTERVAL]);
        assert_eq!(mock.writes[0][19..25], PossessionCommand::Start.cdb());
        assert_eq!(&mock.writes[1], b"SETUP NET START ");
        assert_eq!(mock.writes[3][19..25], WIFI_SET_CDB);
        assert_eq!(&mock.writes[4], request.bytes.as_slice());
    }

    #[test]
    fn start_application_result_ten_is_not_a_windows_retry_status() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = Vec::new();
        append_out_success(&mut reads);
        append_app_result(&mut reads, 10);
        let mut mock = stage_mock(reads);
        let error = provision(&mut mock, &request, Duration::from_secs(2), |_| {}).unwrap_err();
        assert_eq!(error, ProvisionFailure::StartDeviceResult(10));
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET START ")
                .count(),
            1
        );
        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 0);
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET END   ")
                .count(),
            0
        );
    }

    #[test]
    fn start_application_81_maps_to_windows_retry_status_and_never_sets_before_success() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = Vec::new();
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0x81);
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0);
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0);
        let mut mock = stage_mock(reads);
        let mut delays = Vec::new();
        assert_eq!(
            provision(&mut mock, &request, Duration::from_secs(2), |d| delays
                .push(d)),
            Ok(ProvisionSuccess)
        );
        assert_eq!(delays, [START_RETRY_INTERVAL]);
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET START ")
                .count(),
            2
        );
        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 1);
    }

    #[test]
    fn start_application_81_stops_after_fifteen_attempts_without_wifi_set() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = Vec::new();
        for _ in 0..MAX_START_ATTEMPTS {
            append_out_success(&mut reads);
            append_app_result(&mut reads, 0x81);
        }
        let mut mock = stage_mock(reads);
        let mut delays = Vec::new();
        assert_eq!(
            provision(&mut mock, &request, Duration::from_secs(2), |d| delays
                .push(d)),
            Err(ProvisionFailure::StartDeviceResult(0x81))
        );
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET START ")
                .count(),
            MAX_START_ATTEMPTS
        );
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.len() == 31 && w[19..25] == ResultPollRequest.cdb())
                .count(),
            MAX_START_ATTEMPTS
        );
        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 0);
        assert_eq!(delays, vec![START_RETRY_INTERVAL; MAX_START_ATTEMPTS - 1]);
    }

    #[test]
    fn start_unknown_result_does_not_retry_or_send_wifi_set_and_keeps_application_origin() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = Vec::new();
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0x83);
        let mut mock = stage_mock(reads);
        assert_eq!(
            provision(&mut mock, &request, Duration::from_secs(2), |_| {}),
            Err(ProvisionFailure::StartDeviceResult(0x83))
        );
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET START ")
                .count(),
            1
        );
        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 0);
    }

    #[test]
    fn debug_trace_separates_start_transport_status_from_application_byte_and_redacts_set() {
        let request = prepare_wpa2_psk("LabNet", b"supersecret123").unwrap();
        let mut reads = Vec::new();
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0x81);
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0);
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0);
        let mut mock = stage_mock(reads);
        let mut trace = protocol::ProtocolTrace::new(true);
        let result = provision_traced(
            &mut mock,
            &request,
            Duration::from_secs(2),
            |_| {},
            &mut trace,
        );
        assert_eq!(result, Ok(ProvisionSuccess));
        let joined = trace.lines.join("\n");
        assert!(joined.contains("transport status len=13"));
        assert!(joined.contains("application byte 0x81 maps to Windows possession status 2"));
        assert!(joined.contains("OUT data len=16 bytes=[53, 45, 54, 55, 50, 20, 4e, 45, 54, 20, 53, 54, 41, 52, 54, 20]"));
        assert!(joined.contains("OUT data len=284 bytes=<redacted>"));
        assert!(!joined.contains("supersecret123"));
    }

    #[test]
    fn start_pending_result_is_not_repolled_and_transport_failure_never_sets() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = vec![];
        append_out_success(&mut reads);
        append_app_result(&mut reads, 1);
        let mut timed_out = stage_mock(reads);
        assert_eq!(
            provision(&mut timed_out, &request, Duration::ZERO, |_| {}).unwrap_err(),
            ProvisionFailure::StartDeviceResult(1)
        );
        assert_eq!(
            timed_out
                .writes
                .iter()
                .filter(|w| w.len() == 31 && w[19..25] == ResultPollRequest.cdb())
                .count(),
            1
        );
        assert_eq!(
            timed_out.writes.iter().filter(|w| w.len() == 284).count(),
            0
        );

        let mut disconnected = stage_mock(vec![good_usb_status()]); // START write completed, Result-Poll read disconnects
        assert!(matches!(
            provision(&mut disconnected, &request, Duration::from_secs(2), |_| {}),
            Err(ProvisionFailure::StartTransport(_))
        ));
        assert_eq!(
            disconnected
                .writes
                .iter()
                .filter(|w| w.len() == 284)
                .count(),
            0
        );
    }

    #[test]
    fn wifi_timeout_device_errors_and_disconnect_never_retry_set_or_send_end() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        for code in [2, 10, 90] {
            let mut reads = vec![];
            append_out_success(&mut reads);
            append_app_result(&mut reads, 0);
            append_out_success(&mut reads);
            append_app_result(&mut reads, code);
            let mut mock = stage_mock(reads);
            assert_eq!(
                provision(&mut mock, &request, Duration::from_secs(2), |_| {}).unwrap_err(),
                ProvisionFailure::WifiApplicationResult(code)
            );
            assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 1);
            assert_eq!(
                mock.writes
                    .iter()
                    .filter(|w| w.as_slice() == b"SETUP NET END   ")
                    .count(),
                0
            );
        }

        let mut timeout_reads = vec![];
        append_out_success(&mut timeout_reads);
        append_app_result(&mut timeout_reads, 0);
        append_out_success(&mut timeout_reads);
        append_app_result(&mut timeout_reads, 1);
        let mut timed_out = stage_mock(timeout_reads);
        assert_eq!(
            provision(&mut timed_out, &request, Duration::ZERO, |_| {}).unwrap_err(),
            ProvisionFailure::ResultPollTimeout
        );
        assert_eq!(
            timed_out.writes.iter().filter(|w| w.len() == 284).count(),
            1
        );
        assert_eq!(
            timed_out
                .writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET END   ")
                .count(),
            0
        );

        let mut disconnect_reads = vec![];
        append_out_success(&mut disconnect_reads);
        append_app_result(&mut disconnect_reads, 0);
        // SET command/data were emitted, then the status read observes disconnect.
        let mut disconnected = stage_mock(disconnect_reads);
        assert!(matches!(
            provision(&mut disconnected, &request, Duration::from_secs(2), |_| {}),
            Err(ProvisionFailure::WifiSetTransport(_))
        ));
        assert_eq!(
            disconnected
                .writes
                .iter()
                .filter(|w| w.len() == 284)
                .count(),
            1
        );
    }

    #[test]
    fn set_check_condition_runs_sense_and_stops_without_retry_or_end() {
        let request = prepare_wpa2_psk("LabNet", b"12345678").unwrap();
        let mut reads = vec![];
        append_out_success(&mut reads);
        append_app_result(&mut reads, 0);
        reads.push(usb_status(2)); // SET transport CHECK CONDITION
        reads.push(vec![0; 18]);
        reads.push(good_usb_status());
        let mut mock = stage_mock(reads);
        assert!(matches!(
            provision(&mut mock, &request, Duration::from_secs(2), |_| {}),
            Err(ProvisionFailure::WifiSetTransport(_))
        ));
        assert_eq!(mock.writes.iter().filter(|w| w.len() == 284).count(), 1);
        assert_eq!(
            mock.writes
                .iter()
                .filter(|w| w.as_slice() == b"SETUP NET END   ")
                .count(),
            0
        );
        assert!(mock
            .writes
            .iter()
            .any(|w| w.len() == 31 && w[19..25] == [3, 0, 0, 0, 18, 0]));
    }

    #[test]
    fn possession_result_two_retries_start_after_200ms() {
        let mut mock = StageMock {
            writes: vec![],
            reads: vec![
                good_usb_status(),
                result_transfer(2),
                good_usb_status(),
                good_usb_status(),
                result_transfer(0),
                good_usb_status(),
            ]
            .into(),
            read_sizes: vec![],
        };
        let mut delays = vec![];
        let session =
            PossessionSession::acquire_with_sleep(&mut mock, Duration::from_secs(1), |d| {
                delays.push(d)
            })
            .unwrap();
        assert_eq!(session.state(), PossessionState::Active);
        assert_eq!(delays, [Duration::from_millis(200)]);
        assert_eq!(&mock.writes[1], b"SETUP NET START ");
        assert_eq!(&mock.writes[4], b"SETUP NET START ");
    }

    #[test]
    fn result_poll_state_machine_handles_completion_pending_timeout_and_errors() {
        let response = |code| {
            let mut bytes = [0; 20];
            bytes[0] = code;
            ResultPollResponse::parse(&bytes).unwrap()
        };
        let mut outcomes = [1, 0].into_iter();
        let complete = poll_result_bounded(3, || Ok(response(outcomes.next().unwrap()))).unwrap();
        assert_eq!(complete.result, ApplicationResult::Complete);

        let mut pending = 0;
        assert_eq!(
            poll_result_bounded(2, || {
                pending += 1;
                Ok(response(1))
            })
            .unwrap_err(),
            "Result-Poll timed out"
        );
        assert_eq!(pending, 2);
        assert_eq!(
            poll_result_bounded(2, || Ok(response(0x82))).unwrap_err(),
            "scanner application result 0x82"
        );
    }

    #[test]
    fn result_poll_transfer_has_distinct_20_and_13_byte_reads() {
        let mut mock = StageMock {
            writes: vec![],
            reads: vec![result_transfer(1), good_usb_status()].into(),
            read_sizes: vec![],
        };
        let response = poll_result_once(&mut mock).unwrap();
        assert_eq!(response.result, ApplicationResult::Pending);
        assert_eq!(mock.writes.len(), 1);
        assert_eq!(mock.writes[0].len(), 31);
        assert_eq!(&mock.writes[0][19..25], &[0x1c, 0, 0, 0, 0x14, 0]);
        assert_eq!(mock.read_sizes, [20, 13]);
    }

    #[test]
    fn result_poll_physical_loop_waits_between_pending_and_stops_at_deadline() {
        let mut pending_then_done = StageMock {
            writes: vec![],
            reads: vec![
                result_transfer(1),
                good_usb_status(),
                result_transfer(0),
                good_usb_status(),
            ]
            .into(),
            read_sizes: vec![],
        };
        assert_eq!(
            poll_result(&mut pending_then_done, Duration::from_secs(2))
                .unwrap()
                .result,
            ApplicationResult::Complete
        );
        assert_eq!(pending_then_done.writes.len(), 2);

        let mut timed_out = StageMock {
            writes: vec![],
            reads: vec![result_transfer(1), good_usb_status()].into(),
            read_sizes: vec![],
        };
        assert_eq!(
            poll_result(&mut timed_out, Duration::ZERO).unwrap_err(),
            "Result-Poll timed out"
        );
        assert_eq!(timed_out.writes.len(), 1);
    }

    #[test]
    fn result_poll_transfer_handles_success_device_error_and_short_data() {
        let mut success = StageMock {
            writes: vec![],
            reads: vec![result_transfer(0), good_usb_status()].into(),
            read_sizes: vec![],
        };
        assert_eq!(
            poll_result_once(&mut success).unwrap().result,
            ApplicationResult::Complete
        );

        let mut failure = StageMock {
            writes: vec![],
            reads: vec![result_transfer(0x82), good_usb_status()].into(),
            read_sizes: vec![],
        };
        assert_eq!(
            poll_result_once(&mut failure).unwrap().result,
            ApplicationResult::DeviceError(0x82)
        );

        let mut short = StageMock {
            writes: vec![],
            reads: vec![vec![1; 19], good_usb_status()].into(),
            read_sizes: vec![],
        };
        assert!(poll_result_once(&mut short)
            .unwrap_err()
            .contains("short application data"));
        assert_eq!(short.read_sizes, [20, 13]);

        let mut inline_status = good_usb_status();
        inline_status[9] = 0;
        let mut status_only = StageMock {
            writes: vec![],
            reads: vec![inline_status].into(),
            read_sizes: vec![],
        };
        assert!(poll_result_once(&mut status_only)
            .unwrap_err()
            .contains("application data is absent"));
        assert_eq!(status_only.read_sizes, [20]);

        let mut short_status = StageMock {
            writes: vec![],
            reads: vec![result_transfer(0), vec![0x53; 12]].into(),
            read_sizes: vec![],
        };
        assert!(poll_result_once(&mut short_status)
            .unwrap_err()
            .contains("short USB status transfer"));
        assert_eq!(short_status.read_sizes, [20, 13]);
    }

    #[test]
    fn possession_cancel_failure_keeps_session_active_for_explicit_retry() {
        let mut mock = StageMock {
            writes: vec![],
            reads: vec![good_usb_status(), result_transfer(0x82), good_usb_status()].into(),
            read_sizes: vec![],
        };
        let mut session = PossessionSession {
            state: PossessionState::Active,
        };
        assert!(session
            .cancel(&mut mock, Duration::from_secs(1))
            .unwrap_err()
            .contains("0x82"));
        assert_eq!(session.state(), PossessionState::Active);
        assert_eq!(&mock.writes[1], b"SETUP NET END   ");
    }

    #[test]
    fn result_poll_transport_check_condition_runs_sense_sequence() {
        let mut check = good_usb_status();
        check[9] = 2;
        let sense = vec![
            0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0,
        ];
        let mut mock = StageMock {
            writes: vec![],
            reads: vec![result_transfer(0), check, sense, good_usb_status()].into(),
            read_sizes: vec![],
        };
        assert!(poll_result_once(&mut mock)
            .unwrap_err()
            .contains("CHECK CONDITION"));
        assert_eq!(mock.writes.len(), 2);
        assert_eq!(&mock.writes[1][19..25], &[3, 0, 0, 0, 0x12, 0]);
        assert_eq!(mock.read_sizes, [20, 13, 18, 13]);
    }

    #[test]
    fn reconstructed_wifi_request_maps_to_usb_out_phase_byte_for_byte() {
        let request = prepare_wpa2_psk("TestNet", b"abcdefgh").unwrap();
        let cdb = diagnostic_cdb(0x1d, request.bytes.len()).unwrap();
        let mut status_packet = [0u8; 13];
        status_packet[0] = 0x53;
        let mut mock = MockUsb {
            writes: vec![],
            reads: vec![status_packet.to_vec()].into(),
        };
        protocol::scsi_write(&mut mock, &cdb, &request.bytes).unwrap();
        assert_eq!(&mock.writes[0][19..25], &[0x1d, 0, 0, 1, 0x1c, 0]);
        assert_eq!(mock.writes[1], request.bytes);
        assert_eq!(mock.writes[1].len(), 0x11c);
    }
}
