/// TLS configuration module with automatic OS version detection
///
/// This module provides TLS configuration for HTTPS connections with intelligent
/// OS version detection to automatically select the appropriate TLS settings:
///
/// - **Windows 2000/XP/Server 2003**: Automatically uses legacy configuration
///   with TLS 1.0 forced, certificate verification disabled, and SNI disabled
///   (SNI not supported on Windows 2000)
/// - **Windows Vista and later**: Automatically uses modern configuration with
///   TLS 1.2 minimum, Auto maximum, certificate verification enabled, and SNI enabled
///
/// # Usage
///
/// ```rust
/// // Automatically select configuration based on OS version
/// let config = TlsConfig::auto();
///
/// // Explicitly choose modern configuration (for Vista+)
/// let config = TlsConfig::new();
///
/// // Explicitly choose legacy configuration (for Windows 2000/XP)
/// let config = TlsConfig::legacy();
/// ```
#[cfg(feature = "tls")]
use native_tls::TlsConnector;

#[cfg(feature = "tls")]
use std::fs::OpenOptions;
#[cfg(feature = "tls")]
use std::io::Write;
#[cfg(feature = "tls")]
use std::time::Duration;

#[cfg(all(feature = "tls", target_os = "windows"))]
use windows_sys::Win32::Foundation::HMODULE;

#[cfg(all(feature = "tls", target_os = "windows"))]
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW,
    GetProcAddress,
};

#[cfg(all(feature = "tls", target_os = "windows"))]
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

#[cfg(all(feature = "tls", target_os = "windows"))]
use core::mem;

#[cfg(feature = "tls")]
fn log_to_file(message: &str) {
    let log_path = "E:\\code\\rust9x-windows2000auth\\rust-src\\tls_log.txt";
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

#[cfg(all(feature = "tls", target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

#[cfg(all(feature = "tls", target_os = "windows"))]
impl OsVersion {
    pub fn detect() -> Option<Self> {
        unsafe {
            let ntdll: HMODULE = GetModuleHandleW(windows_sys::w!("ntdll.dll"));

            if ntdll.is_null() {
                let msg = "[OS_DETECT] GetModuleHandleW(ntdll.dll) failed";
                eprintln!("{}", msg);
                log_to_file(msg);
                return None;
            }

            let proc = GetProcAddress(ntdll, windows_sys::s!("RtlGetVersion"));

            let proc = match proc {
                Some(proc) => proc,
                None => {
                    let msg = "[OS_DETECT] GetProcAddress(RtlGetVersion) failed";
                    eprintln!("{}", msg);
                    log_to_file(msg);
                    return None;
                }
            };

            type RtlGetVersionFn =
                unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;

            let rtl_get_version: RtlGetVersionFn = mem::transmute(proc as *const ());

            let mut info: OSVERSIONINFOW = mem::zeroed();
            info.dwOSVersionInfoSize =
                mem::size_of::<OSVERSIONINFOW>() as u32;

            let status = rtl_get_version(&mut info);

            if status != 0 {
                let msg = format!(
                    "[OS_DETECT] RtlGetVersion failed: NTSTATUS=0x{:08X}",
                    status as u32
                );
                eprintln!("{}", msg);
                log_to_file(&msg);
                return None;
            }

            let version = OsVersion {
                major: info.dwMajorVersion,
                minor: info.dwMinorVersion,
                build: info.dwBuildNumber,
            };

            let msg = format!(
                "[OS_DETECT] RtlGetVersion -> {}.{}.{}",
                version.major,
                version.minor,
                version.build
            );

            eprintln!("{}", msg);
            log_to_file(&msg);

            Some(version)
        }
    }
}

/// Windows OS version classification for TLS configuration.
#[cfg(all(feature = "tls", target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsVersion {
    /// Windows 2000 or earlier (major version 5, minor version 0)
    Windows2000,
    /// Windows XP (major version 5, minor version 1)
    WindowsXP,
    /// Windows Server 2003 / XP x64 (major version 5, minor version 2)
    WindowsServer2003,
    /// Windows Vista / Server 2008 (major version 6, minor version 0)
    WindowsVista,
    /// Windows 7 / Server 2008 R2 (major version 6, minor version 1)
    Windows7,
    /// Windows 8 / Server 2012 (major version 6, minor version 2)
    Windows8,
    /// Windows 8.1 / Server 2012 R2 (major version 6, minor version 3)
    Windows81,
    /// Windows 10 / Server 2016+ (major version 10 or higher)
    Windows10OrLater,
    /// Unknown version
    Unknown,
}

#[cfg(all(feature = "tls", target_os = "windows"))]
impl WindowsVersion {
    /// Detect the real Windows version using RtlGetVersion.
    pub fn detect() -> Self {
        let version = match OsVersion::detect() {
            Some(version) => version,
            None => {
                return WindowsVersion::Unknown;
            }
        };

        match (version.major, version.minor) {
            (5, 0) => WindowsVersion::Windows2000,
            (5, 1) => WindowsVersion::WindowsXP,
            (5, 2) => WindowsVersion::WindowsServer2003,
            (6, 0) => WindowsVersion::WindowsVista,
            (6, 1) => WindowsVersion::Windows7,
            (6, 2) => WindowsVersion::Windows8,
            (6, 3) => WindowsVersion::Windows81,
            (10, _) => WindowsVersion::Windows10OrLater,
            (major, _) if major >= 11 => WindowsVersion::Windows10OrLater,
            _ => WindowsVersion::Unknown,
        }
    }

    pub fn requires_legacy_tls(&self) -> bool {
        matches!(
            self,
            WindowsVersion::Windows2000
                | WindowsVersion::WindowsXP
                | WindowsVersion::WindowsServer2003
        )
    }

    pub fn supports_sni(&self) -> bool {
        !matches!(self, WindowsVersion::Windows2000)
    }
}

#[cfg(all(feature = "tls", not(target_os = "windows")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsVersion {
    Unknown,
}

#[cfg(all(feature = "tls", not(target_os = "windows")))]
impl WindowsVersion {
    pub fn detect() -> Self {
        WindowsVersion::Unknown
    }

    pub fn requires_legacy_tls(&self) -> bool {
        false
    }

    pub fn supports_sni(&self) -> bool {
        true
    }
}

/// TLS protocol versions for configuration
#[cfg(feature = "tls")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProtocol {
    /// Auto-negotiate the highest supported protocol
    Auto,
    /// TLS 1.0 (deprecated, should only be used for legacy compatibility)
    Tls1_0,
    /// TLS 1.1 (deprecated, should only be used for legacy compatibility)
    Tls1_1,
    /// TLS 1.2 (recommended minimum)
    Tls1_2,
    /// TLS 1.3 (most secure, when available)
    Tls1_3,
}

#[cfg(feature = "tls")]
impl Default for TlsProtocol {
    fn default() -> Self {
        Self::Auto
    }
}

/// TLS configuration for HTTPS connections with robust settings
#[cfg(feature = "tls")]
pub struct TlsConfig {
    /// Whether to verify server certificates
    pub verify_certs: bool,
    /// Minimum TLS protocol version to accept
    pub min_protocol: TlsProtocol,
    /// Maximum TLS protocol version to accept
    pub max_protocol: TlsProtocol,
    /// Whether to use SNI (Server Name Indication)
    pub use_sni: bool,
    /// Connection timeout for TLS handshake
    pub handshake_timeout: Duration,
    /// Whether to accept invalid hostnames (dangerous)
    pub danger_accept_invalid_hostnames: bool,
    /// Whether to accept any certificate (dangerous)
    pub danger_accept_invalid_certs: bool,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// Create a TLS configuration automatically selected based on OS version
   pub fn auto() -> Self {
        let version = WindowsVersion::detect();

        let msg = format!(
            "[TLS] Auto-selecting config based on OS version: {:?}",
            version
        );

        eprintln!("{}", msg);
        log_to_file(&msg);

        if version.requires_legacy_tls() {
            let legacy_msg =
                "[TLS] OS requires legacy TLS configuration";

            eprintln!("{}", legacy_msg);
            log_to_file(legacy_msg);

            Self::legacy_for(version)
        } else {
            let modern_msg =
                "[TLS] OS uses modern TLS configuration";

            eprintln!("{}", modern_msg);
            log_to_file(modern_msg);

            Self::new()
        }
    }

    /// Create a new TLS configuration with secure defaults
    pub fn new() -> Self {
        let new_msg = "[TLS] Creating new TlsConfig with secure defaults";
        eprintln!("{}", new_msg);
        #[cfg(feature = "std")]
        log_to_file(new_msg);
        
        Self {
            verify_certs: true,
            min_protocol: TlsProtocol::Auto,
            max_protocol: TlsProtocol::Tls1_2,
            use_sni: true,
            handshake_timeout: Duration::from_secs(30),
            danger_accept_invalid_hostnames: false,
            danger_accept_invalid_certs: false,
        }
    }

    /// Create a lenient TLS configuration for development/testing
    pub fn lenient() -> Self {
        let msg = "[TLS] Creating lenient TlsConfig for development/testing";
        eprintln!("{}", msg);
        #[cfg(feature = "std")]
        log_to_file(msg);
        
        Self {
            verify_certs: false,
            min_protocol: TlsProtocol::Auto,
            max_protocol: TlsProtocol::Auto,
            use_sni: true,
            handshake_timeout: Duration::from_secs(30),
            danger_accept_invalid_hostnames: true,
            danger_accept_invalid_certs: true,
        }
    }

    /// Create a legacy-compatible TLS configuration for old systems
    pub fn legacy() -> Self {
        let version = WindowsVersion::detect();
        Self::legacy_for(version)
    }

    fn legacy_for(version: WindowsVersion) -> Self {
        let msg = format!(
            "[TLS] Creating legacy-compatible configuration for {:?}",
            version
        );

        eprintln!("{}", msg);
        log_to_file(&msg);

        let use_sni = version.supports_sni();

        let sni_msg = format!(
            "[TLS] Legacy configuration SNI enabled: {}",
            use_sni
        );

        eprintln!("{}", sni_msg);
        log_to_file(&sni_msg);

        Self {
            verify_certs: false,
            min_protocol: TlsProtocol::Tls1_0,
            max_protocol: TlsProtocol::Tls1_0,
            use_sni,
            handshake_timeout: Duration::from_secs(30),
            danger_accept_invalid_hostnames: true,
            danger_accept_invalid_certs: true,
        }
    }

    /// Set certificate verification
    pub fn with_cert_verification(mut self, verify: bool) -> Self {
        let verify_msg = format!("[TLS] Setting cert verification to: {}", verify);
        eprintln!("{}", verify_msg);
        #[cfg(feature = "std")]
        log_to_file(&verify_msg);
        
        self.verify_certs = verify;
        self
    }

    /// Set minimum TLS protocol version
    pub fn with_min_protocol(mut self, protocol: TlsProtocol) -> Self {
        let proto_msg = format!("[TLS] Setting minimum protocol to: {:?}", protocol);
        eprintln!("{}", proto_msg);
        #[cfg(feature = "std")]
        log_to_file(&proto_msg);
        
        self.min_protocol = protocol;
        self
    }

    /// Set maximum TLS protocol version
    pub fn with_max_protocol(mut self, protocol: TlsProtocol) -> Self {
        let proto_msg = format!("[TLS] Setting maximum protocol to: {:?}", protocol);
        eprintln!("{}", proto_msg);
        #[cfg(feature = "std")]
        log_to_file(&proto_msg);
        
        self.max_protocol = protocol;
        self
    }

    /// Enable or disable SNI
    pub fn with_sni(mut self, use_sni: bool) -> Self {
        let sni_msg = format!("[TLS] Setting SNI to: {}", use_sni);
        eprintln!("{}", sni_msg);
        #[cfg(feature = "std")]
        log_to_file(&sni_msg);
        
        self.use_sni = use_sni;
        self
    }

    /// Set handshake timeout
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        let timeout_msg = format!("[TLS] Setting handshake timeout to: {:?}", timeout);
        eprintln!("{}", timeout_msg);
        #[cfg(feature = "std")]
        log_to_file(&timeout_msg);
        
        self.handshake_timeout = timeout;
        self
    }

    /// Danger: Accept invalid hostnames (for testing only)
    pub fn danger_accept_invalid_hostnames(mut self, accept: bool) -> Self {
        let warning_msg = format!("[TLS] WARNING: Setting accept invalid hostnames to: {} (DANGEROUS)", accept);
        eprintln!("{}", warning_msg);
        #[cfg(feature = "std")]
        log_to_file(&warning_msg);
        
        self.danger_accept_invalid_hostnames = accept;
        self
    }

    /// Danger: Accept invalid certificates (for testing only)
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        let warning_msg = format!("[TLS] WARNING: Setting accept invalid certs to: {} (DANGEROUS)", accept);
        eprintln!("{}", warning_msg);
        #[cfg(feature = "std")]
        log_to_file(&warning_msg);
        
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Build the TLS connector with current configuration
    pub fn build_connector(&self) -> native_tls::Result<TlsConnector> {
        let build_msg = "[TLS] Building TLS connector with current configuration";
        eprintln!("{}", build_msg);
        #[cfg(feature = "std")]
        log_to_file(build_msg);
        
        let config_msg = format!(
            "[TLS] Configuration: verify_certs={}, min_protocol={:?}, max_protocol={:?}, use_sni={}, timeout={:?}",
            self.verify_certs, self.min_protocol, self.max_protocol, self.use_sni, self.handshake_timeout
        );
        eprintln!("{}", config_msg);
        #[cfg(feature = "std")]
        log_to_file(&config_msg);
        
        let mut builder = TlsConnector::builder();
        
        // Map our TlsProtocol to native_tls Protocol
        let native_min_protocol = match self.min_protocol {
            TlsProtocol::Auto => None,
            TlsProtocol::Tls1_0 => Some(native_tls::Protocol::Tlsv10),
            TlsProtocol::Tls1_1 => Some(native_tls::Protocol::Tlsv11),
            TlsProtocol::Tls1_2 => Some(native_tls::Protocol::Tlsv12),
            TlsProtocol::Tls1_3 => Some(native_tls::Protocol::Tlsv13),
        };
        
        let native_max_protocol = match self.max_protocol {
            TlsProtocol::Auto => None,
            TlsProtocol::Tls1_0 => Some(native_tls::Protocol::Tlsv10),
            TlsProtocol::Tls1_1 => Some(native_tls::Protocol::Tlsv11),
            TlsProtocol::Tls1_2 => Some(native_tls::Protocol::Tlsv12),
            TlsProtocol::Tls1_3 => Some(native_tls::Protocol::Tlsv13),
        };
        
        let min_protocol_msg = format!("[TLS] Mapping min_protocol {:?} to native_tls {:?}", self.min_protocol, native_min_protocol);
        eprintln!("{}", min_protocol_msg);
        #[cfg(feature = "std")]
        log_to_file(&min_protocol_msg);
        
        let max_protocol_msg = format!("[TLS] Mapping max_protocol {:?} to native_tls {:?}", self.max_protocol, native_max_protocol);
        eprintln!("{}", max_protocol_msg);
        #[cfg(feature = "std")]
        log_to_file(&max_protocol_msg);
        
        if let Some(protocol) = native_min_protocol {
            let set_proto_msg = format!("[TLS] Setting minimum protocol to {:?}", protocol);
            eprintln!("{}", set_proto_msg);
            #[cfg(feature = "std")]
            log_to_file(&set_proto_msg);
            
            builder.min_protocol_version(Some(protocol));
        }
        
        if let Some(protocol) = native_max_protocol {
            let set_max_proto_msg = format!("[TLS] Setting maximum protocol to {:?}", protocol);
            eprintln!("{}", set_max_proto_msg);
            #[cfg(feature = "std")]
            log_to_file(&set_max_proto_msg);
            
            builder.max_protocol_version(Some(protocol));
        }
        
        // Set certificate verification
        if !self.verify_certs || self.danger_accept_invalid_certs {
            let warning_msg = "[TLS] WARNING: Certificate verification disabled or invalid certs accepted";
            eprintln!("{}", warning_msg);
            #[cfg(feature = "std")]
            log_to_file(warning_msg);
            
            builder.danger_accept_invalid_certs(true);
        }
        
        // Set hostname verification
        if self.danger_accept_invalid_hostnames {
            let warning_msg = "[TLS] WARNING: Invalid hostname acceptance enabled";
            eprintln!("{}", warning_msg);
            #[cfg(feature = "std")]
            log_to_file(warning_msg);
            
            builder.danger_accept_invalid_hostnames(true);
        }
        
        // SNI is enabled by default in native_tls
        if !self.use_sni {
            let sni_msg = "[TLS] SNI disabled (native_tls uses SNI by default, this may not have effect)";
            eprintln!("{}", sni_msg);
            #[cfg(feature = "std")]
            log_to_file(sni_msg);
            
            builder.use_sni(false);
        }
        
        let result = builder.build();
        match &result {
            Ok(_connector) => {
                let success_msg = "[TLS] TLS connector built successfully";
                eprintln!("{}", success_msg);
                #[cfg(feature = "std")]
                log_to_file(success_msg);
                
                // Log connector details if possible
                let details_msg = format!("[TLS] Connector ready for secure connections");
                eprintln!("{}", details_msg);
                #[cfg(feature = "std")]
                log_to_file(&details_msg);
            }
            Err(e) => {
                let error_msg = format!("[TLS] Failed to build TLS connector: {}", e);
                eprintln!("{}", error_msg);
                #[cfg(feature = "std")]
                log_to_file(&error_msg);
                
                // Provide more detailed error information
                let error_details = format!("[TLS] Error details: description={}", e);
                eprintln!("{}", error_details);
                #[cfg(feature = "std")]
                log_to_file(&error_details);
            }
        }
        
        result
    }

    /// Validate the current configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.danger_accept_invalid_certs && self.verify_certs {
            return Err("Cannot have both verify_certs=true and danger_accept_invalid_certs=true".to_string());
        }
        
        if self.danger_accept_invalid_hostnames && self.verify_certs {
            return Err("Cannot have both verify_certs=true and danger_accept_invalid_hostnames=true".to_string());
        }
        
        if self.handshake_timeout.as_secs() == 0 {
            return Err("Handshake timeout must be greater than 0".to_string());
        }
        
        let validation_msg = "[TLS] Configuration validation passed";
        eprintln!("{}", validation_msg);
        #[cfg(feature = "std")]
        log_to_file(validation_msg);
        
        Ok(())
    }
}

#[cfg(feature = "tls")]
impl Default for TlsConfig {
    fn default() -> Self {
        Self::auto()
    }
}

#[cfg(not(feature = "tls"))]
pub struct TlsConfig;

#[cfg(not(feature = "tls"))]
impl TlsConfig {
    pub fn auto() -> Self {
        eprintln!("[TLS] TLS feature not enabled - using stub TlsConfig");
        Self
    }

    pub fn new() -> Self {
        eprintln!("[TLS] TLS feature not enabled - using stub TlsConfig");
        Self
    }

    pub fn lenient() -> Self {
        eprintln!("[TLS] TLS feature not enabled - using stub TlsConfig");
        Self
    }

    pub fn legacy() -> Self {
        eprintln!("[TLS] TLS feature not enabled - using stub TlsConfig");
        Self
    }
}

#[cfg(not(feature = "tls"))]
impl Default for TlsConfig {
    fn default() -> Self {
        Self::auto()
    }
}
