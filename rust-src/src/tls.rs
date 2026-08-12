#[cfg(feature = "tls")]
use native_tls::TlsConnector;

#[cfg(feature = "tls")]
use std::fs::OpenOptions;
#[cfg(feature = "tls")]
use std::io::Write;
#[cfg(feature = "tls")]
use std::time::Duration;

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
    /// Create a new TLS configuration with secure defaults
    pub fn new() -> Self {
        let new_msg = "[TLS] Creating new TlsConfig with secure defaults";
        eprintln!("{}", new_msg);
        #[cfg(feature = "std")]
        log_to_file(new_msg);
        
        Self {
            verify_certs: true,
            min_protocol: TlsProtocol::Tls1_2,
            max_protocol: TlsProtocol::Auto,
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
        let msg = "[TLS] Creating legacy-compatible TlsConfig for old systems";
        eprintln!("{}", msg);
        #[cfg(feature = "std")]
        log_to_file(msg);
        
        Self {
            verify_certs: false, // Disable cert verification for old systems
            min_protocol: TlsProtocol::Tls1_0,
            max_protocol: TlsProtocol::Auto,
            use_sni: true,
            handshake_timeout: Duration::from_secs(30),
            danger_accept_invalid_hostnames: true, // Accept invalid hostnames for old systems
            danger_accept_invalid_certs: true, // Accept invalid certs for old systems
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
        let native_protocol = match self.min_protocol {
            TlsProtocol::Auto => None,
            TlsProtocol::Tls1_0 => Some(native_tls::Protocol::Tlsv10),
            TlsProtocol::Tls1_1 => Some(native_tls::Protocol::Tlsv11),
            TlsProtocol::Tls1_2 => Some(native_tls::Protocol::Tlsv12),
            TlsProtocol::Tls1_3 => Some(native_tls::Protocol::Tlsv13),
        };
        
        let protocol_msg = format!("[TLS] Mapping min_protocol {:?} to native_tls {:?}", self.min_protocol, native_protocol);
        eprintln!("{}", protocol_msg);
        #[cfg(feature = "std")]
        log_to_file(&protocol_msg);
        
        // CRITICAL FIX: For Windows 2000 compatibility, we must set max_protocol to TLS 1.0
        // This forces the schannel crate to use the older SCHANNEL_CRED interface instead of
        // the newer SCH_CREDENTIALS interface which requires Windows 10+ APIs
        let native_max_protocol = match self.min_protocol {
            TlsProtocol::Auto => Some(native_tls::Protocol::Tlsv10), // Force TLS 1.0 max for Windows 2000
            TlsProtocol::Tls1_0 => Some(native_tls::Protocol::Tlsv10),
            TlsProtocol::Tls1_1 => Some(native_tls::Protocol::Tlsv11),
            TlsProtocol::Tls1_2 => Some(native_tls::Protocol::Tlsv12),
            TlsProtocol::Tls1_3 => Some(native_tls::Protocol::Tlsv13),
        };
        
        let max_protocol_msg = format!("[TLS] Setting max protocol to {:?} to force legacy Schannel interface", native_max_protocol);
        eprintln!("{}", max_protocol_msg);
        #[cfg(feature = "std")]
        log_to_file(&max_protocol_msg);
        
        if let Some(protocol) = native_protocol {
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
            Ok(connector) => {
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
        Self::new()
    }
}

#[cfg(not(feature = "tls"))]
pub struct TlsConfig;

#[cfg(not(feature = "tls"))]
impl TlsConfig {
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
