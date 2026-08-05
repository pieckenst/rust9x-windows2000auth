#[cfg(feature = "tls")]
use native_tls::TlsConnector;

#[cfg(feature = "tls")]
use std::fs::OpenOptions;
#[cfg(feature = "tls")]
use std::io::Write;

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

/// TLS configuration for HTTPS connections
#[cfg(feature = "tls")]
pub struct TlsConfig {
    pub verify_certs: bool,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    pub fn new() -> Self {
        let new_msg = "[TLS] Creating new TlsConfig with default settings";
        eprintln!("{}", new_msg);
        #[cfg(feature = "std")]
        log_to_file(new_msg);
        
        Self {
            verify_certs: true,
        }
    }

    pub fn with_cert_verification(mut self, verify: bool) -> Self {
        let verify_msg = format!("[TLS] Setting cert verification to: {}", verify);
        eprintln!("{}", verify_msg);
        #[cfg(feature = "std")]
        log_to_file(&verify_msg);
        
        self.verify_certs = verify;
        self
    }

    pub fn build_connector(&self) -> native_tls::Result<TlsConnector> {
        let build_msg = "[TLS] Building TLS connector";
        eprintln!("{}", build_msg);
        #[cfg(feature = "std")]
        log_to_file(build_msg);
        
        let mut builder = TlsConnector::builder();
        if !self.verify_certs {
            let warning_msg = "[TLS] WARNING: Certificate verification disabled - accepting invalid certs";
            eprintln!("{}", warning_msg);
            #[cfg(feature = "std")]
            log_to_file(warning_msg);
            
            builder.danger_accept_invalid_certs(true);
        }
        
        let result = builder.build();
        match &result {
            Ok(_) => {
                let success_msg = "[TLS] TLS connector built successfully";
                eprintln!("{}", success_msg);
                #[cfg(feature = "std")]
                log_to_file(success_msg);
            }
            Err(e) => {
                let error_msg = format!("[TLS] Failed to build TLS connector: {}", e);
                eprintln!("{}", error_msg);
                #[cfg(feature = "std")]
                log_to_file(&error_msg);
            }
        }
        
        result
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
}
