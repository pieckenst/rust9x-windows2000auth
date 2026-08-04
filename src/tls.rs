#[cfg(feature = "tls")]
use native_tls::TlsConnector;

/// TLS configuration for HTTPS connections
#[cfg(feature = "tls")]
pub struct TlsConfig {
    pub verify_certs: bool,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    pub fn new() -> Self {
        Self {
            verify_certs: true,
        }
    }

    pub fn with_cert_verification(mut self, verify: bool) -> Self {
        self.verify_certs = verify;
        self
    }

    pub fn build_connector(&self) -> native_tls::Result<TlsConnector> {
        let mut builder = TlsConnector::builder();
        if !self.verify_certs {
            builder.danger_accept_invalid_certs(true);
        }
        builder.build()
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
        Self
    }
}
