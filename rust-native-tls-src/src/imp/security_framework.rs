use security_framework::base;
use security_framework::certificate::SecCertificate;
use security_framework::identity::SecIdentity;
use security_framework::import_export::{ImportedIdentity, Pkcs12ImportOptions};
#[cfg(target_os = "macos")]
use security_framework::random::SecRandom;
use security_framework::secure_transport::{
    self, ClientBuilder, SslConnectionType, SslContext, SslProtocol, SslProtocolSide,
};
#[cfg(target_os = "macos")]
use security_framework_sys::base::errSecIO;
#[cfg(any(feature = "alpn", target_os = "macos"))]
use security_framework_sys::base::errSecParam;
#[cfg(target_os = "macos")]
use std::sync::{Mutex, Once};
use std::{error, fmt, io, str};

#[cfg(target_os = "macos")]
use security_framework::os::macos::certificate::{PropertyType, SecCertificateExt};
#[cfg(target_os = "macos")]
use security_framework::os::macos::certificate_oids::CertificateOid;
#[cfg(target_os = "macos")]
use security_framework::os::macos::identity::SecIdentityExt;
#[cfg(target_os = "macos")]
use security_framework::os::macos::import_export::{
    ImportOptions, Pkcs12ImportOptionsExt, SecItems,
};
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::{self, KeychainSettings, SecKeychain};

use crate::{Protocol, TlsAcceptorBuilder, TlsConnectorBuilder};
use log::{debug, error, info, trace, warn};

#[cfg(target_os = "macos")]
static SET_AT_EXIT: Once = Once::new();

#[cfg(target_os = "macos")]
static TEMP_KEYCHAIN: Mutex<Option<(SecKeychain, tempfile::TempDir)>> = Mutex::new(None);

fn convert_protocol(protocol: Protocol) -> SslProtocol {
    match protocol {
        Protocol::Sslv3 => SslProtocol::SSL3,
        Protocol::Tlsv10 => SslProtocol::TLS1,
        Protocol::Tlsv11 => SslProtocol::TLS11,
        Protocol::Tlsv12 => SslProtocol::TLS12,
        Protocol::Tlsv13 => SslProtocol::TLS13,
    }
}

pub struct Error(base::Error);

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        error::Error::source(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl From<base::Error> for Error {
    fn from(error: base::Error) -> Error {
        Error(error)
    }
}

#[derive(Clone, Debug)]
pub struct Identity {
    identity: SecIdentity,
    chain: Vec<SecCertificate>,
}

impl Identity {
    #[cfg(not(target_os = "macos"))]
    pub fn from_pkcs8(_: &[u8], _: &[u8]) -> Result<Identity, Error> {
        panic!("Not implemented on iOS");
    }

    #[cfg(target_os = "macos")]
    pub fn from_pkcs8(pem: &[u8], key: &[u8]) -> Result<Identity, Error> {
        info!("Identity::from_pkcs8 called with {} bytes of PEM data and {} bytes of key data", pem.len(), key.len());
        if !key.starts_with(b"-----BEGIN PRIVATE KEY-----") {
            error!("Key is not in PKCS#8 format");
            return Err(Error(base::Error::from(errSecParam)));
        }

        let dir = tempfile::TempDir::new().map_err(|_| Error(base::Error::from(errSecIO)))?;
        debug!("Created temporary directory");
        let keychain = keychain::CreateOptions::new()
            .password(&random_password()?)
            .create(dir.path().join("identity.keychain"))?;
        debug!("Created temporary keychain");

        let mut items = SecItems::default();

        debug!("Importing private key");
        ImportOptions::new()
            .filename("key.pem")
            .items(&mut items)
            .keychain(&keychain)
            .import(key)?;

        debug!("Importing certificate chain");
        ImportOptions::new()
            .filename("chain.pem")
            .items(&mut items)
            .keychain(&keychain)
            .import(pem)?;

        let cert = items
            .certificates
            .first()
            .ok_or_else(|| Error(base::Error::from(errSecParam)))?;
        debug!("Creating identity from certificate");
        let ident = SecIdentity::with_certificate(&[keychain], cert)?;
        info!("Identity created successfully from PKCS#8");
        Ok(Identity {
            identity: ident,
            chain: items.certificates.into_iter().skip(1).collect(),
        })
    }

    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        info!("Identity::from_pkcs12 called with {} bytes of PKCS#12 data", buf.len());
        let mut imports = Identity::import_options(buf, pass)?;
        debug!("PKCS#12 imported successfully");
        let import = imports.pop().unwrap();

        let identity = import
            .identity
            .expect("Pkcs12 files must include an identity");
        debug!("Extracted identity from PKCS#12");

        // FIXME: Compare the certificates for equality using CFEqual
        let identity_cert = identity.certificate()?.to_der();

        let chain = import
                .cert_chain
                .unwrap_or(vec![])
                .into_iter()
                .filter(|c| c.to_der() != identity_cert)
                .collect();
        debug!("Certificate chain has {} certificates", chain.len());
        info!("Identity created successfully from PKCS#12");
        Ok(Identity {
            identity,
            chain,
        })
    }

    #[cfg(target_os = "macos")]
    fn import_options(buf: &[u8], pass: &str) -> Result<Vec<ImportedIdentity>, Error> {
        SET_AT_EXIT.call_once(|| {
            extern "C" fn atexit() {
                *TEMP_KEYCHAIN.lock().unwrap() = None;
            }
            unsafe {
                libc::atexit(atexit);
            }
        });

        // keep it locked during import()
        let keychain = &mut *TEMP_KEYCHAIN.lock().unwrap();

        let keychain = match keychain {
            Some((keychain, _)) => keychain.clone(),
            lock @ None => {
                let dir =
                    tempfile::TempDir::new().map_err(|_| Error(base::Error::from(errSecIO)))?;

                let mut keychain = keychain::CreateOptions::new()
                    .password(pass)
                    .create(dir.path().join("tmp.keychain"))?;
                keychain.set_settings(&KeychainSettings::new())?;

                *lock = Some((keychain.clone(), dir));
                keychain
            }
        };
        let mut import_opts = Pkcs12ImportOptions::new();
        // Method shadowed by deprecated method.
        <Pkcs12ImportOptions as Pkcs12ImportOptionsExt>::keychain(&mut import_opts, keychain);
        let imports = import_opts.passphrase(pass).import(buf)?;
        Ok(imports)
    }

    #[cfg(not(target_os = "macos"))]
    fn import_options(buf: &[u8], pass: &str) -> Result<Vec<ImportedIdentity>, Error> {
        let imports = Pkcs12ImportOptions::new().passphrase(pass).import(buf)?;
        Ok(imports)
    }
}

#[cfg(target_os = "macos")]
fn random_password() -> Result<String, Error> {
    use std::fmt::Write;
    let mut bytes = [0_u8; 10];
    SecRandom::default()
        .copy_bytes(&mut bytes)
        .map_err(|_| Error(base::Error::from(errSecIO)))?;
    let mut s = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(s, "{byte:02X}").map_err(|_| Error(base::Error::from(errSecIO)))?;
    }
    Ok(s)
}

#[derive(Clone)]
pub struct Certificate(SecCertificate);

impl Certificate {
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        debug!("Certificate::from_der called with {} bytes of DER data", buf.len());
        let cert = SecCertificate::from_der(buf)?;
        info!("Certificate created successfully from DER");
        Ok(Certificate(cert))
    }

    #[cfg(target_os = "macos")]
    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        debug!("Certificate::from_pem called with {} bytes of PEM data", buf.len());
        let mut items = SecItems::default();
        ImportOptions::new().items(&mut items).import(buf)?;
        if items.certificates.len() == 1 && items.identities.is_empty() && items.keys.is_empty() {
            info!("Certificate created successfully from PEM");
            Ok(Certificate(items.certificates.pop().unwrap()))
        } else {
            error!("Invalid PEM data for single certificate");
            Err(Error(base::Error::from(errSecParam)))
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn from_pem(_: &[u8]) -> Result<Certificate, Error> {
        panic!("Not implemented on iOS, tvOS, watchOS or visionOS");
    }

    #[cfg(target_os = "macos")]
    pub fn stack_from_pem(buf: &[u8]) -> Result<Vec<Certificate>, Error> {
        debug!("Certificate::stack_from_pem called with {} bytes of PEM data", buf.len());
        let mut items = SecItems::default();
        ImportOptions::new().items(&mut items).import(buf)?;
        if items.identities.is_empty() && items.keys.is_empty() {
            info!("Successfully created {} certificates from PEM stack", items.certificates.len());
            Ok(items.certificates.into_iter().map(Certificate).collect())
        } else {
            error!("Invalid PEM data for certificate stack");
            Err(Error(base::Error::from(errSecParam)))
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn stack_from_pem(_buf: &[u8]) -> Result<Vec<Certificate>, Error> {
        panic!("Not implemented on iOS");
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        debug!("Certificate::to_der called");
        Ok(self.0.to_der())
    }
}

pub enum HandshakeError<S> {
    WouldBlock(MidHandshakeTlsStream<S>),
    Failure(Error),
}

impl<S> From<secure_transport::ClientHandshakeError<S>> for HandshakeError<S> {
    fn from(e: secure_transport::ClientHandshakeError<S>) -> HandshakeError<S> {
        match e {
            secure_transport::ClientHandshakeError::Failure(e) => HandshakeError::Failure(e.into()),
            secure_transport::ClientHandshakeError::Interrupted(s) => {
                HandshakeError::WouldBlock(MidHandshakeTlsStream::Client(s))
            }
        }
    }
}

impl<S> From<base::Error> for HandshakeError<S> {
    fn from(e: base::Error) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

pub enum MidHandshakeTlsStream<S> {
    Server(
        secure_transport::MidHandshakeSslStream<S>,
        Option<SecCertificate>,
    ),
    Client(secure_transport::MidHandshakeClientBuilder<S>),
}

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MidHandshakeTlsStream::Server(ref s, _) => s.fmt(fmt),
            MidHandshakeTlsStream::Client(ref s) => s.fmt(fmt),
        }
    }
}

impl<S> MidHandshakeTlsStream<S> {
    pub fn get_ref(&self) -> &S {
        match *self {
            MidHandshakeTlsStream::Server(ref s, _) => s.get_ref(),
            MidHandshakeTlsStream::Client(ref s) => s.get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut S {
        match *self {
            MidHandshakeTlsStream::Server(ref mut s, _) => s.get_mut(),
            MidHandshakeTlsStream::Client(ref mut s) => s.get_mut(),
        }
    }
}

impl<S> MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write,
{
    pub fn handshake(self) -> Result<TlsStream<S>, HandshakeError<S>> {
        match self {
            MidHandshakeTlsStream::Server(s, cert) => match s.handshake() {
                Ok(stream) => Ok(TlsStream { stream, cert }),
                Err(secure_transport::HandshakeError::Failure(e)) => {
                    Err(HandshakeError::Failure(Error(e)))
                }
                Err(secure_transport::HandshakeError::Interrupted(s)) => Err(
                    HandshakeError::WouldBlock(MidHandshakeTlsStream::Server(s, cert)),
                ),
            },
            MidHandshakeTlsStream::Client(s) => match s.handshake() {
                Ok(stream) => Ok(TlsStream { stream, cert: None }),
                Err(e) => Err(e.into()),
            },
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct TlsConnector {
    identity: Option<Identity>,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
    roots: Vec<SecCertificate>,
    use_sni: bool,
    danger_accept_invalid_hostnames: bool,
    danger_accept_invalid_certs: bool,
    disable_built_in_roots: bool,
    #[cfg(feature = "alpn")]
    alpn: Vec<Box<str>>,
}

impl TlsConnector {
    #[allow(clippy::unnecessary_wraps)]
    pub fn new(builder: &TlsConnectorBuilder) -> Result<Self, Error> {
        info!("TlsConnector::new called");
        info!("TlsConnector created with configuration:");
        debug!("  min_protocol: {:?}", builder.min_protocol);
        debug!("  max_protocol: {:?}", builder.max_protocol);
        debug!("  root_certificates: {}", builder.root_certificates.len());
        debug!("  use_sni: {}", builder.use_sni);
        debug!("  accept_invalid_hostnames: {}", builder.accept_invalid_hostnames);
        debug!("  accept_invalid_certs: {}", builder.accept_invalid_certs);
        debug!("  disable_built_in_roots: {}", builder.disable_built_in_roots);
        #[cfg(feature = "alpn")]
        debug!("  alpn protocols: {}", builder.alpn.len());

        Ok(Self {
            identity: builder.identity.as_ref().map(|i| i.0.clone()),
            min_protocol: builder.min_protocol,
            max_protocol: builder.max_protocol,
            roots: builder
                .root_certificates
                .iter()
                .map(|c| (c.0).0.clone())
                .collect(),
            use_sni: builder.use_sni,
            danger_accept_invalid_hostnames: builder.accept_invalid_hostnames,
            danger_accept_invalid_certs: builder.accept_invalid_certs,
            disable_built_in_roots: builder.disable_built_in_roots,
            #[cfg(feature = "alpn")]
            alpn: builder.alpn.clone(),
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        info!("TlsConnector::connect called with domain: {}", domain);
        let mut builder = ClientBuilder::new();
        let min = self.min_protocol.map(convert_protocol);
        let max = self.max_protocol.map(convert_protocol);
        debug!("  Protocol min: {:?}, max: {:?}", min, max);
        if let Some(min) = min {
            // If the unsupported TLS 1.3 is the minimum, then let it fail
            debug!("  Setting minimum protocol: {:?}", min);
            builder.protocol_min(min);
        }
        if let Some(max) = max {
            builder.protocol_max(match max {
                // If TLS 1.3 is allowed but not required, then use the latest that is actually supported - 1.2
                SslProtocol::TLS13 if min != Some(SslProtocol::TLS13) => {
                    debug!("  Adjusting TLS13 to TLS12 (not supported as minimum)");
                    SslProtocol::TLS12
                },
                other => other,
            });
            debug!("  Setting maximum protocol: {:?}", max);
        }
        if let Some(identity) = self.identity.as_ref() {
            debug!("  Setting identity with {} chain certificates", identity.chain.len());
            builder.identity(&identity.identity, &identity.chain);
        }
        debug!("  Setting {} anchor certificates", self.roots.len());
        builder.anchor_certificates(&self.roots);
        debug!("  SNI: {}, hostname verification: {}", self.use_sni, !self.danger_accept_invalid_hostnames);
        builder.use_sni(self.use_sni);
        builder.danger_accept_invalid_hostnames(self.danger_accept_invalid_hostnames);
        debug!("  Accept invalid certs: {}", self.danger_accept_invalid_certs);
        builder.danger_accept_invalid_certs(self.danger_accept_invalid_certs);
        debug!("  Trust anchor certificates only: {}", self.disable_built_in_roots);
        builder.trust_anchor_certificates_only(self.disable_built_in_roots);

        #[cfg(feature = "alpn")]
        {
            if !self.alpn.is_empty() {
                debug!("  Setting ALPN protocols: {:?}", self.alpn);
                builder.alpn_protocols(&self.alpn.iter().map(|s| &**s).collect::<Vec<_>>());
            }
        }

        debug!("  Initiating TLS handshake");
        match builder.handshake(domain, stream) {
            Ok(stream) => {
                info!("  TLS connection established successfully");
                Ok(TlsStream { stream, cert: None })
            },
            Err(e) => {
                error!("  TLS connection failed: {:?}", e);
                Err(e.into())
            },
        }
    }
}

#[derive(Clone)]
pub struct TlsAcceptor {
    identity: Identity,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
}

impl TlsAcceptor {
    #[allow(clippy::unnecessary_wraps)]
    pub fn new(builder: &TlsAcceptorBuilder) -> Result<Self, Error> {
        info!("TlsAcceptor::new called");
        info!("TlsAcceptor created with configuration:");
        debug!("  min_protocol: {:?}", builder.min_protocol);
        debug!("  max_protocol: {:?}", builder.max_protocol);

        Ok(Self {
            identity: builder.identity.0.clone(),
            min_protocol: builder.min_protocol,
            max_protocol: builder.max_protocol,
        })
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        info!("TlsAcceptor::accept called");
        let mut ctx = SslContext::new(SslProtocolSide::SERVER, SslConnectionType::STREAM)?;
        debug!("  Created SSL context for server");

        if let Some(min) = self.min_protocol {
            debug!("  Setting minimum protocol: {:?}", min);
            ctx.set_protocol_version_min(convert_protocol(min))?;
        }
        if let Some(max) = self.max_protocol {
            debug!("  Setting maximum protocol: {:?}", max);
            ctx.set_protocol_version_max(convert_protocol(max))?;
        }
        debug!("  Setting certificate with {} chain certificates", self.identity.chain.len());
        ctx.set_certificate(&self.identity.identity, &self.identity.chain)?;
        let cert = Some(self.identity.identity.certificate()?);
        debug!("  Initiating TLS handshake");
        match ctx.handshake(stream) {
            Ok(stream) => {
                info!("  TLS connection accepted successfully");
                Ok(TlsStream { stream, cert })
            },
            Err(secure_transport::HandshakeError::Failure(e)) => {
                error!("  TLS handshake failed: {:?}", e);
                Err(HandshakeError::Failure(Error(e)))
            }
            Err(secure_transport::HandshakeError::Interrupted(s)) => {
                info!("  TLS handshake interrupted");
                Err(HandshakeError::WouldBlock(MidHandshakeTlsStream::Server(s, cert)))
            },
        }
    }
}

pub struct TlsStream<S> {
    stream: secure_transport::SslStream<S>,
    #[cfg_attr(not(target_os = "macos"), allow(unused))]
    cert: Option<SecCertificate>,
}

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}

impl<S> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        trace!("TlsStream::buffered_read_size called");
        Ok(self.stream.context().buffered_read_size()?)
    }

    #[allow(deprecated)]
    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        debug!("TlsStream::peer_certificate called");
        let Some(trust) = self.stream.context().peer_trust2()? else {
            debug!("  No peer trust available");
            return Ok(None);
        };
        debug!("  Evaluating peer trust");
        trust.evaluate()?;

        Ok(trust.certificate_at_index(0).map(Certificate))
    }

    #[cfg(feature = "alpn")]
    pub fn negotiated_alpn(&self) -> Result<Option<Vec<u8>>, Error> {
        debug!("TlsStream::negotiated_alpn called");
        match self.stream.context().alpn_protocols() {
            Ok(protocols) => {
                // Per RFC7301, "ProtocolNameList" MUST contain exactly one "ProtocolName".
                assert!(protocols.len() < 2);

                if protocols.is_empty() {
                    // Not sure this is actually possible.
                    debug!("  No ALPN protocols negotiated");
                    Ok(None)
                } else {
                    let proto = protocols.into_iter().next().unwrap().into_bytes();
                    debug!("  Negotiated ALPN: {:?}", String::from_utf8_lossy(&proto));
                    Ok(Some(proto))
                }
            }
            // The macOS API appears to return `errSecParam` whenever no ALPN was negotiated, both
            // when it isn't attempted and when it isn't successful.
            Err(e) if e.code() == errSecParam => {
                debug!("  No ALPN negotiated (errSecParam)");
                Ok(None)
            },
            Err(other) => {
                error!("  ALPN query failed: {:?}", other);
                Err(Error::from(other))
            },
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn tls_server_end_point(&self) -> Result<Option<Vec<u8>>, Error> {
        debug!("TlsStream::tls_server_end_point called (not supported on this platform)");
        Ok(None)
    }

    #[cfg(target_os = "macos")]
    pub fn tls_server_end_point(&self) -> Result<Option<Vec<u8>>, Error> {
        debug!("TlsStream::tls_server_end_point called");
        let cert = match self.cert {
            Some(ref cert) => {
                debug!("  Using local certificate");
                cert.clone()
            },
            None => match self.peer_certificate()? {
                Some(cert) => {
                    debug!("  Using peer certificate");
                    cert.0
                },
                None => {
                    debug!("  No certificate available");
                    return Ok(None);
                },
            },
        };

        let Some(property) = cert
            .properties(Some(&[CertificateOid::x509_v1_signature_algorithm()]))
            .ok()
            .and_then(|p| p.get(CertificateOid::x509_v1_signature_algorithm()))
        else {
            debug!("  No signature algorithm property found");
            return Ok(None);
        };

        let PropertyType::Section(section) = property.get() else {
            debug!("  Property is not a section");
            return Ok(None);
        };

        let Some(algorithm) = section.iter().find(|p| p.label() == "Algorithm") else {
            debug!("  No algorithm property found");
            return Ok(None);
        };

        let PropertyType::String(algorithm) = algorithm.get() else {
            debug!("  Algorithm is not a string");
            return Ok(None);
        };

        debug!("  Signature algorithm: {}", algorithm.to_string());
        let digest = match &*algorithm.to_string() {
            // MD5
            "1.2.840.113549.2.5" | "1.2.840.113549.1.1.4" | "1.3.14.3.2.3" => {
                debug!("  Using SHA256 for MD5 signature");
                Digest::Sha256
            },
            // SHA-1
            "1.3.14.3.2.26"
            | "1.3.14.3.2.15"
            | "1.2.840.113549.1.1.5"
            | "1.3.14.3.2.29"
            | "1.2.840.10040.4.3"
            | "1.3.14.3.2.13"
            | "1.2.840.10045.4.1" => {
                debug!("  Using SHA256 for SHA-1 signature");
                Digest::Sha256
            },
            // SHA-224
            "2.16.840.1.101.3.4.2.4"
            | "1.2.840.113549.1.1.14"
            | "2.16.840.1.101.3.4.3.1"
            | "1.2.840.10045.4.3.1" => {
                debug!("  Using SHA224");
                Digest::Sha224
            },
            // SHA-256
            "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => {
                debug!("  Using SHA256");
                Digest::Sha256
            }
            // SHA-384
            "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => {
                debug!("  Using SHA384");
                Digest::Sha384
            }
            // SHA-512
            "2.16.840.1.101.3.4.2.3" | "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => {
                debug!("  Using SHA512");
                Digest::Sha512
            }
            _ => {
                debug!("  Unknown signature algorithm");
                return Ok(None);
            },
        };

        let der = cert.to_der();
        let hash = digest.hash(&der);
        debug!("  Computed hash, length: {}", hash.len());
        Ok(Some(hash))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        info!("TlsStream::shutdown called");
        match self.stream.close() {
            Ok(_) => {
                info!("  TLS shutdown completed successfully");
                Ok(())
            },
            Err(e) => {
                error!("  TLS shutdown failed: {:?}", e);
                Err(e.into())
            },
        }
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(target_os = "macos")]
enum Digest {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(target_os = "macos")]
impl Digest {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        const CC_SHA224_DIGEST_LENGTH: usize = 28;
        const CC_SHA256_DIGEST_LENGTH: usize = 32;
        const CC_SHA384_DIGEST_LENGTH: usize = 48;
        const CC_SHA512_DIGEST_LENGTH: usize = 64;
        unsafe {
            assert!(data.len() <= u32::MAX as usize);
            match *self {
                Digest::Sha224 => {
                    let mut buf = [0; CC_SHA224_DIGEST_LENGTH];
                    CC_SHA224(data.as_ptr(), data.len() as u32, buf.as_mut_ptr());
                    buf.to_vec()
                }
                Digest::Sha256 => {
                    let mut buf = [0; CC_SHA256_DIGEST_LENGTH];
                    CC_SHA256(data.as_ptr(), data.len() as u32, buf.as_mut_ptr());
                    buf.to_vec()
                }
                Digest::Sha384 => {
                    let mut buf = [0; CC_SHA384_DIGEST_LENGTH];
                    CC_SHA384(data.as_ptr(), data.len() as u32, buf.as_mut_ptr());
                    buf.to_vec()
                }
                Digest::Sha512 => {
                    let mut buf = [0; CC_SHA512_DIGEST_LENGTH];
                    CC_SHA512(data.as_ptr(), data.len() as u32, buf.as_mut_ptr());
                    buf.to_vec()
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn CC_SHA224(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA384(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA512(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
}
