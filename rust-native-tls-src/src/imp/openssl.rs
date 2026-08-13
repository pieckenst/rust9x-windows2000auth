use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    self, MidHandshakeSslStream, SslAcceptor, SslConnector, SslContextBuilder, SslMethod,
    SslVerifyMode,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509VerifyResult, X509};
use openssl_probe::ProbeResult;
use std::sync::LazyLock;
use std::{error, fmt, io};

use crate::{Protocol, TlsAcceptorBuilder, TlsConnectorBuilder};
use log::{debug, error, info, trace, warn};

static PROBE_RESULT: LazyLock<ProbeResult> = LazyLock::new(openssl_probe::probe);

#[cfg(have_min_max_version)]
fn supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> Result<(), ErrorStack> {
    use openssl::ssl::SslVersion;

    fn cvt(p: Protocol) -> SslVersion {
        match p {
            Protocol::Sslv3 => SslVersion::SSL3,
            Protocol::Tlsv10 => SslVersion::TLS1,
            Protocol::Tlsv11 => SslVersion::TLS1_1,
            Protocol::Tlsv12 => SslVersion::TLS1_2,
            Protocol::Tlsv13 => SslVersion::TLS1_3,
        }
    }

    ctx.set_min_proto_version(min.map(cvt))?;
    ctx.set_max_proto_version(max.map(cvt))?;

    Ok(())
}

#[cfg(not(have_min_max_version))]
fn supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> Result<(), ErrorStack> {
    use openssl::ssl::SslOptions;

    let no_ssl_mask = SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::NO_TLSV1
        | SslOptions::NO_TLSV1_1
        | SslOptions::NO_TLSV1_2;

    ctx.clear_options(no_ssl_mask);
    let mut options = SslOptions::empty();
    options |= match min {
        None => SslOptions::empty(),
        Some(Protocol::Sslv3) => SslOptions::NO_SSLV2,
        Some(Protocol::Tlsv10) => SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3,
        Some(Protocol::Tlsv11) => {
            SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1
        }
        Some(Protocol::Tlsv12) => {
            SslOptions::NO_SSLV2
                | SslOptions::NO_SSLV3
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
        }
        Some(Protocol::Tlsv13) => {
            SslOptions::NO_SSLV2
                | SslOptions::NO_SSLV3
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
                | SslOptions::NO_TLSV1_2
        }
    };
    options |= match max {
        // NO_TLSV1_3 may be unavailalbe in the old versions
        None | Some(Protocol::Tlsv12 | Protocol::Tlsv13) => SslOptions::empty(),
        Some(Protocol::Tlsv11) => SslOptions::NO_TLSV1_2,
        Some(Protocol::Tlsv10) => SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::Sslv3) => {
            SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2
        }
    };

    ctx.set_options(options);

    Ok(())
}

#[cfg(target_os = "android")]
fn load_android_root_certs(connector: &mut SslContextBuilder) -> Result<(), Error> {
    use std::fs;

    if let Ok(dir) = fs::read_dir("/system/etc/security/cacerts") {
        let certs = dir
            .filter_map(|r| r.ok())
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| X509::from_pem(&b).ok());
        for cert in certs {
            if let Err(err) = connector.cert_store_mut().add_cert(cert) {
                debug!("load_android_root_certs error: {:?}", err);
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Normal(ErrorStack),
    Ssl(ssl::Error, X509VerifyResult),
    EmptyChain,
    NotPkcs8,
    AlpnTooLong,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Normal(ref e) => error::Error::source(e),
            Error::Ssl(ref e, _) => error::Error::source(e),
            Error::EmptyChain => None,
            Error::NotPkcs8 => None,
            Error::AlpnTooLong => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Normal(ref e) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, X509VerifyResult::OK) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, v) => write!(fmt, "{} ({})", e, v),
            Error::EmptyChain => write!(
                fmt,
                "at least one certificate must be provided to create an identity"
            ),
            Error::NotPkcs8 => write!(fmt, "expected PKCS#8 PEM"),
            Error::AlpnTooLong => write!(fmt, "ALPN too long"),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::Normal(err)
    }
}

#[derive(Clone)]
pub struct Identity {
    pkey: PKey<Private>,
    cert: X509,
    chain: Vec<X509>,
}

impl Identity {
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        info!("Identity::from_pkcs12 called with {} bytes of PKCS#12 data", buf.len());
        let pkcs12 = Pkcs12::from_der(buf)?;
        debug!("PKCS#12 DER parsed successfully");
        let parsed = pkcs12.parse2(pass)?;
        debug!("PKCS#12 parsed with password");
        Ok(Identity {
            pkey: parsed.pkey.ok_or_else(|| {
                error!("No private key found in PKCS#12");
                Error::EmptyChain
            })?,
            cert: parsed.cert.ok_or_else(|| {
                error!("No certificate found in PKCS#12");
                Error::EmptyChain
            })?,
            // > The stack is the reverse of what you might expect due to the way
            // > PKCS12_parse is implemented, so we need to load it backwards.
            // > https://github.com/sfackler/rust-native-tls/commit/05fb5e583be589ab63d9f83d986d095639f8ec44
            chain: parsed.ca.into_iter().flatten().rev().collect(),
        })
    }

    pub fn from_pkcs8(buf: &[u8], key: &[u8]) -> Result<Identity, Error> {
        info!("Identity::from_pkcs8 called with {} bytes of PEM data and {} bytes of key data", buf.len(), key.len());
        if !key.starts_with(b"-----BEGIN PRIVATE KEY-----") {
            error!("Key is not in PKCS#8 format");
            return Err(Error::NotPkcs8);
        }

        let pkey = PKey::private_key_from_pem(key)?;
        debug!("Private key parsed from PEM");
        let mut cert_chain = X509::stack_from_pem(buf)?.into_iter();
        let cert = cert_chain.next().ok_or_else(|| {
            error!("No certificate found in PEM data");
            Error::EmptyChain
        })?;
        let chain = cert_chain.collect();
        debug!("Certificate chain loaded with {} intermediate certificates", chain.len());
        Ok(Identity { pkey, cert, chain })
    }
}

#[derive(Clone)]
pub struct Certificate(X509);

impl Certificate {
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        debug!("Certificate::from_der called with {} bytes of DER data", buf.len());
        let cert = X509::from_der(buf)?;
        info!("Certificate created successfully from DER");
        Ok(Certificate(cert))
    }

    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        debug!("Certificate::from_pem called with {} bytes of PEM data", buf.len());
        let cert = X509::from_pem(buf)?;
        info!("Certificate created successfully from PEM");
        Ok(Certificate(cert))
    }

    pub fn stack_from_pem(buf: &[u8]) -> Result<Vec<Certificate>, Error> {
        debug!("Certificate::stack_from_pem called with {} bytes of PEM data", buf.len());
        let certs = X509::stack_from_pem(buf)?;
        info!("Successfully created {} certificates from PEM stack", certs.len());
        Ok(certs.into_iter().map(Certificate).collect())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        debug!("Certificate::to_der called");
        let der = self.0.to_der()?;
        info!("Certificate converted to DER, length: {}", der.len());
        Ok(der)
    }
}

pub struct MidHandshakeTlsStream<S>(MidHandshakeSslStream<S>);

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> MidHandshakeTlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S> MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write,
{
    pub fn handshake(self) -> Result<TlsStream<S>, HandshakeError<S>> {
        match self.0.handshake() {
            Ok(s) => Ok(TlsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

pub enum HandshakeError<S> {
    Failure(Error),
    WouldBlock(MidHandshakeTlsStream<S>),
}

impl<S> From<ssl::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: ssl::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            ssl::HandshakeError::SetupFailure(e) => HandshakeError::Failure(e.into()),
            ssl::HandshakeError::Failure(e) => {
                let v = e.ssl().verify_result();
                HandshakeError::Failure(Error::Ssl(e.into_error(), v))
            }
            ssl::HandshakeError::WouldBlock(s) => {
                HandshakeError::WouldBlock(MidHandshakeTlsStream(s))
            }
        }
    }
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}

#[derive(Clone)]
pub struct TlsConnector {
    connector: SslConnector,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl TlsConnector {
    pub fn new(builder: &TlsConnectorBuilder) -> Result<TlsConnector, Error> {
        info!("TlsConnector::new called");
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        debug!("Created SSL connector builder");

        // We need to load these separately so an error on one doesn't prevent the other from loading.
        if let Some(cert_file) = &PROBE_RESULT.cert_file {
            debug!("Loading cert file: {:?}", cert_file);
            if let Err(e) = connector.load_verify_locations(Some(cert_file), None) {
                debug!("load_verify_locations cert file error: {:?}", e);
            }
        }
        for cert_dir in &PROBE_RESULT.cert_dir {
            debug!("Loading cert dir: {:?}", cert_dir);
            if let Err(e) = connector.load_verify_locations(None, Some(cert_dir)) {
                debug!("load_verify_locations cert dir error: {:?}", e);
            }
        }

        if let Some(ref identity) = builder.identity {
            debug!("Setting identity certificate and private key");
            connector.set_certificate(&identity.0.cert)?;
            connector.set_private_key(&identity.0.pkey)?;
            debug!("Adding {} chain certificates", identity.0.chain.len());
            for cert in identity.0.chain.iter() {
                // https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_extra_chain_cert.html
                // specifies that "When sending a certificate chain, extra chain certificates are
                // sent in order following the end entity certificate."
                connector.add_extra_chain_cert(cert.to_owned())?;
            }
        }
        debug!("Setting supported protocols: min={:?}, max={:?}", builder.min_protocol, builder.max_protocol);
        supported_protocols(builder.min_protocol, builder.max_protocol, &mut connector)?;

        if builder.disable_built_in_roots {
            debug!("Disabling built-in root certificates");
            connector.set_cert_store(X509StoreBuilder::new()?.build());
        }

        debug!("Adding {} root certificates", builder.root_certificates.len());
        for cert in &builder.root_certificates {
            if let Err(err) = connector.cert_store_mut().add_cert((cert.0).0.clone()) {
                debug!("add_cert error: {:?}", err);
            }
        }

        #[cfg(feature = "alpn")]
        if !builder.alpn.is_empty() {
            debug!("Setting ALPN protocols: {:?}", builder.alpn);
            connector.set_alpn_protos(&alpn_wire_format(&builder.alpn)?)?;
        }

        #[cfg(target_os = "android")]
        load_android_root_certs(&mut connector)?;

        info!("TlsConnector created with configuration:");
        debug!("  use_sni: {}", builder.use_sni);
        debug!("  accept_invalid_hostnames: {}", builder.accept_invalid_hostnames);
        debug!("  accept_invalid_certs: {}", builder.accept_invalid_certs);

        Ok(TlsConnector {
            connector: connector.build(),
            use_sni: builder.use_sni,
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
            accept_invalid_certs: builder.accept_invalid_certs,
        })
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        info!("TlsConnector::connect called with domain: {}", domain);
        let mut ssl = self
            .connector
            .configure()?
            .use_server_name_indication(self.use_sni)
            .verify_hostname(!self.accept_invalid_hostnames);
        debug!("  SNI: {}, hostname verification: {}", self.use_sni, !self.accept_invalid_hostnames);
        if self.accept_invalid_certs {
            debug!("  Disabling certificate verification");
            ssl.set_verify(SslVerifyMode::NONE);
        }

        debug!("  Initiating TLS handshake");
        let s = ssl.connect(domain, stream)?;
        info!("  TLS connection established successfully");
        Ok(TlsStream(s))
    }
}

#[cfg(any(feature = "alpn", feature = "alpn-accept"))]
fn alpn_wire_format(alpn_list: &[Box<str>]) -> Result<Vec<u8>, Error> {
    // Wire format is each alpn preceded by its length as a byte.
    let mut alpn_wire_format =
        Vec::with_capacity(alpn_list.iter().map(|s| s.len()).sum::<usize>() + alpn_list.len());
    for alpn in alpn_list.iter().map(|s| s.as_bytes()) {
        let len_byte = alpn.len().try_into().map_err(|_| Error::AlpnTooLong)?;

        if alpn_wire_format.capacity() - alpn_wire_format.len() >= 1 {
            alpn_wire_format.push(len_byte);
        }
        if alpn_wire_format.capacity() - alpn_wire_format.len() >= alpn.len() {
            alpn_wire_format.extend(alpn);
        }
    }
    Ok(alpn_wire_format)
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsConnector")
            // n.b. SslConnector is a newtype on SslContext which implements a noop Debug so it's omitted
            .field("use_sni", &self.use_sni)
            .field("accept_invalid_hostnames", &self.accept_invalid_hostnames)
            .field("accept_invalid_certs", &self.accept_invalid_certs)
            .finish()
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(SslAcceptor);

impl TlsAcceptor {
    pub fn new(builder: &TlsAcceptorBuilder) -> Result<TlsAcceptor, Error> {
        info!("TlsAcceptor::new called");
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        debug!("Created SSL acceptor builder with Mozilla intermediate configuration");
        debug!("Setting private key and certificate");
        acceptor.set_private_key(&builder.identity.0.pkey)?;
        acceptor.set_certificate(&builder.identity.0.cert)?;
        #[cfg(feature = "alpn-accept")]
        if !builder.accept_alpn.is_empty() {
            debug!("Setting ALPN accept protocols: {:?}", builder.accept_alpn);
            let alpn_wire_format = alpn_wire_format(&builder.accept_alpn)?;
            acceptor.set_alpn_protos(&alpn_wire_format)?;
            // set up ALPN selection routine - as select_next_proto
            acceptor.set_alpn_select_callback(move |_: &mut openssl::ssl::SslRef, client_list: &[u8]| {
                debug!("ALPN select callback called with client list length: {}", client_list.len());
                openssl::ssl::select_next_proto(&alpn_wire_format, client_list).and_then(|selected| {
                    if selected.is_empty() || selected.len() > client_list.len() {
                        return None;
                    }
                    // return string from the client list to separate it from alpn_wire_format's lifetime
                    // https://github.com/rust-openssl/rust-openssl/pull/2360#issuecomment-2651522324
                    client_list.windows(selected.len()).find(|&item| item == selected)
                })
                .ok_or(openssl::ssl::AlpnError::NOACK)
            });
        }
        debug!("Adding {} chain certificates", builder.identity.0.chain.len());
        for cert in builder.identity.0.chain.iter() {
            // https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_extra_chain_cert.html
            // specifies that "When sending a certificate chain, extra chain certificates are
            // sent in order following the end entity certificate."
            acceptor.add_extra_chain_cert(cert.to_owned())?;
        }
        debug!("Setting supported protocols: min={:?}, max={:?}", builder.min_protocol, builder.max_protocol);
        supported_protocols(builder.min_protocol, builder.max_protocol, &mut acceptor)?;

        info!("TlsAcceptor created successfully");
        Ok(TlsAcceptor(acceptor.build()))
    }

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        info!("TlsAcceptor::accept called");
        debug!("  Accepting TLS connection");
        let s = self.0.accept(stream)?;
        info!("  TLS connection accepted successfully");
        Ok(TlsStream(s))
    }
}

pub struct TlsStream<S>(ssl::SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        trace!("TlsStream::buffered_read_size called");
        Ok(self.0.ssl().pending())
    }

    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        debug!("TlsStream::peer_certificate called");
        Ok(self.0.ssl().peer_certificate().map(Certificate))
    }

    #[cfg(feature = "alpn")]
    pub fn negotiated_alpn(&self) -> Result<Option<Vec<u8>>, Error> {
        debug!("TlsStream::negotiated_alpn called");
        Ok(self
            .0
            .ssl()
            .selected_alpn_protocol()
            .map(|alpn| {
                debug!("  Negotiated ALPN: {:?}", String::from_utf8_lossy(alpn));
                alpn.to_vec()
            }))
    }

    pub fn tls_server_end_point(&self) -> Result<Option<Vec<u8>>, Error> {
        debug!("TlsStream::tls_server_end_point called");
        let cert = if self.0.ssl().is_server() {
            debug!("  Using server certificate");
            self.0.ssl().certificate().map(|x| x.to_owned())
        } else {
            debug!("  Using peer certificate");
            self.0.ssl().peer_certificate()
        };

        let cert = match cert {
            Some(cert) => cert,
            None => {
                debug!("  No certificate available");
                return Ok(None);
            },
        };

        let algo_nid = cert.signature_algorithm().object().nid();
        debug!("  Signature algorithm NID: {:?}", algo_nid);
        let signature_algorithms = match algo_nid.signature_algorithms() {
            Some(algs) => algs,
            None => {
                debug!("  No signature algorithms available");
                return Ok(None);
            },
        };

        let md = match signature_algorithms.digest {
            Nid::MD5 | Nid::SHA1 => {
                debug!("  Using SHA256 for MD5/SHA1 signature");
                MessageDigest::sha256()
            },
            nid => match MessageDigest::from_nid(nid) {
                Some(md) => {
                    debug!("  Using digest from NID: {:?}", nid);
                    md
                },
                None => {
                    debug!("  Could not create MessageDigest from NID");
                    return Ok(None);
                },
            },
        };

        let digest = cert.digest(md)?;
        debug!("  Computed digest, length: {}", digest.len());

        Ok(Some(digest.to_vec()))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        info!("TlsStream::shutdown called");
        match self.0.shutdown() {
            Ok(_) => {
                info!("  TLS shutdown completed successfully");
                Ok(())
            },
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => {
                info!("  TLS shutdown with ZERO_RETURN");
                Ok(())
            },
            Err(e) => {
                error!("  TLS shutdown failed: {:?}", e);
                Err(e.into_io_error().unwrap_or_else(io::Error::other))
            },
        }
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
