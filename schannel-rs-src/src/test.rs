use std::env;
use std::io::{self, Error, Read, Write};
use std::mem;
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::Once;
use std::thread;

use windows_sys::Win32::Foundation;
use windows_sys::Win32::Security::Cryptography;
use windows_sys::Win32::System::{SystemInformation, Time};

use crate::alpn_list::AlpnList;
use crate::cert_context::{CertContext, HashAlgorithm, KeySpec};
use crate::cert_store::{CertAdd, CertStore, Memory};
use crate::crypt_prov::{AcquireOptions, ProviderType};
use crate::schannel_cred::{Algorithm, Direction, Protocol, SchannelCred};
use crate::tls_stream::{self, HandshakeError};
use crate::Inner;

#[test]
fn basic() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

#[test]
fn invalid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Rc2, Algorithm::Ecdsa])
        .acquire(Direction::Outbound);
    assert_eq!(
        creds.err().unwrap().raw_os_error().unwrap(),
        Foundation::SEC_E_ALGORITHM_MISMATCH as i32
    );
}

#[test]
fn valid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Aes128, Algorithm::Ecdsa])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

fn unwrap_handshake<S>(e: HandshakeError<S>) -> io::Error {
    match e {
        HandshakeError::Failure(e) => e,
        HandshakeError::Interrupted(_) => panic!("not an I/O error"),
    }
}

#[test]
#[ignore] // google's inconsistent about disallowing sslv3
fn invalid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Ssl3])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::SEC_E_UNSUPPORTED_FUNCTION as i32
    );
}

#[test]
fn valid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

#[test]
fn valid_protocol_with_intermediate_certs() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("lh3.googleusercontent.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("lh3.googleusercontent.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

#[test]
fn expired_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("expired.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("expired.badssl.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::CERT_E_EXPIRED as i32
    );
}

#[test]
fn self_signed_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::CERT_E_UNTRUSTEDROOT as i32
    );
}

#[test]
fn self_signed_cert_manual_trust() {
    let cert = include_bytes!("../test/self-signed.badssl.com.cer");
    let mut store = Memory::new().unwrap();
    store.add_encoded_certificate(cert).unwrap();

    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .cert_store(store.into_store())
        .connect(creds, stream)
        .unwrap();
}

#[test]
fn wrong_host_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("wrong.host.badssl.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::CERT_E_CN_NO_MATCH as i32
    );
}

#[test]
fn wrong_host_cert_ignored() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    tls_stream::Builder::new()
        .domain("wrong.host.badssl.com")
        .accept_invalid_hostnames(true)
        .connect(creds, stream)
        .unwrap();
}

#[test]
fn shutdown() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.shutdown().unwrap();
}

#[test]
fn validation_failure_is_permanent() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    // temporarily switch to nonblocking to allow us to construct the stream
    // without validating
    stream.set_nonblocking(true).unwrap();
    let stream = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .connect(creds, stream);
    let stream = match stream {
        Err(HandshakeError::Interrupted(s)) => s,
        _ => panic!(),
    };
    stream.get_ref().set_nonblocking(false).unwrap();
    let err = unwrap_handshake(stream.handshake().err().unwrap());
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::CERT_E_UNTRUSTEDROOT as i32
    );
}

#[test]
fn verify_callback_success() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .verify_callback(|validation_result| {
            assert!(validation_result.result().is_err());
            Ok(())
        })
        .connect(creds, stream)
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: self-signed.badssl.com\r\n\r\n")
        .unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.1 200 OK"));
    assert!(out.ends_with(b"</html>\n"));
}

#[test]
fn tls_13() {
    if env::var("SCHANNEL_SKIP_TLS_13_TEST") == Ok("1".to_owned()) {
        return
    }

    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12, Protocol::Tls13])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("tls13.akamai.io:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("tls13.akamai.io")
        .connect(creds, stream)
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: tls13.akamai.io\r\n\r\n")
        .unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();

    let pattern = b"Your client negotiated TLS 1.3";
    assert!(out.windows(pattern.len()).any(|x| x == pattern));
}

#[test]
fn verify_callback_error() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("google.com")
        .verify_callback(|validation_result| {
            assert!(validation_result.result().is_ok());
            Err(io::Error::from_raw_os_error(
                Foundation::CERT_E_UNTRUSTEDROOT,
            ))
        })
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::CERT_E_UNTRUSTEDROOT as i32
    );
}

#[test]
fn verify_callback_gives_failed_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .verify_callback(|validation_result| {
            let expected_finger = include_bytes!("../test/self-signed.badssl.com.cer.sha1").to_vec();
            assert_eq!(
                validation_result
                    .failed_certificate()
                    .unwrap()
                    .fingerprint(HashAlgorithm::sha1())
                    .unwrap(),
                expected_finger
            );
            Err(io::Error::from_raw_os_error(
                Foundation::CERT_E_UNTRUSTEDROOT,
            ))
        })
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        Foundation::CERT_E_UNTRUSTEDROOT as i32
    );
}

#[test]
fn no_session_resumed() {
    for _ in 0..2 {
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let stream = TcpStream::connect("google.com:443").unwrap();
        let stream = tls_stream::Builder::new()
            .domain("google.com")
            .connect(creds, stream)
            .unwrap();
        assert!(!stream.session_resumed().unwrap());
    }
}

#[test]
fn basic_session_resumed() {
    let creds = SchannelCred::builder()
        // TOOD: figure out why Tls13 doesnt resume
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let creds_copy = creds.clone();

    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds_copy, stream)
        .unwrap();
    assert!(!stream.session_resumed().unwrap());

    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    assert!(stream.session_resumed().unwrap());
}

#[test]
fn session_resumption_thread_safety() {
    let creds = SchannelCred::builder()
        // TOOD: figure out why Tls13 doesnt resume
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();

    // Connect once so that the session ticket is cached.
    let creds_copy = creds.clone();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds_copy, stream)
        .unwrap();
    assert!(!stream.session_resumed().unwrap());

    let mut threads = vec![];
    for _ in 0..4 {
        let creds_copy = creds.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..10 {
                let creds = creds_copy.clone();
                let stream = TcpStream::connect("google.com:443").unwrap();
                let stream = tls_stream::Builder::new()
                    .domain("google.com")
                    .connect(creds, stream)
                    .unwrap();
                assert!(stream.session_resumed().unwrap());
            }
        }));
    }

    for thread in threads.into_iter() {
        thread.join().unwrap()
    }
}

const FRIENDLY_NAME: &str = "schannel-rs localhost testing cert";

fn install_certificate() -> io::Result<CertContext> {
    unsafe {
        let mut provider = 0;
        let mut hkey = 0;

        let mut buffer = "schannel-rs test suite"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let res = Cryptography::CryptAcquireContextW(
            &mut provider,
            buffer.as_ptr(),
            ptr::null(),
            Cryptography::PROV_RSA_FULL,
            Cryptography::CRYPT_MACHINE_KEYSET,
        );
        if res == 0 {
            // create a new key container (since it does not exist)
            let res = Cryptography::CryptAcquireContextW(
                &mut provider,
                buffer.as_ptr(),
                ptr::null(),
                Cryptography::PROV_RSA_FULL,
                Cryptography::CRYPT_NEWKEYSET | Cryptography::CRYPT_MACHINE_KEYSET,
            );
            if res == 0 {
                return Err(Error::last_os_error());
            }
        }

        // create a new keypair (RSA-2048)
        let res = Cryptography::CryptGenKey(
            provider,
            Cryptography::AT_SIGNATURE,
            0x0800 << 16 | Cryptography::CRYPT_EXPORTABLE,
            &mut hkey,
        );
        if res == 0 {
            return Err(Error::last_os_error());
        }

        // start creating the certificate
        let name = "CN=localhost,O=schannel-rs,OU=schannel-rs,G=schannel_rs"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut cname_buffer: [u16; 257] = mem::zeroed();
        let mut cname_len = cname_buffer.len() as u32;
        let res = Cryptography::CertStrToNameW(
            Cryptography::X509_ASN_ENCODING,
            name.as_ptr(),
            Cryptography::CERT_X500_NAME_STR,
            ptr::null_mut(),
            cname_buffer.as_mut_ptr() as *mut u8,
            &mut cname_len,
            ptr::null_mut(),
        );
        if res == 0 {
            return Err(Error::last_os_error());
        }

        let subject_issuer = Cryptography::CRYPT_INTEGER_BLOB {
            cbData: cname_len,
            pbData: cname_buffer.as_ptr() as *mut u8,
        };
        let key_provider = Cryptography::CRYPT_KEY_PROV_INFO {
            pwszContainerName: buffer.as_mut_ptr(),
            pwszProvName: ptr::null_mut(),
            dwProvType: Cryptography::PROV_RSA_FULL,
            dwFlags: Cryptography::CRYPT_MACHINE_KEYSET,
            cProvParam: 0,
            rgProvParam: ptr::null_mut(),
            dwKeySpec: Cryptography::AT_SIGNATURE,
        };
        let sig_algorithm = Cryptography::CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: Cryptography::szOID_RSA_SHA256RSA as *mut _,
            Parameters: mem::zeroed(),
        };
        let mut expiration_date: Foundation::SYSTEMTIME = mem::zeroed();
        SystemInformation::GetSystemTime(&mut expiration_date);
        let mut file_time: Foundation::FILETIME = mem::zeroed();
        let res = Time::SystemTimeToFileTime(&expiration_date, &mut file_time);
        if res == 0 {
            return Err(Error::last_os_error());
        }
        let mut timestamp: u64 =
            file_time.dwLowDateTime as u64 | (file_time.dwHighDateTime as u64) << 32;
        // one day, timestamp unit is in 100 nanosecond intervals
        timestamp += (1E9 as u64) / 100 * (60 * 60 * 24);
        file_time.dwLowDateTime = timestamp as u32;
        file_time.dwHighDateTime = (timestamp >> 32) as u32;
        let res = Time::FileTimeToSystemTime(&file_time, &mut expiration_date);
        if res == 0 {
            return Err(Error::last_os_error());
        }

        // create a self signed certificate
        let cert_context = Cryptography::CertCreateSelfSignCertificate(
            Cryptography::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default(),
            &subject_issuer,
            Cryptography::CERT_CREATE_SELFSIGN_FLAGS::default(),
            &key_provider,
            &sig_algorithm,
            ptr::null_mut(),
            &expiration_date,
            ptr::null_mut(),
        );
        if cert_context.is_null() {
            return Err(Error::last_os_error());
        }
        let cert_context = CertContext::from_inner(cert_context);
        cert_context.set_friendly_name(FRIENDLY_NAME)?;

        // install the certificate to the machine's local store
        io::stdout()
            .write_all(
                br#"

The schannel-rs test suite is about to add a certificate to your set of root
and trusted certificates. This certificate should be for the domain "localhost"
with the description related to "schannel". This certificate is only valid for
one day and will be automatically deleted if you re-run the schannel-rs test
suite later.

If you would rather not do this please cancel the addition and re-run the
test suite with SCHANNEL_RS_SKIP_SERVER_TESTS=1.

"#,
            )
            .unwrap();
        local_root_store().add_cert(&cert_context, CertAdd::ReplaceExisting)?;
        Ok(cert_context)
    }
}

fn local_root_store() -> CertStore {
    if env::var("APPVEYOR").is_ok() || env::var("CI").is_ok() {
        CertStore::open_local_machine("Root").unwrap()
    } else {
        CertStore::open_current_user("Root").unwrap()
    }
}

fn localhost_cert() -> Option<CertContext> {
    if env::var("SCHANNEL_RS_SKIP_SERVER_TESTS").is_ok() {
        return None;
    }

    // Our tests need a certficiate that the system trusts to run with, and we
    // do this by basically generating a certificate on the fly. This
    // initialization block synchronizes tests to ensure that we only generate
    // one certificate which is then used by all the tests.
    //
    // First we check to see if the root trust store already has one of our
    // certificates, identified by the "friendly name" we set when the
    // certificate was created. If it's expired, then we delete it and generate
    // another. If none is found, we also generate another.
    //
    // Note that generating a certificate and adding it to the root trust store
    // will likely trigger a prompt to the user asking if they want to do that,
    // so we generate certificates that are valid for some amount of time so you
    // don't have to hit the "OK" button each time you run `cargo test`.
    //
    // After the initialization is performed we just probe the root store again
    // and find the certificate we added (or was already there).
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        for cert in local_root_store().certs() {
            let name = match cert.friendly_name() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if name != FRIENDLY_NAME {
                continue;
            }
            if !cert.is_time_valid().unwrap() {
                io::stdout()
                    .write_all(
                        br#"

The schannel-rs test suite is about to delete an old copy of one of its
certificates from your root trust store. This certificate was only valid for one
day and it is no longer needed. The host should be "localhost" and the
description should mention "schannel".

"#,
                    )
                    .unwrap();
                cert.delete().unwrap();
            } else {
                return;
            }
        }

        install_certificate().unwrap();
    });

    for cert in local_root_store().certs() {
        let name = match cert.friendly_name() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if name == FRIENDLY_NAME {
            return Some(cert);
        }
    }

    panic!("couldn't find a cert");
}

#[test]
fn accept_a_socket() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, stream)
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let mut stream = tls_stream::Builder::new().accept(creds, stream).unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    let mut buf = [0; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    t.join().unwrap();
}

#[test]
fn accept_one_byte_at_a_time() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    #[derive(Debug)]
    struct OneByteAtATime<S> {
        inner: S,
    }

    impl<S: Read> Read for OneByteAtATime<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(&mut buf[..1])
        }
    }

    impl<S: Write> Write for OneByteAtATime<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(&buf[..1])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, OneByteAtATime { inner: stream })
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let mut stream = tls_stream::Builder::new()
        .accept(creds, OneByteAtATime { inner: stream })
        .unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    let mut buf = [0; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    t.join().unwrap();
}

#[test]
fn split_cert_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let cert = include_bytes!("../test/cert.der");
        let mut store = Memory::new().unwrap();
        store.add_encoded_certificate(cert).unwrap();
        let store = store.into_store();

        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("foobar.com")
            .cert_store(store)
            .connect(creds, stream)
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
        stream.shutdown().unwrap();
    });

    let cert = include_bytes!("../test/cert.der");
    let cert = CertContext::new(cert).unwrap();

    let mut options = AcquireOptions::new();
    options.container("schannel-test");
    let type_ = ProviderType::rsa_full();

    let mut container = match options.acquire(type_) {
        Ok(container) => container,
        Err(_) => options.new_keyset(true).acquire(type_).unwrap(),
    };
    let key = include_bytes!("../test/key.key");
    container.import().import(key).unwrap();

    cert.set_key_prov_info()
        .container("schannel-test")
        .type_(type_)
        .keep_open(true)
        .key_spec(KeySpec::key_exchange())
        .set()
        .unwrap();

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let mut stream = tls_stream::Builder::new().accept(creds, stream).unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    let mut buf = [0; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    t.join().unwrap();
}

#[test]
fn test_loopback_alpn() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .request_application_protocols(&[b"h2"])
            .connect(creds, stream)
            .unwrap();
        assert_eq!(
            stream
                .negotiated_application_protocol()
                .expect("localhost unreachable"),
            Some(b"h2".to_vec())
        );

        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let stream = tls_stream::Builder::new()
        .request_application_protocols(&[b"h2"])
        .accept(creds, stream)
        .unwrap();
    assert_eq!(
        stream
            .negotiated_application_protocol()
            .expect("localhost unreachable"),
        Some(b"h2".to_vec())
    );

    t.join().unwrap();
}

#[test]
fn test_loopback_alpn_mismatch() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, stream)
            .unwrap();
        assert_eq!(
            stream
                .negotiated_application_protocol()
                .expect("localhost unreachable"),
            None
        );

        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let stream = tls_stream::Builder::new()
        .request_application_protocols(&[b"h2"])
        .accept(creds, stream)
        .unwrap();
    assert_eq!(
        stream
            .negotiated_application_protocol()
            .expect("localhost unreachable"),
        None
    );

    t.join().unwrap();
}

#[test]
fn test_external_alpn() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .request_application_protocols(&[b"h2"])
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    assert_eq!(
        stream
            .negotiated_application_protocol()
            .expect("google.com unreachable"),
        Some(b"h2".to_vec())
    );
}

#[test]
fn test_alpn_list() {
    let raw_proto_alpn_list = b"\x02h2";
    // Little-endian bit representation of the expected `SEC_APPLICATION_PROTOCOL_LIST`.
    let proto_list = &[
        // `sspi::SecApplicationProtocolNegotiationExt_ALPN` equals 2.
        &[2, 0, 0, 0, raw_proto_alpn_list.len() as u8, 0] as &[u8],
        raw_proto_alpn_list,
    ]
    .concat();
    let full_alpn_list = [&[proto_list.len() as u8, 0, 0, 0] as &[u8], proto_list].concat();
    assert_eq!(
        &AlpnList::new(&[b"h2".to_vec()]) as &[u8],
        &full_alpn_list as &[u8]
    );

    let raw_proto_alpn_list = b"\x02h2\x08http/1.1";
    // Little-endian bit representation of the expected `SEC_APPLICATION_PROTOCOL_LIST`.
    let proto_list = &[
        // `sspi::SecApplicationProtocolNegotiationExt_ALPN` equals 2.
        &[2, 0, 0, 0, raw_proto_alpn_list.len() as u8, 0] as &[u8],
        raw_proto_alpn_list,
    ]
    .concat();
    let full_alpn_list = [&[proto_list.len() as u8, 0, 0, 0] as &[u8], proto_list].concat();
    assert_eq!(
        &AlpnList::new(&[b"h2".to_vec(), b"http/1.1".to_vec()]) as &[u8],
        &full_alpn_list as &[u8]
    );
}

/// This should reproduce renegotiation error on TLS1.3.
/// It also verifies the same works on TLS1.2 because why not.
#[test]
fn test_renegotiation_corruption() {
    // This did not reproduce with 2 MB so not sure how reliant this test is.
    let payload_size = 4 * 1024 * 1024;
    
    let mut protos = vec![Protocol::Tls12];
    if std::env::var("SCHANNEL_SKIP_TLS_13_TEST") != Ok("1".to_owned()) {
        protos.push(Protocol::Tls13);
    }

    for proto in protos {
        let mut data_to_send = vec![0u8; payload_size];
        let pattern = [0,1,2,3,4];
        for (i, byte) in data_to_send.iter_mut().enumerate() {
            *byte = pattern[i % pattern.len()];
        }

        let cert = match localhost_cert() {
            Some(cert) => cert,
            None => return,
        };

        // 1. Setup TCP on random port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // 2. Server Thread
        let server_handle = thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().unwrap();
            tcp_stream.set_nonblocking(true).unwrap();

            let creds = SchannelCred::builder()
                .cert(cert)
                .enabled_protocols(&[proto])
                .acquire(Direction::Inbound)
                .unwrap();

            // Drive Handshake
            let mut res = tls_stream::Builder::new().accept(creds, tcp_stream);
            let mut stream = loop {
                match res {
                    Ok(s) => break s,
                    Err(crate::tls_stream::HandshakeError::Interrupted(mid)) => {
                        res = mid.handshake();
                    }
                    Err(e) => panic!("Server handshake failed: {:?}", e),
                }
            };

            // Server Read Loop
            let mut received = Vec::with_capacity(payload_size);
            let mut buf = [0u8; 16384];
            while received.len() < payload_size {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::yield_now(),
                    Err(e) => panic!("Server read error: {:?}", e),
                }
            }
            received
        });

        // 3. Client Logic
        let tcp_stream = TcpStream::connect(addr).unwrap();
        tcp_stream.set_nonblocking(true).unwrap();

        let creds = SchannelCred::builder()
            .enabled_protocols(&[proto])
            .acquire(Direction::Outbound)
            .unwrap();

        // Drive Handshake
        let mut res = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, tcp_stream);
        
        let mut client_tls = loop {
            match res {
                Ok(s) => break s,
                Err(crate::tls_stream::HandshakeError::Interrupted(mid)) => {
                    res = mid.handshake();
                }
                Err(e) => panic!("Client handshake failed: {:?}", e),
            }
        };

        // 4. The Interleaved Write/Read Loop
        let mut total_sent = 0;
        while total_sent < payload_size {
            let chunk = &data_to_send[total_sent..];
            match client_tls.write(chunk) {
                Ok(n) => total_sent += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // FORCE THE ISSUE: 
                    // While waiting for buffer space, try to read.
                    // This pulls in the NewSessionTicket and triggers SEC_I_RENEGOTIATE.
                    let mut dummy = [0u8; 1];
                    let _ = client_tls.read(&mut dummy);
                }
                Err(e) => panic!("Client write error: {:?}", e),
            }
        }

        let received_data = server_handle.join().expect("Server thread panicked");

        // 5. Validation
        assert_eq!(received_data.len(), payload_size, "{:?} Data length mismatch!", proto);
        let mismatch_count = received_data.iter()
            .zip(data_to_send.iter())
            .filter(|(a, b)| a != b)
            .count();

        // Calculate any difference in length as well
        let length_diff = (received_data.len() as i128 - data_to_send.len() as i128).abs();

        assert_eq!(mismatch_count, 0, "{:?} DATA CORRUPTION DETECTED: {} bytes do not match (Length diff: {})", proto, mismatch_count, length_diff);
    }
}

#[test]
fn test_acquire_credentials_handle_a_vs_w_null() {
    use windows_sys::Win32::Security::Authentication::Identity;
    use windows_sys::Win32::Security::Credentials;
    use windows_sys::Win32::Foundation;
    use windows_sys::Win32::System::LibraryLoader;

    eprintln!("=== Testing AcquireCredentialsHandleA vs W with NULL pAuthData ===");
    eprintln!("=== Test: Raw GetProcAddress A vs W vs windows-sys A vs W ===");

    // First, inspect UNISP_NAME_W pointer and contents
    unsafe {
        eprintln!("UNISP_NAME_W ptr = {:p}", Identity::UNISP_NAME_W);

        if !Identity::UNISP_NAME_W.is_null() {
            let mut p = Identity::UNISP_NAME_W;
            for i in 0..16 {
                let v = *p;
                eprintln!("UNISP_NAME_W[{}] = 0x{:04X} ('{}')", i, v, if v >= 32 && v <= 126 { v as u8 as char } else { '?' });
                if v == 0 {
                    break;
                }
                p = p.add(1);
            }
        }
    }

    let direction_flag = Identity::SECPKG_CRED_OUTBOUND;

    // Define function types for raw GetProcAddress calls - using exact Windows signature
    type AcquireCredentialsHandleAFunc = unsafe extern "system" fn(
        *mut i8,                              // pszPrincipal (SEC_CHAR * - mutable)
        *mut i8,                              // pszPackage (SEC_CHAR * - mutable)
        u32,                                  // fCredentialUse
        *mut core::ffi::c_void,               // pvLogonID (PLUID)
        *const core::ffi::c_void,             // pAuthData (PVOID)
        Option<unsafe extern "system" fn()>, // pGetKeyFn (SEC_GET_KEY_FN)
        *const core::ffi::c_void,             // pvGetKeyArgument (PVOID)
        *mut Credentials::SecHandle,          // phCredential (PCredHandle)
        *mut Foundation::FILETIME,            // ptsExpiry (PTimeStamp - as FILETIME)
    ) -> i32;

    type AcquireCredentialsHandleWFunc = unsafe extern "system" fn(
        *mut u16,                             // pszPrincipal (LPWSTR - mutable)
        *mut u16,                             // pszPackage (LPWSTR - mutable)
        u32,                                  // fCredentialUse
        *mut core::ffi::c_void,               // pvLogonID (PLUID)
        *const core::ffi::c_void,             // pAuthData (PVOID)
        Option<unsafe extern "system" fn()>, // pGetKeyFn (SEC_GET_KEY_FN)
        *const core::ffi::c_void,             // pvGetKeyArgument (PVOID)
        *mut Credentials::SecHandle,          // phCredential (PCredHandle)
        *mut Foundation::FILETIME,            // ptsExpiry (PTimeStamp - as FILETIME)
    ) -> i32;

    // Load secur32.dll
    unsafe {
        let secur32_name = b"secur32.dll\0";
        let secur32 = LibraryLoader::GetModuleHandleA(secur32_name.as_ptr() as *const u8);
        if secur32.is_null() {
            eprintln!("Failed to get secur32.dll module handle");
            return;
        }
        eprintln!("secur32.dll module handle: {:p}", secur32);

        // Get raw function pointers via GetProcAddress
        let acquire_a_name = b"AcquireCredentialsHandleA\0";
        let acquire_w_name = b"AcquireCredentialsHandleW\0";
        let acquire_a_raw = LibraryLoader::GetProcAddress(secur32, acquire_a_name.as_ptr() as *const u8);
        let acquire_w_raw = LibraryLoader::GetProcAddress(secur32, acquire_w_name.as_ptr() as *const u8);

        eprintln!("Raw GetProcAddress results:");
        eprintln!("  AcquireCredentialsHandleA: {:?}", acquire_a_raw);
        eprintln!("  AcquireCredentialsHandleW: {:?}", acquire_w_raw);

        if acquire_a_raw.is_none() || acquire_w_raw.is_none() {
            eprintln!("Failed to get function pointers via GetProcAddress");
            return;
        }

        let acquire_a_raw_ptr = acquire_a_raw.unwrap();
        let acquire_w_raw_ptr = acquire_w_raw.unwrap();
        
        eprintln!("Address comparison:");
        eprintln!("  GetProcAddress AcquireCredentialsHandleA: {:p}", acquire_a_raw_ptr);
        eprintln!("  GetProcAddress AcquireCredentialsHandleW: {:p}", acquire_w_raw_ptr);
        
        // Get the addresses of the windows-sys imported functions
        let a_addr = Identity::AcquireCredentialsHandleA as *const () as usize;
        let w_addr = Identity::AcquireCredentialsHandleW as *const () as usize;
        eprintln!("  windows-sys AcquireCredentialsHandleA: 0x{:X}", a_addr);
        eprintln!("  windows-sys AcquireCredentialsHandleW: 0x{:X}", w_addr);
        
        eprintln!("Address comparison:");
        eprintln!("  A addresses match: {}", acquire_a_raw_ptr as usize == a_addr);
        eprintln!("  W addresses match: {}", acquire_w_raw_ptr as usize == w_addr);

        let acquire_a_func: AcquireCredentialsHandleAFunc = mem::transmute(acquire_a_raw_ptr);
        let acquire_w_func: AcquireCredentialsHandleWFunc = mem::transmute(acquire_w_raw_ptr);

        // Test 1: Raw GetProcAddress A with NULL params
        {
            let mut before: u32 = 0x11111111;
            let mut handle: Credentials::SecHandle = mem::zeroed();
            let mut after: u32 = 0x22222222;
            let mut expiry: Foundation::FILETIME = mem::zeroed();
            
            eprintln!("=== Test 1: Raw GetProcAddress AcquireCredentialsHandleA ===");
            eprintln!("  Principal: NULL");
            eprintln!("  Package: UNISP_NAME_A");
            eprintln!("  Direction: 0x{:08X} (SECPKG_CRED_OUTBOUND)", direction_flag);
            eprintln!("  pAuthData: NULL");
            eprintln!("  Canary before: 0x{:08X}", before);
            eprintln!("  Handle before: lower=0x{:08X} upper=0x{:08X}", handle.dwLower, handle.dwUpper);
            eprintln!("  Expiry before: low=0x{:08X} high=0x{:08X}", expiry.dwLowDateTime, expiry.dwHighDateTime);

            let status = acquire_a_func(
                ptr::null_mut(),
                Identity::UNISP_NAME_A as *mut i8,
                direction_flag,
                ptr::null_mut(),
                ptr::null(),
                None,
                ptr::null(),
                &mut handle,
                &mut expiry,
            );
            
            eprintln!("=== Raw A result: 0x{:08X} ===", status);
            eprintln!("  Canary after: 0x{:08X}", after);
            eprintln!("  Handle after: lower=0x{:08X} upper=0x{:08X}", handle.dwLower, handle.dwUpper);
            eprintln!("  Expiry after: low=0x{:08X} high=0x{:08X}", expiry.dwLowDateTime, expiry.dwHighDateTime);
            eprintln!("  Handle address: {:p}", &handle);
            
            if status == Foundation::SEC_E_OK {
                eprintln!("Raw AcquireCredentialsHandleA succeeded");
                let _ = Identity::FreeCredentialsHandle(&handle);
            } else {
                eprintln!("Raw AcquireCredentialsHandleA failed: 0x{:08X}", status);
            }
        }

        // Test 2: Raw GetProcAddress W with NULL params
        {
            let mut before: u32 = 0x33333333;
            let mut handle: Credentials::SecHandle = mem::zeroed();
            let mut after: u32 = 0x44444444;
            let mut expiry: Foundation::FILETIME = mem::zeroed();
            
            eprintln!("=== Test 2: Raw GetProcAddress AcquireCredentialsHandleW ===");
            eprintln!("  Principal: NULL");
            eprintln!("  Package: UNISP_NAME_W");
            eprintln!("  Direction: 0x{:08X} (SECPKG_CRED_OUTBOUND)", direction_flag);
            eprintln!("  pAuthData: NULL");
            eprintln!("  Canary before: 0x{:08X}", before);
            eprintln!("  Handle before: lower=0x{:08X} upper=0x{:08X}", handle.dwLower, handle.dwUpper);
            eprintln!("  Expiry before: low=0x{:08X} high=0x{:08X}", expiry.dwLowDateTime, expiry.dwHighDateTime);

            let status = acquire_w_func(
                ptr::null_mut(),
                Identity::UNISP_NAME_W as *mut u16,
                direction_flag,
                ptr::null_mut(),
                ptr::null(),
                None,
                ptr::null(),
                &mut handle,
                &mut expiry,
            );
            
            eprintln!("=== Raw W result: 0x{:08X} ===", status);
            eprintln!("  Canary after: 0x{:08X}", after);
            eprintln!("  Handle after: lower=0x{:08X} upper=0x{:08X}", handle.dwLower, handle.dwUpper);
            eprintln!("  Expiry after: low=0x{:08X} high=0x{:08X}", expiry.dwLowDateTime, expiry.dwHighDateTime);
            eprintln!("  Handle address: {:p}", &handle);
            
            if status == Foundation::SEC_E_OK {
                eprintln!("Raw AcquireCredentialsHandleW succeeded");
                let _ = Identity::FreeCredentialsHandle(&handle);
            } else {
                eprintln!("Raw AcquireCredentialsHandleW failed: 0x{:08X}", status);
            }
        }

        // Test 3: windows-sys A with NULL params
        {
            let mut handle: Credentials::SecHandle = mem::zeroed();
            
            eprintln!("=== Test 3: windows-sys AcquireCredentialsHandleA ===");
            eprintln!("  Principal: NULL");
            eprintln!("  Package: UNISP_NAME_A");
            eprintln!("  Direction: 0x{:08X} (SECPKG_CRED_OUTBOUND)", direction_flag);
            eprintln!("  pAuthData: NULL");

            let status = Identity::AcquireCredentialsHandleA(
                ptr::null(),
                Identity::UNISP_NAME_A,
                direction_flag,
                ptr::null_mut(),
                ptr::null(),
                None,
                ptr::null_mut(),
                &mut handle,
                ptr::null_mut(),
            );
            
            eprintln!("=== windows-sys A result: 0x{:08X} ===", status);
            
            if status == Foundation::SEC_E_OK {
                eprintln!("windows-sys AcquireCredentialsHandleA succeeded");
                let _ = Identity::FreeCredentialsHandle(&handle);
            } else {
                eprintln!("windows-sys AcquireCredentialsHandleA failed: 0x{:08X}", status);
            }
        }

        // Test 4: windows-sys W with NULL params
        {
            let mut handle: Credentials::SecHandle = mem::zeroed();
            
            eprintln!("=== Test 4: windows-sys AcquireCredentialsHandleW ===");
            eprintln!("  Principal: NULL");
            eprintln!("  Package: UNISP_NAME_W");
            eprintln!("  Direction: 0x{:08X} (SECPKG_CRED_OUTBOUND)", direction_flag);
            eprintln!("  pAuthData: NULL");

            let status = Identity::AcquireCredentialsHandleW(
                ptr::null(),
                Identity::UNISP_NAME_W,
                direction_flag,
                ptr::null_mut(),
                ptr::null(),
                None,
                ptr::null_mut(),
                &mut handle,
                ptr::null_mut(),
            );
            
            eprintln!("=== windows-sys W result: 0x{:08X} ===", status);
            
            if status == Foundation::SEC_E_OK {
                eprintln!("windows-sys AcquireCredentialsHandleW succeeded");
                let _ = Identity::FreeCredentialsHandle(&handle);
            } else {
                eprintln!("windows-sys AcquireCredentialsHandleW failed: 0x{:08X}", status);
            }
        }
    }

    eprintln!("=== Complete test suite finished ===");
    eprintln!("=== Summary: Raw A | Raw W | windows-sys A | windows-sys W ===");
}

#[test]
fn test_initialize_security_context_a_vs_w() {
    use windows_sys::Win32::Foundation;
    use windows_sys::Win32::Security::Authentication::Identity;
    use windows_sys::Win32::Security::Credentials;
    use windows_sys::Win32::System::LibraryLoader;

    eprintln!("=== Testing InitializeSecurityContextA vs W ===");
    eprintln!("=== Test: Raw GetProcAddress A vs W vs windows-sys A vs W ===");

    let direction_flag = Identity::SECPKG_CRED_OUTBOUND;
    let requests = Identity::ISC_REQ_CONFIDENTIALITY | Identity::ISC_REQ_STREAM;

    // Define function types for InitializeSecurityContext
    type InitializeSecurityContextAFunc = unsafe extern "system" fn(
        *const Credentials::SecHandle,           // phCredential
        *const Credentials::SecHandle,           // phContext
        *const i8,                               // pszTargetName
        u32,                                     // fContextReq
        u32,                                     // Reserved1
        u32,                                     // TargetDataRep
        *const Identity::SecBufferDesc,          // pInput
        u32,                                     // Reserved2
        *mut Credentials::SecHandle,             // phNewContext
        *mut Identity::SecBufferDesc,            // pOutput
        *mut u32,                               // pfContextAttr
        *mut Foundation::FILETIME,              // ptsExpiry (as FILETIME)
    ) -> i32;

    type InitializeSecurityContextWFunc = unsafe extern "system" fn(
        *const Credentials::SecHandle,           // phCredential
        *const Credentials::SecHandle,           // phContext
        *const u16,                             // pszTargetName
        u32,                                     // fContextReq
        u32,                                     // Reserved1
        u32,                                     // TargetDataRep
        *const Identity::SecBufferDesc,          // pInput
        u32,                                     // Reserved2
        *mut Credentials::SecHandle,             // phNewContext
        *mut Identity::SecBufferDesc,            // pOutput
        *mut u32,                               // pfContextAttr
        *mut Foundation::FILETIME,              // ptsExpiry (as FILETIME)
    ) -> i32;

    // Load secur32.dll
    unsafe {
        let secur32_name = b"secur32.dll\0";
        let secur32 = LibraryLoader::GetModuleHandleA(secur32_name.as_ptr() as *const u8);
        if secur32.is_null() {
            eprintln!("Failed to get secur32.dll module handle");
            return;
        }
        eprintln!("secur32.dll module handle: {:p}", secur32);

        // Get raw function pointers via GetProcAddress
        let init_a_name = b"InitializeSecurityContextA\0";
        let init_w_name = b"InitializeSecurityContextW\0";
        let init_a_raw = LibraryLoader::GetProcAddress(secur32, init_a_name.as_ptr() as *const u8);
        let init_w_raw = LibraryLoader::GetProcAddress(secur32, init_w_name.as_ptr() as *const u8);

        eprintln!("Raw GetProcAddress results:");
        eprintln!("  InitializeSecurityContextA: {:?}", init_a_raw);
        eprintln!("  InitializeSecurityContextW: {:?}", init_w_raw);

        if init_a_raw.is_none() || init_w_raw.is_none() {
            eprintln!("Failed to get function pointers via GetProcAddress");
            return;
        }

        let init_a_raw_ptr = init_a_raw.unwrap();
        let init_w_raw_ptr = init_w_raw.unwrap();
        
        eprintln!("Address comparison:");
        eprintln!("  GetProcAddress InitializeSecurityContextA: {:p}", init_a_raw_ptr);
        eprintln!("  GetProcAddress InitializeSecurityContextW: {:p}", init_w_raw_ptr);
        
        // Get the addresses of the windows-sys imported functions
        let init_a_addr = Identity::InitializeSecurityContextA as *const () as usize;
        let init_w_addr = Identity::InitializeSecurityContextW as *const () as usize;
        eprintln!("  windows-sys InitializeSecurityContextA: 0x{:X}", init_a_addr);
        eprintln!("  windows-sys InitializeSecurityContextW: 0x{:X}", init_w_addr);
        
        eprintln!("Address comparison:");
        eprintln!("  A addresses match: {}", init_a_raw_ptr as usize == init_a_addr);
        eprintln!("  W addresses match: {}", init_w_raw_ptr as usize == init_w_addr);

        // First, acquire a credential using raw W (which we know works)
        type AcquireCredentialsHandleWFunc = unsafe extern "system" fn(
            *mut u16,
            *mut u16,
            u32,
            *mut core::ffi::c_void,
            *const core::ffi::c_void,
            Option<unsafe extern "system" fn()>,
            *const core::ffi::c_void,
            *mut Credentials::SecHandle,
            *mut Foundation::FILETIME,
        ) -> i32;

        let acquire_w_name = b"AcquireCredentialsHandleW\0";
        let acquire_w_raw = LibraryLoader::GetProcAddress(secur32, acquire_w_name.as_ptr() as *const u8);
        
        if acquire_w_raw.is_none() {
            eprintln!("Failed to get AcquireCredentialsHandleW pointer");
            return;
        }

        let acquire_w_func: AcquireCredentialsHandleWFunc = mem::transmute(acquire_w_raw.unwrap());

        let mut cred: Credentials::SecHandle = mem::zeroed();
        let mut expiry: Foundation::FILETIME = mem::zeroed();

        let acquire_status = acquire_w_func(
            ptr::null_mut(),
            Identity::UNISP_NAME_W as *mut u16,
            direction_flag,
            ptr::null_mut(),
            ptr::null(),
            None,
            ptr::null(),
            &mut cred,
            &mut expiry,
        );

        if acquire_status != Foundation::SEC_E_OK {
            eprintln!("Failed to acquire credential with raw W: 0x{:08X}", acquire_status);
            return;
        }

        eprintln!("Credential acquired successfully with raw W");
        eprintln!("Credential handle: lower=0x{:08X} upper=0x{:08X}", cred.dwLower, cred.dwUpper);
        eprintln!("Credential object address: {:p}", &cred);
        eprintln!("Credential size: {} bytes", std::mem::size_of::<Credentials::SecHandle>());

        // Use ISC_REQ_ALLOCATE_MEMORY for proper buffer allocation
        let requests_with_alloc = requests | Identity::ISC_REQ_ALLOCATE_MEMORY;
        eprintln!("Requests with ALLOCATE_MEMORY: 0x{:08X}", requests_with_alloc);

        // Define QueryCredentialsAttributes function type
        type QueryCredentialsAttributesAFunc = unsafe extern "system" fn(
            *const Credentials::SecHandle,
            u32,
            *mut core::ffi::c_void,
        ) -> i32;

        type QueryCredentialsAttributesWFunc = unsafe extern "system" fn(
            *const Credentials::SecHandle,
            u32,
            *mut core::ffi::c_void,
        ) -> i32;

        // Get QueryCredentialsAttributes function pointers
        let query_a_name = b"QueryCredentialsAttributesA\0";
        let query_w_name = b"QueryCredentialsAttributesW\0";
        let query_a_raw = LibraryLoader::GetProcAddress(secur32, query_a_name.as_ptr() as *const u8);
        let query_w_raw = LibraryLoader::GetProcAddress(secur32, query_w_name.as_ptr() as *const u8);

        eprintln!("QueryCredentialsAttributes pointers:");
        eprintln!("  QueryCredentialsAttributesA: {:?}", query_a_raw);
        eprintln!("  QueryCredentialsAttributesW: {:?}", query_w_raw);

        if let Some(query_a_ptr) = query_a_raw {
            let query_a_func: QueryCredentialsAttributesAFunc = mem::transmute(query_a_ptr);
            
            // Test with SECPKG_CRED_ATTR_NAMES attribute using correct structure
            let mut names = SecPkgCredentialsNamesA {
                s_user_name: ptr::null_mut(),
            };
            let query_status = query_a_func(
                &cred,
                Identity::SECPKG_CRED_ATTR_NAMES,
                &mut names as *mut _ as *mut core::ffi::c_void,
            );
            
            eprintln!("QueryCredentialsAttributesA result: 0x{:08X}", query_status);
            
            if query_status == Foundation::SEC_E_OK {
                eprintln!("  Credential handle is VALID (QueryCredentialsAttributesA succeeded)");
                if !names.s_user_name.is_null() {
                    eprintln!("  Username ptr: {:p}", names.s_user_name);
                    // Free the string allocated by SSPI
                    let _ = Identity::FreeContextBuffer(names.s_user_name as *mut core::ffi::c_void);
                }
            } else {
                eprintln!("  Credential handle is INVALID (QueryCredentialsAttributesA failed)");
            }
        }

        if let Some(query_w_ptr) = query_w_raw {
            let query_w_func: QueryCredentialsAttributesWFunc = mem::transmute(query_w_ptr);
            
            // Test with SECPKG_CRED_ATTR_NAMES attribute using correct structure
            let mut names = SecPkgCredentialsNamesW {
                s_user_name: ptr::null_mut(),
            };
            let query_status = query_w_func(
                &cred,
                Identity::SECPKG_CRED_ATTR_NAMES,
                &mut names as *mut _ as *mut core::ffi::c_void,
            );
            
            eprintln!("QueryCredentialsAttributesW result: 0x{:08X}", query_status);
            
            if query_status == Foundation::SEC_E_OK {
                eprintln!("  Credential handle is VALID (QueryCredentialsAttributesW succeeded)");
                if !names.s_user_name.is_null() {
                    eprintln!("  Username ptr: {:p}", names.s_user_name);
                    // Free the string allocated by SSPI
                    let _ = Identity::FreeContextBuffer(names.s_user_name as *mut core::ffi::c_void);
                }
            } else {
                eprintln!("  Credential handle is INVALID (QueryCredentialsAttributesW failed)");
            }
        }

        // Now test InitializeSecurityContext with the acquired credential
        let target_name_w: Vec<u16> = "example.com\0".encode_utf16().collect();
        let target_name_a: Vec<u8> = "example.com\0".bytes().collect();
        
        // Build proper 3-buffer output setup for Schannel
        let mut outbuf_a = [
            Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            },
            Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_ALERT,
                pvBuffer: ptr::null_mut(),
            },
            Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_EMPTY,
                pvBuffer: ptr::null_mut(),
            },
        ];

        let mut outbuf_w = [
            Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            },
            Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_ALERT,
                pvBuffer: ptr::null_mut(),
            },
            Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_EMPTY,
                pvBuffer: ptr::null_mut(),
            },
        ];

        let init_a_func: InitializeSecurityContextAFunc = mem::transmute(init_a_raw_ptr);
        let init_w_func: InitializeSecurityContextWFunc = mem::transmute(init_w_raw_ptr);

        // Test 1: Raw InitializeSecurityContextA
        {
            let mut ctxt: Credentials::SecHandle = mem::zeroed();
            let mut attrs: u32 = 0;
            let mut expiry: Foundation::FILETIME = mem::zeroed();
            let mut outdesc = Identity::SecBufferDesc {
                ulVersion: Identity::SECBUFFER_VERSION,
                cBuffers: 3,
                pBuffers: outbuf_a.as_mut_ptr(),
            };
            
            eprintln!("=== Test 1: Raw InitializeSecurityContextA ===");
            eprintln!("  Credential: from raw W AcquireCredentialsHandleW");
            eprintln!("  Target: example.com");
            eprintln!("  Requests: 0x{:08X} (with ALLOCATE_MEMORY)", requests_with_alloc);

            let status = init_a_func(
                &cred,
                ptr::null(),
                target_name_a.as_ptr() as *const i8,
                requests_with_alloc,
                0,
                0,
                ptr::null(),
                0,
                &mut ctxt,
                &mut outdesc,
                &mut attrs,
                &mut expiry,
            );
            
            eprintln!("=== Raw A result: 0x{:08X} ===", status);
            
            if status == Foundation::SEC_E_OK || status == Foundation::SEC_I_CONTINUE_NEEDED {
                eprintln!("Raw InitializeSecurityContextA succeeded or continue needed");
                eprintln!("  Token buffer: ptr={:p}, size={}", outbuf_a[0].pvBuffer, outbuf_a[0].cbBuffer);
                if !outbuf_a[0].pvBuffer.is_null() {
                    let _ = Identity::FreeContextBuffer(outbuf_a[0].pvBuffer);
                }
                let _ = Identity::DeleteSecurityContext(&mut ctxt);
            } else {
                eprintln!("Raw InitializeSecurityContextA failed: 0x{:08X}", status);
            }
        }

        // Test 2: Raw InitializeSecurityContextW
        {
            let mut ctxt: Credentials::SecHandle = mem::zeroed();
            let mut attrs: u32 = 0;
            let mut expiry: Foundation::FILETIME = mem::zeroed();
            let mut outdesc = Identity::SecBufferDesc {
                ulVersion: Identity::SECBUFFER_VERSION,
                cBuffers: 3,
                pBuffers: outbuf_w.as_mut_ptr(),
            };
            
            eprintln!("=== Test 2: Raw InitializeSecurityContextW ===");
            eprintln!("  Credential: from raw W AcquireCredentialsHandleW");
            eprintln!("  Target: example.com");
            eprintln!("  Requests: 0x{:08X} (with ALLOCATE_MEMORY)", requests_with_alloc);

            let status = init_w_func(
                &cred,
                ptr::null(),
                target_name_w.as_ptr(),
                requests_with_alloc,
                0,
                0,
                ptr::null(),
                0,
                &mut ctxt,
                &mut outdesc,
                &mut attrs,
                &mut expiry,
            );
            
            eprintln!("=== Raw W result: 0x{:08X} ===", status);
            
            if status == Foundation::SEC_E_OK || status == Foundation::SEC_I_CONTINUE_NEEDED {
                eprintln!("Raw InitializeSecurityContextW succeeded or continue needed");
                eprintln!("  Token buffer: ptr={:p}, size={}", outbuf_w[0].pvBuffer, outbuf_w[0].cbBuffer);
                if !outbuf_w[0].pvBuffer.is_null() {
                    let _ = Identity::FreeContextBuffer(outbuf_w[0].pvBuffer);
                }
                let _ = Identity::DeleteSecurityContext(&mut ctxt);
            } else {
                eprintln!("Raw InitializeSecurityContextW failed: 0x{:08X}", status);
            }
        }

        // Test 3: windows-sys InitializeSecurityContextA
        {
            let mut ctxt: Credentials::SecHandle = mem::zeroed();
            let mut attrs: u32 = 0;
            let mut expiry_sys: i64 = 0;
            let mut outbuf_sys = [
                Identity::SecBuffer {
                    cbBuffer: 0,
                    BufferType: Identity::SECBUFFER_TOKEN,
                    pvBuffer: ptr::null_mut(),
                },
                Identity::SecBuffer {
                    cbBuffer: 0,
                    BufferType: Identity::SECBUFFER_ALERT,
                    pvBuffer: ptr::null_mut(),
                },
                Identity::SecBuffer {
                    cbBuffer: 0,
                    BufferType: Identity::SECBUFFER_EMPTY,
                    pvBuffer: ptr::null_mut(),
                },
            ];
            let mut outdesc = Identity::SecBufferDesc {
                ulVersion: Identity::SECBUFFER_VERSION,
                cBuffers: 3,
                pBuffers: outbuf_sys.as_mut_ptr(),
            };
            
            eprintln!("=== Test 3: windows-sys InitializeSecurityContextA ===");
            eprintln!("  Credential: from raw W AcquireCredentialsHandleW");
            eprintln!("  Target: example.com");
            eprintln!("  Requests: 0x{:08X} (with ALLOCATE_MEMORY)", requests_with_alloc);

            let status = Identity::InitializeSecurityContextA(
                &cred,
                ptr::null(),
                target_name_a.as_ptr() as *const i8,
                requests_with_alloc,
                0,
                0,
                ptr::null(),
                0,
                &mut ctxt,
                &mut outdesc,
                &mut attrs,
                &mut expiry_sys,
            );
            
            eprintln!("=== windows-sys A result: 0x{:08X} ===", status);
            
            if status == Foundation::SEC_E_OK || status == Foundation::SEC_I_CONTINUE_NEEDED {
                eprintln!("windows-sys InitializeSecurityContextA succeeded or continue needed");
                eprintln!("  Token buffer: ptr={:p}, size={}", outbuf_sys[0].pvBuffer, outbuf_sys[0].cbBuffer);
                if !outbuf_sys[0].pvBuffer.is_null() {
                    let _ = Identity::FreeContextBuffer(outbuf_sys[0].pvBuffer);
                }
                let _ = Identity::DeleteSecurityContext(&mut ctxt);
            } else {
                eprintln!("windows-sys InitializeSecurityContextA failed: 0x{:08X}", status);
            }
        }

        // Test 4: windows-sys InitializeSecurityContextW
        {
            let mut ctxt: Credentials::SecHandle = mem::zeroed();
            let mut attrs: u32 = 0;
            let mut expiry_sys: i64 = 0;
            let mut outbuf_sys = [
                Identity::SecBuffer {
                    cbBuffer: 0,
                    BufferType: Identity::SECBUFFER_TOKEN,
                    pvBuffer: ptr::null_mut(),
                },
                Identity::SecBuffer {
                    cbBuffer: 0,
                    BufferType: Identity::SECBUFFER_ALERT,
                    pvBuffer: ptr::null_mut(),
                },
                Identity::SecBuffer {
                    cbBuffer: 0,
                    BufferType: Identity::SECBUFFER_EMPTY,
                    pvBuffer: ptr::null_mut(),
                },
            ];
            let mut outdesc = Identity::SecBufferDesc {
                ulVersion: Identity::SECBUFFER_VERSION,
                cBuffers: 3,
                pBuffers: outbuf_sys.as_mut_ptr(),
            };
            
            eprintln!("=== Test 4: windows-sys InitializeSecurityContextW ===");
            eprintln!("  Credential: from raw W AcquireCredentialsHandleW");
            eprintln!("  Target: example.com");
            eprintln!("  Requests: 0x{:08X} (with ALLOCATE_MEMORY)", requests_with_alloc);

            let status = Identity::InitializeSecurityContextW(
                &cred,
                ptr::null(),
                target_name_w.as_ptr(),
                requests_with_alloc,
                0,
                0,
                ptr::null(),
                0,
                &mut ctxt,
                &mut outdesc,
                &mut attrs,
                &mut expiry_sys,
            );
            
            eprintln!("=== windows-sys W result: 0x{:08X} ===", status);
            
            if status == Foundation::SEC_E_OK || status == Foundation::SEC_I_CONTINUE_NEEDED {
                eprintln!("windows-sys InitializeSecurityContextW succeeded or continue needed");
                eprintln!("  Token buffer: ptr={:p}, size={}", outbuf_sys[0].pvBuffer, outbuf_sys[0].cbBuffer);
                if !outbuf_sys[0].pvBuffer.is_null() {
                    let _ = Identity::FreeContextBuffer(outbuf_sys[0].pvBuffer);
                }
                let _ = Identity::DeleteSecurityContext(&mut ctxt);
            } else {
                eprintln!("windows-sys InitializeSecurityContextW failed: 0x{:08X}", status);
            }
        }

        // Clean up credential
        let _ = Identity::FreeCredentialsHandle(&cred);
    }

    eprintln!("=== InitializeSecurityContext test suite finished ===");
    eprintln!("=== Summary: Raw A | Raw W | windows-sys A | windows-sys W ===");
}

#[repr(C)]
struct SecPkgCredentialsNamesW {
    s_user_name: *mut u16,
}

#[repr(C)]
struct SecPkgCredentialsNamesA {
    s_user_name: *mut i8,
}

#[test]
fn test_credential_isc_matrix() {
    use windows_sys::Win32::Foundation;
    use windows_sys::Win32::Security::Authentication::Identity;
    use windows_sys::Win32::Security::Credentials;
    use windows_sys::Win32::System::LibraryLoader;

    eprintln!("=== Testing Credential/ISC Matrix ===");
    eprintln!("=== Test: Acquire A/W vs ISC A/W combinations ===");

    let direction_flag = Identity::SECPKG_CRED_OUTBOUND;
    let requests = Identity::ISC_REQ_CONFIDENTIALITY | Identity::ISC_REQ_STREAM;

    // Define function types - using exact Windows signature
    type AcquireCredentialsHandleAFunc = unsafe extern "system" fn(
        *mut i8, *mut i8, u32, *mut core::ffi::c_void, *const core::ffi::c_void,
        Option<unsafe extern "system" fn()>, *const core::ffi::c_void,
        *mut Credentials::SecHandle, *mut Foundation::FILETIME,
    ) -> i32;

    type AcquireCredentialsHandleWFunc = unsafe extern "system" fn(
        *mut u16, *mut u16, u32, *mut core::ffi::c_void, *const core::ffi::c_void,
        Option<unsafe extern "system" fn()>, *const core::ffi::c_void,
        *mut Credentials::SecHandle, *mut Foundation::FILETIME,
    ) -> i32;

    type InitializeSecurityContextAFunc = unsafe extern "system" fn(
        *const Credentials::SecHandle, *const Credentials::SecHandle, *const i8,
        u32, u32, u32, *const Identity::SecBufferDesc, u32,
        *mut Credentials::SecHandle, *mut Identity::SecBufferDesc, *mut u32, *mut i64,
    ) -> i32;

    type InitializeSecurityContextWFunc = unsafe extern "system" fn(
        *const Credentials::SecHandle, *const Credentials::SecHandle, *const u16,
        u32, u32, u32, *const Identity::SecBufferDesc, u32,
        *mut Credentials::SecHandle, *mut Identity::SecBufferDesc, *mut u32, *mut i64,
    ) -> i32;

    unsafe {
        let secur32_name = b"secur32.dll\0";
        let secur32 = LibraryLoader::GetModuleHandleA(secur32_name.as_ptr() as *const u8);
        if secur32.is_null() {
            eprintln!("Failed to get secur32.dll module handle");
            return;
        }

        // Get function pointers
        let acquire_a_raw = LibraryLoader::GetProcAddress(secur32, b"AcquireCredentialsHandleA\0".as_ptr() as *const u8);
        let acquire_w_raw = LibraryLoader::GetProcAddress(secur32, b"AcquireCredentialsHandleW\0".as_ptr() as *const u8);
        let init_a_raw = LibraryLoader::GetProcAddress(secur32, b"InitializeSecurityContextA\0".as_ptr() as *const u8);
        let init_w_raw = LibraryLoader::GetProcAddress(secur32, b"InitializeSecurityContextW\0".as_ptr() as *const u8);

        if acquire_a_raw.is_none() || acquire_w_raw.is_none() || init_a_raw.is_none() || init_w_raw.is_none() {
            eprintln!("Failed to get function pointers");
            return;
        }

        let acquire_a_func: AcquireCredentialsHandleAFunc = mem::transmute(acquire_a_raw.unwrap());
        let acquire_w_func: AcquireCredentialsHandleWFunc = mem::transmute(acquire_w_raw.unwrap());
        let init_a_func: InitializeSecurityContextAFunc = mem::transmute(init_a_raw.unwrap());
        let init_w_func: InitializeSecurityContextWFunc = mem::transmute(init_w_raw.unwrap());

        let target_name_w: Vec<u16> = "example.com\0".encode_utf16().collect();
        let target_name_a: Vec<u8> = "example.com\0".bytes().collect();

        // Test matrix: Acquire A/W vs ISC A/W
        let combinations = [
            ("Acquire A", "ISC A"),
            ("Acquire A", "ISC W"),
            ("Acquire W", "ISC A"),
            ("Acquire W", "ISC W"),
        ];

        for (acquire_method, isc_method) in combinations.iter() {
            eprintln!("=== Test: {} → {} ===", acquire_method, isc_method);

            let mut cred: Credentials::SecHandle = mem::zeroed();
            let mut expiry: Foundation::FILETIME = mem::zeroed();

            // Acquire credential
            let acquire_status = if *acquire_method == "Acquire A" {
                acquire_a_func(
                    ptr::null_mut(),
                    Identity::UNISP_NAME_A as *mut i8,
                    direction_flag,
                    ptr::null_mut(),
                    ptr::null(),
                    None,
                    ptr::null(),
                    &mut cred,
                    &mut expiry,
                )
            } else {
                acquire_w_func(
                    ptr::null_mut(),
                    Identity::UNISP_NAME_W,
                    direction_flag,
                    ptr::null_mut(),
                    ptr::null(),
                    None,
                    ptr::null(),
                    &mut cred,
                    &mut expiry,
                )
            };

            if acquire_status != Foundation::SEC_E_OK {
                eprintln!("  Acquire failed: 0x{:08X}", acquire_status);
                continue;
            }

            eprintln!("  Credential acquired: lower=0x{:08X} upper=0x{:08X}", cred.dwLower, cred.dwUpper);
            eprintln!("  Credential address: {:p}", &cred);

            // Test credential handle validity with QueryCredentialsAttributes
            let query_a_raw = LibraryLoader::GetProcAddress(secur32, b"QueryCredentialsAttributesA\0".as_ptr() as *const u8);
            let query_w_raw = LibraryLoader::GetProcAddress(secur32, b"QueryCredentialsAttributesW\0".as_ptr() as *const u8);

            type QueryCredentialsAttributesAFunc = unsafe extern "system" fn(
                *const Credentials::SecHandle, u32, *mut core::ffi::c_void,
            ) -> i32;

            type QueryCredentialsAttributesWFunc = unsafe extern "system" fn(
                *const Credentials::SecHandle, u32, *mut core::ffi::c_void,
            ) -> i32;

            if let Some(query_a_ptr) = query_a_raw {
                let query_a_func: QueryCredentialsAttributesAFunc = mem::transmute(query_a_ptr);
                let mut names = SecPkgCredentialsNamesA {
                    s_user_name: ptr::null_mut(),
                };
                let query_status = query_a_func(
                    &cred,
                    Identity::SECPKG_CRED_ATTR_NAMES,
                    &mut names as *mut _ as *mut core::ffi::c_void,
                );
                eprintln!("  QueryCredentialsAttributesA: 0x{:08X}", query_status);
                if query_status == Foundation::SEC_E_OK && !names.s_user_name.is_null() {
                    let _ = Identity::FreeContextBuffer(names.s_user_name as *mut core::ffi::c_void);
                }
            }

            if let Some(query_w_ptr) = query_w_raw {
                let query_w_func: QueryCredentialsAttributesWFunc = mem::transmute(query_w_ptr);
                let mut names = SecPkgCredentialsNamesW {
                    s_user_name: ptr::null_mut(),
                };
                let query_status = query_w_func(
                    &cred,
                    Identity::SECPKG_CRED_ATTR_NAMES,
                    &mut names as *mut _ as *mut core::ffi::c_void,
                );
                eprintln!("  QueryCredentialsAttributesW: 0x{:08X}", query_status);
                if query_status == Foundation::SEC_E_OK && !names.s_user_name.is_null() {
                    let _ = Identity::FreeContextBuffer(names.s_user_name as *mut core::ffi::c_void);
                }
            }

            // Build output buffer
            let mut outbuf = Identity::SecBuffer {
                cbBuffer: 0,
                BufferType: Identity::SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            };

            let mut outdesc = Identity::SecBufferDesc {
                ulVersion: Identity::SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut outbuf,
            };

            // Call InitializeSecurityContext
            let mut ctxt: Credentials::SecHandle = mem::zeroed();
            let mut attrs: u32 = 0;
            let mut expiry_isc: Foundation::FILETIME = mem::zeroed();

            let isc_status = if *isc_method == "ISC A" {
                eprintln!("  Before ISC A: lower=0x{:08X} upper=0x{:08X}", cred.dwLower, cred.dwUpper);
                init_a_func(
                    &cred,
                    ptr::null(),
                    target_name_a.as_ptr() as *const i8,
                    requests,
                    0,
                    0,
                    ptr::null(),
                    0,
                    &mut ctxt,
                    &mut outdesc,
                    &mut attrs,
                    &mut expiry_isc,
                )
            } else {
                eprintln!("  Before ISC W: lower=0x{:08X} upper=0x{:08X}", cred.dwLower, cred.dwUpper);
                init_w_func(
                    &cred,
                    ptr::null(),
                    target_name_w.as_ptr(),
                    requests,
                    0,
                    0,
                    ptr::null(),
                    0,
                    &mut ctxt,
                    &mut outdesc,
                    &mut attrs,
                    &mut expiry_isc,
                )
            };

            eprintln!("  ISC result: 0x{:08X}", isc_status);

            if isc_status == Foundation::SEC_E_OK || isc_status == Foundation::SEC_I_CONTINUE_NEEDED {
                eprintln!("  ISC succeeded or continue needed");
                let _ = Identity::DeleteSecurityContext(&mut ctxt);
            } else {
                eprintln!("  ISC failed: 0x{:08X}", isc_status);
            }

            // Clean up credential
            let _ = Identity::FreeCredentialsHandle(&cred);
        }
    }

    eprintln!("=== Credential/ISC matrix test finished ===");
}
