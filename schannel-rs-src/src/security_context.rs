use std::io;
use std::mem;
use std::ptr;

use log::{debug, error, info, trace, warn};
use windows_sys::Win32::Foundation;
use windows_sys::Win32::Security::Authentication::Identity;
use windows_sys::Win32::Security::Credentials;

use crate::alpn_list::AlpnList;
use crate::cert_context::CertContext;
use crate::context_buffer::ContextBuffer;
use crate::schannel_cred::SchannelCred;
use crate::{log_init_requests, secbuf, secbuf_desc, Inner, INIT_REQUESTS};

pub struct SecurityContext(Credentials::SecHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        debug!("SecurityContext::drop called, deleting security context");
        unsafe {
            let result = Identity::DeleteSecurityContext(&self.0);
            if result != Foundation::SEC_E_OK {
                warn!("DeleteSecurityContext failed with error: 0x{:08X}", result);
            } else {
                debug!("DeleteSecurityContext succeeded");
            }
        }
    }
}

impl Inner<Credentials::SecHandle> for SecurityContext {
    unsafe fn from_inner(inner: Credentials::SecHandle) -> SecurityContext {
        debug!("SecurityContext::from_inner called");
        SecurityContext(inner)
    }

    fn as_inner(&self) -> Credentials::SecHandle {
        trace!("SecurityContext::as_inner called");
        self.0
    }

    fn get_mut(&mut self) -> &mut Credentials::SecHandle {
        trace!("SecurityContext::get_mut called");
        &mut self.0
    }
}

impl SecurityContext {
    pub fn initialize(
        cred: &mut SchannelCred,
        accept: bool,
        domain: Option<&[u16]>,
        requested_application_protocols: &Option<Vec<Vec<u8>>>,
    ) -> io::Result<(SecurityContext, Option<ContextBuffer>)> {
        info!("SecurityContext::initialize called");
        info!("  accept: {}", accept);
        info!("  domain: {:?}", domain.map(|d| String::from_utf16_lossy(d)));
        info!("  requested_application_protocols: {} protocols", 
              requested_application_protocols.as_ref().map(|p| p.len()).unwrap_or(0));

        // Log INIT_REQUESTS flags
        log_init_requests();

        unsafe {
            let mut ctxt = mem::zeroed();

            if accept {
                // If we're performing an accept then we need to wait to call
                // `AcceptSecurityContext` until we've actually read some data.
                info!("Accept mode: delaying AcceptSecurityContext until data is available");
                return Ok((SecurityContext(ctxt), None));
            }

            let domain_ptr = domain.map(|b| b.as_ptr()).unwrap_or(ptr::null_mut());
            info!("Domain/SNI pointer: {:p}", domain_ptr);

            let mut inbufs = vec![];
            info!("Creating input buffers");

            // Make sure `AlpnList` is kept alive for the duration of this function.
            let mut alpns = requested_application_protocols
                .as_ref()
                .map(|alpn| {
                    info!("Creating ALPN list with {} protocols", alpn.len());
                    for (i, proto) in alpn.iter().enumerate() {
                        debug!("  ALPN[{}]: {:?}", i, String::from_utf8_lossy(proto));
                    }
                    AlpnList::new(alpn)
                });
            if let Some(ref mut alpns) = alpns {
                debug!("Adding SECBUFFER_APPLICATION_PROTOCOLS buffer");
                inbufs.push(secbuf(
                    Identity::SECBUFFER_APPLICATION_PROTOCOLS,
                    Some(&mut alpns[..]),
                ));
            };

            info!("Input buffer count: {}", inbufs.len());
            let inbuf_desc = secbuf_desc(&mut inbufs[..]);

            let mut outbuf = [secbuf(Identity::SECBUFFER_EMPTY, None)];
            info!("Creating output buffer: SECBUFFER_EMPTY");
            let mut outbuf_desc = secbuf_desc(&mut outbuf);

            let mut attributes = 0;
            info!("Calling InitializeSecurityContextW");
            info!("  Credential handle: {:p}", &cred.as_inner());
            info!("  Context: NULL (first call)");
            info!("  Domain: {:p}", domain_ptr);
            info!("  INIT_REQUESTS: 0x{:08X}", INIT_REQUESTS);
            info!("  Reserved1: 0");
            info!("  TargetDataRep: 0");
            info!("  Input buffers: {} buffers", inbufs.len());
            info!("  Reserved2: 0");
            info!("  Output context: {:p}", &mut ctxt);
            info!("  Output buffers: 1 buffer");
            info!("  Attributes: {:p}", &mut attributes);
            info!("  Expiration: NULL");

            match Identity::InitializeSecurityContextW(
                &cred.as_inner(),
                ptr::null_mut(),
                domain_ptr,
                INIT_REQUESTS,
                0,
                0,
                &inbuf_desc,
                0,
                &mut ctxt,
                &mut outbuf_desc,
                &mut attributes,
                ptr::null_mut(),
            ) {
                Foundation::SEC_I_CONTINUE_NEEDED => {
                    info!("InitializeSecurityContextW returned SEC_I_CONTINUE_NEEDED (0x{:08X})", Foundation::SEC_I_CONTINUE_NEEDED);
                    info!("  Attributes: 0x{:08X}", attributes);
                    debug!("  Context attributes:");
                    debug!("    ASC_RET_ALLOCATED_MEMORY: {}", (attributes & Identity::ASC_RET_ALLOCATED_MEMORY) != 0);
                    debug!("    ASC_RET_CONFIDENTIALITY: {}", (attributes & Identity::ASC_RET_CONFIDENTIALITY) != 0);
                    debug!("    ASC_RET_CONNECTION: {}", (attributes & Identity::ASC_RET_CONNECTION) != 0);
                    debug!("    ASC_RET_USED_DCE_STYLE: {}", (attributes & Identity::ASC_RET_USED_DCE_STYLE) != 0);
                    debug!("    ASC_RET_SEQUENCE_DETECT: {}", (attributes & Identity::ASC_RET_SEQUENCE_DETECT) != 0);
                    debug!("    ASC_RET_REPLAY_DETECT: {}", (attributes & Identity::ASC_RET_REPLAY_DETECT) != 0);
                    debug!("    ASC_RET_EXTENDED_ERROR: {}", (attributes & Identity::ASC_RET_EXTENDED_ERROR) != 0);
                    debug!("    ASC_RET_STREAM: {}", (attributes & Identity::ASC_RET_STREAM) != 0);
                    debug!("    ASC_RET_INTEGRITY: {}", (attributes & Identity::ASC_RET_INTEGRITY) != 0);

                    info!("Output buffer state:");
                    info!("  Buffer type: 0x{:X}", outbuf[0].BufferType);
                    info!("  Buffer length: {}", outbuf[0].cbBuffer);
                    info!("  Buffer pointer: {:p}", outbuf[0].pvBuffer);

                    Ok((SecurityContext(ctxt), Some(ContextBuffer(outbuf[0]))))
                }
                Foundation::SEC_E_OK => {
                    info!("InitializeSecurityContextW returned SEC_E_OK (0x{:08X})", Foundation::SEC_E_OK);
                    info!("  Handshake completed immediately");
                    info!("  Attributes: 0x{:08X}", attributes);
                    Ok((SecurityContext(ctxt), None))
                }
                err => {
                    error!("InitializeSecurityContextW failed with error: 0x{:08X}", err);
                    error!("Error description: {}", io::Error::from_raw_os_error(err));
                    Err(io::Error::from_raw_os_error(err))
                },
            }
        }
    }

    unsafe fn attribute<T>(&self, attr: Identity::SECPKG_ATTR) -> io::Result<T> {
        debug!("SecurityContext::attribute called with attr: 0x{:08X}", attr);
        let mut value = mem::zeroed();
        debug!("Calling QueryContextAttributesW");
        let status =
            Identity::QueryContextAttributesW(&self.0, attr, &mut value as *mut _ as *mut _);
        match status {
            Foundation::SEC_E_OK => {
                debug!("QueryContextAttributesW succeeded (SEC_E_OK)");
                Ok(value)
            },
            err => {
                error!("QueryContextAttributesW failed with error: 0x{:08X}", err);
                Err(io::Error::from_raw_os_error(err))
            },
        }
    }

    pub fn application_protocol(&self) -> io::Result<Identity::SecPkgContext_ApplicationProtocol> {
        debug!("SecurityContext::application_protocol called");
        unsafe { self.attribute(Identity::SECPKG_ATTR_APPLICATION_PROTOCOL) }
    }

    pub fn session_info(&self) -> io::Result<Identity::SecPkgContext_SessionInfo> {
        debug!("SecurityContext::session_info called");
        unsafe { self.attribute(Identity::SECPKG_ATTR_SESSION_INFO) }
    }

    pub fn stream_sizes(&self) -> io::Result<Identity::SecPkgContext_StreamSizes> {
        debug!("SecurityContext::stream_sizes called");
        unsafe { self.attribute(Identity::SECPKG_ATTR_STREAM_SIZES) }
    }

    pub fn remote_cert(&self) -> io::Result<CertContext> {
        debug!("SecurityContext::remote_cert called");
        unsafe {
            self.attribute(Identity::SECPKG_ATTR_REMOTE_CERT_CONTEXT)
                .map(|p| {
                    debug!("Successfully retrieved remote certificate context");
                    CertContext::from_inner(p)
                })
        }
    }

    pub fn local_cert(&self) -> io::Result<CertContext> {
        debug!("SecurityContext::local_cert called");
        unsafe {
            self.attribute(Identity::SECPKG_ATTR_LOCAL_CERT_CONTEXT)
                .map(|p| {
                    debug!("Successfully retrieved local certificate context");
                    CertContext::from_inner(p)
                })
        }
    }
}
