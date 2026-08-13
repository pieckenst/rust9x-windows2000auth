use std::io;
use std::mem;
use std::ptr;

use log::{debug, error, info, trace, warn};
use windows_sys::Win32::Foundation;
use windows_sys::Win32::Security::Authentication::Identity;
use windows_sys::Win32::Security::Credentials;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW,
    GetModuleFileNameW,
};


use crate::alpn_list::AlpnList;
use crate::cert_context::CertContext;
use crate::context_buffer::ContextBuffer;
use crate::schannel_cred::SchannelCred;
use crate::{log_init_requests, secbuf, secbuf_desc, Inner, INIT_REQUESTS};

pub struct SecurityContext(Credentials::SecHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        eprintln!("SecurityContext::drop called, deleting security context");
        unsafe {
            let result = Identity::DeleteSecurityContext(&self.0);
            if result != Foundation::SEC_E_OK {
                eprintln!("DeleteSecurityContext failed with error: 0x{:08X}", result);
            } else {
                eprintln!("DeleteSecurityContext succeeded");
            }
        }
    }
}

impl Inner<Credentials::SecHandle> for SecurityContext {
    unsafe fn from_inner(inner: Credentials::SecHandle) -> SecurityContext {
        eprintln!("SecurityContext::from_inner called");
        SecurityContext(inner)
    }

    fn as_inner(&self) -> Credentials::SecHandle {
        eprintln!("SecurityContext::as_inner called");
        self.0
    }

    fn get_mut(&mut self) -> &mut Credentials::SecHandle {
        eprintln!("SecurityContext::get_mut called");
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
        eprintln!("=== LOCAL SCHANNEL SecurityContext::initialize ENTERED ===");
        eprintln!("SecurityContext::initialize called");
        eprintln!("  accept: {}", accept);
        eprintln!("  domain: {:?}", domain.map(|d| String::from_utf16_lossy(d)));
        eprintln!("  requested_application_protocols: {} protocols", 
              requested_application_protocols.as_ref().map(|p| p.len()).unwrap_or(0));

        // Log INIT_REQUESTS flags
        log_init_requests();

        unsafe {
              let h = GetModuleHandleW(windows_sys::w!("secur32.dll"));

    eprintln!("secur32.dll handle = {:p}", h);

    let mut path = [0u16; 512];
    let len = GetModuleFileNameW(
        h,
        path.as_mut_ptr(),
        path.len() as u32,
    );

    let path = String::from_utf16_lossy(&path[..len as usize]);
    eprintln!("secur32.dll path = {}", path);
            let mut ctxt = mem::zeroed();

            if accept {
                // If we're performing an accept then we need to wait to call
                // `AcceptSecurityContext` until we've actually read some data.
                eprintln!("Accept mode: delaying AcceptSecurityContext until data is available");
                return Ok((SecurityContext(ctxt), None));
            }

             /*
         * IMPORTANT:
         *
         * We are deliberately using the ANSI InitializeSecurityContextA path.
         * The public API currently gives us UTF-16 here, so convert the target
         * name to a NUL-terminated ANSI byte string.
         *
         * For normal HTTPS hostnames this is ASCII, so this is sufficient for
         * the current Schannel test.
         */
        let domain_ansi_storage: Option<Vec<i8>> = domain
            .map(|d| {
                let s = String::from_utf16_lossy(d);

                eprintln!("Target/domain UTF-16 string: {:?}", s);

                let mut bytes = s
                    .as_bytes()
                    .iter()
                    .map(|&b| b as i8)
                    .collect::<Vec<i8>>();

                if !bytes.last().map(|&b| b == 0).unwrap_or(false) {
                    bytes.push(0);
                }

                eprintln!(
                    "Target/domain ANSI string: {:?}",
                    String::from_utf8_lossy(
                        &bytes
                            .iter()
                            .map(|&b| b as u8)
                            .collect::<Vec<u8>>()
                    )
                );

                bytes
            });

        let domain_ptr: *const i8 = domain_ansi_storage
            .as_ref()
            .map(|b| b.as_ptr())
            .unwrap_or(ptr::null());

        eprintln!("Domain/SNI ANSI pointer: {:p}", domain_ptr);

            let mut inbufs = vec![];
            eprintln!("Creating input buffers");

            // Make sure `AlpnList` is kept alive for the duration of this function.
            let mut alpns = requested_application_protocols
                .as_ref()
                .map(|alpn| {
                    eprintln!("Creating ALPN list with {} protocols", alpn.len());
                    for (i, proto) in alpn.iter().enumerate() {
                        eprintln!("  ALPN[{}]: {:?}", i, String::from_utf8_lossy(proto));
                    }
                    AlpnList::new(alpn)
                });
            if let Some(ref mut alpns) = alpns {
                eprintln!("Adding SECBUFFER_APPLICATION_PROTOCOLS buffer");
                inbufs.push(secbuf(
                    Identity::SECBUFFER_APPLICATION_PROTOCOLS,
                    Some(&mut alpns[..]),
                ));
            };

            eprintln!("Input buffer count: {}", inbufs.len());
            
            // Microsoft requires pInput == NULL on the first client call to
            // InitializeSecurityContext when there are no input buffers.
            // Passing a non-NULL descriptor with zero buffers violates the API contract.
            let inbuf_desc_ptr = if inbufs.is_empty() {
                eprintln!("No input buffers - passing NULL for pInput (first call requirement)");
                ptr::null()
            } else {
                eprintln!("Creating SecBufferDesc with {} buffers", inbufs.len());
                &secbuf_desc(&mut inbufs[..]) as *const _
            };

            // When ISC_REQ_ALLOCATE_MEMORY is specified, Microsoft requires:
            // - SECBUFFER_TOKEN for Schannel to allocate the output token
            // - SECBUFFER_ALERT for alert data
            // - SECBUFFER_EMPTY as a spare buffer
            let mut outbuf = [
                secbuf(Identity::SECBUFFER_TOKEN, None),
                secbuf(Identity::SECBUFFER_ALERT, None),
                secbuf(Identity::SECBUFFER_EMPTY, None),
            ];
            eprintln!("Creating output buffers: TOKEN, ALERT, EMPTY");
            let mut outbuf_desc = secbuf_desc(&mut outbuf);
            let cred_handle = cred.as_inner();

            let mut attributes = 0;
            eprintln!("Calling InitializeSecurityContextA");
            eprintln!(
                "CredHandle: lower=0x{:08X} upper=0x{:08X}",
                cred_handle.dwLower,
                cred_handle.dwUpper,
            );
            eprintln!("  Context: NULL (first call)");
            eprintln!("  Domain: {:p}", domain_ptr);
            eprintln!("  INIT_REQUESTS: 0x{:08X}", INIT_REQUESTS);
            eprintln!("  Reserved1: 0");
            eprintln!("  TargetDataRep: 0");
            eprintln!("  Input buffers: {} buffers", inbufs.len());
            eprintln!("  pInput pointer: {:p}", inbuf_desc_ptr);
            eprintln!("  Reserved2: 0");
            eprintln!("  Output context: {:p}", &mut ctxt);
            eprintln!("  Output buffers: 1 buffer");
            eprintln!("  Attributes: {:p}", &mut attributes);
            eprintln!("  Expiration: NULL");
            eprintln!(
    "SecHandle size = {} align = {}",
    mem::size_of::<Credentials::SecHandle>(),
    mem::align_of::<Credentials::SecHandle>()
);

eprintln!(
    "SecBuffer size = {} align = {}",
    mem::size_of::<Identity::SecBuffer>(),
    mem::align_of::<Identity::SecBuffer>()
);

eprintln!(
    "SecBufferDesc size = {} align = {}",
    mem::size_of::<Identity::SecBufferDesc>(),
    mem::align_of::<Identity::SecBufferDesc>()
);
eprintln!(
    "usize={} pointer={}",
    mem::size_of::<usize>(),
    mem::size_of::<*const ()>()
);

            eprintln!("=== BEFORE InitializeSecurityContextA ===");
            let status = Identity::InitializeSecurityContextA(
    &cred_handle,
    ptr::null_mut(),
    domain_ptr,
    INIT_REQUESTS,
    0,
    0,
    inbuf_desc_ptr,
    0,
    &mut ctxt,
    &mut outbuf_desc,
    &mut attributes,
    ptr::null_mut(),
);
            eprintln!("=== AFTER InitializeSecurityContextA: 0x{:08X} ===", status as u32);

            match status {
                Foundation::SEC_I_CONTINUE_NEEDED => {
                    eprintln!("InitializeSecurityContextA returned SEC_I_CONTINUE_NEEDED (0x{:08X})", Foundation::SEC_I_CONTINUE_NEEDED);
                    eprintln!("  Attributes: 0x{:08X}", attributes);
                    eprintln!("  Context attributes:");
                    eprintln!("    ASC_RET_ALLOCATED_MEMORY: {}", (attributes & Identity::ASC_RET_ALLOCATED_MEMORY) != 0);
                    eprintln!("    ASC_RET_CONFIDENTIALITY: {}", (attributes & Identity::ASC_RET_CONFIDENTIALITY) != 0);
                    eprintln!("    ASC_RET_CONNECTION: {}", (attributes & Identity::ASC_RET_CONNECTION) != 0);
                    eprintln!("    ASC_RET_USED_DCE_STYLE: {}", (attributes & Identity::ASC_RET_USED_DCE_STYLE) != 0);
                    eprintln!("    ASC_RET_SEQUENCE_DETECT: {}", (attributes & Identity::ASC_RET_SEQUENCE_DETECT) != 0);
                    eprintln!("    ASC_RET_REPLAY_DETECT: {}", (attributes & Identity::ASC_RET_REPLAY_DETECT) != 0);
                    eprintln!("    ASC_RET_EXTENDED_ERROR: {}", (attributes & Identity::ASC_RET_EXTENDED_ERROR) != 0);
                    eprintln!("    ASC_RET_STREAM: {}", (attributes & Identity::ASC_RET_STREAM) != 0);
                    eprintln!("    ASC_RET_INTEGRITY: {}", (attributes & Identity::ASC_RET_INTEGRITY) != 0);

                    eprintln!("Output buffer state:");
                    eprintln!("  Buffer[0] (TOKEN) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[0].BufferType, outbuf[0].cbBuffer, outbuf[0].pvBuffer);
                    eprintln!("  Buffer[1] (ALERT) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[1].BufferType, outbuf[1].cbBuffer, outbuf[1].pvBuffer);
                    eprintln!("  Buffer[2] (EMPTY) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[2].BufferType, outbuf[2].cbBuffer, outbuf[2].pvBuffer);

                    // Free the alert buffer if Schannel allocated it
                    if !outbuf[1].pvBuffer.is_null() {
                        eprintln!("Freeing alert buffer at {:p}", outbuf[1].pvBuffer);
                        Identity::FreeContextBuffer(outbuf[1].pvBuffer);
                    }

                    Ok((SecurityContext(ctxt), Some(ContextBuffer(outbuf[0]))))
                }
                Foundation::SEC_E_OK => {
                    eprintln!("InitializeSecurityContextA returned SEC_E_OK (0x{:08X})", Foundation::SEC_E_OK);
                    eprintln!("  Handshake completed immediately");
                    eprintln!("  Attributes: 0x{:08X}", attributes);
                    
                    eprintln!("Output buffer state:");
                    eprintln!("  Buffer[0] (TOKEN) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[0].BufferType, outbuf[0].cbBuffer, outbuf[0].pvBuffer);
                    eprintln!("  Buffer[1] (ALERT) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[1].BufferType, outbuf[1].cbBuffer, outbuf[1].pvBuffer);
                    eprintln!("  Buffer[2] (EMPTY) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[2].BufferType, outbuf[2].cbBuffer, outbuf[2].pvBuffer);

                    // Free the alert buffer if Schannel allocated it
                    if !outbuf[1].pvBuffer.is_null() {
                        eprintln!("Freeing alert buffer at {:p}", outbuf[1].pvBuffer);
                        Identity::FreeContextBuffer(outbuf[1].pvBuffer);
                    }
                    
                    // Free the token buffer if Schannel allocated it (immediate completion case)
                    if !outbuf[0].pvBuffer.is_null() {
                        eprintln!("Freeing token buffer at {:p}", outbuf[0].pvBuffer);
                        Identity::FreeContextBuffer(outbuf[0].pvBuffer);
                    }

                    Ok((SecurityContext(ctxt), None))
                }
                err => {
                    eprintln!("InitializeSecurityContextA failed with error: 0x{:08X}", err);
                    eprintln!("Error description: {}", io::Error::from_raw_os_error(err));
                    
                    eprintln!("Output buffer state on error:");
                    eprintln!("  Buffer[0] (TOKEN) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[0].BufferType, outbuf[0].cbBuffer, outbuf[0].pvBuffer);
                    eprintln!("  Buffer[1] (ALERT) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[1].BufferType, outbuf[1].cbBuffer, outbuf[1].pvBuffer);
                    eprintln!("  Buffer[2] (EMPTY) type: 0x{:X}, length: {}, ptr: {:p}", outbuf[2].BufferType, outbuf[2].cbBuffer, outbuf[2].pvBuffer);

                    // Free the alert buffer if Schannel allocated it even on error
                    if !outbuf[1].pvBuffer.is_null() {
                        eprintln!("Freeing alert buffer at {:p}", outbuf[1].pvBuffer);
                        Identity::FreeContextBuffer(outbuf[1].pvBuffer);
                    }
                    
                    // Free the token buffer if Schannel allocated it even on error
                    if !outbuf[0].pvBuffer.is_null() {
                        eprintln!("Freeing token buffer at {:p}", outbuf[0].pvBuffer);
                        Identity::FreeContextBuffer(outbuf[0].pvBuffer);
                    }

                    Err(io::Error::from_raw_os_error(err))
                },
            }
        }
    }

    unsafe fn attribute<T>(&self, attr: Identity::SECPKG_ATTR) -> io::Result<T> {
        eprintln!("SecurityContext::attribute called with attr: 0x{:08X}", attr);
        let mut value = mem::zeroed();
        eprintln!("Calling QueryContextAttributesA");
        let status =
            Identity::QueryContextAttributesA(&self.0, attr, &mut value as *mut _ as *mut _);
        match status {
            Foundation::SEC_E_OK => {
                eprintln!("QueryContextAttributesA succeeded (SEC_E_OK)");
                Ok(value)
            },
            err => {
                eprintln!("QueryContextAttributesA failed with error: 0x{:08X}", err);
                Err(io::Error::from_raw_os_error(err))
            },
        }
    }

    pub fn application_protocol(&self) -> io::Result<Identity::SecPkgContext_ApplicationProtocol> {
        eprintln!("SecurityContext::application_protocol called");
        unsafe { self.attribute(Identity::SECPKG_ATTR_APPLICATION_PROTOCOL) }
    }

    pub fn session_info(&self) -> io::Result<Identity::SecPkgContext_SessionInfo> {
        eprintln!("SecurityContext::session_info called");
        unsafe { self.attribute(Identity::SECPKG_ATTR_SESSION_INFO) }
    }

    pub fn stream_sizes(&self) -> io::Result<Identity::SecPkgContext_StreamSizes> {
        eprintln!("SecurityContext::stream_sizes called");
        unsafe { self.attribute(Identity::SECPKG_ATTR_STREAM_SIZES) }
    }

    pub fn remote_cert(&self) -> io::Result<CertContext> {
        eprintln!("SecurityContext::remote_cert called");
        unsafe {
            self.attribute(Identity::SECPKG_ATTR_REMOTE_CERT_CONTEXT)
                .map(|p| {
                    eprintln!("Successfully retrieved remote certificate context");
                    CertContext::from_inner(p)
                })
        }
    }

    pub fn local_cert(&self) -> io::Result<CertContext> {
        eprintln!("SecurityContext::local_cert called");
        unsafe {
            self.attribute(Identity::SECPKG_ATTR_LOCAL_CERT_CONTEXT)
                .map(|p| {
                    eprintln!("Successfully retrieved local certificate context");
                    CertContext::from_inner(p)
                })
        }
    }
}
