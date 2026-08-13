//! Bindings to the Windows SChannel APIs.
#![cfg(windows)]
#![warn(missing_docs)]
#![allow(non_upper_case_globals)]

use std::ffi::c_void;
use std::ptr;

use log::{debug, error, info, trace, warn};
use windows_sys::Win32::Security::Authentication::Identity;

macro_rules! inner {
    ($t:path, $raw:ty) => {
        impl crate::Inner<$raw> for $t {
            unsafe fn from_inner(t: $raw) -> Self {
                $t(t)
            }

            fn as_inner(&self) -> $raw {
                self.0
            }

            fn get_mut(&mut self) -> &mut $raw {
                &mut self.0
            }
        }

        impl crate::RawPointer for $t {
            unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> $t {
                $t(t as _)
            }

            unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void {
                self.0 as *mut _
            }
        }
    };
}

/// Allows access to the underlying schannel API representation of a wrapped data type
///
/// Performing actions with internal handles might lead to the violation of internal assumptions
/// and therefore is inherently unsafe.
pub trait RawPointer {
    /// Constructs an instance of this type from its handle / pointer.
    /// # Safety
    /// This function is unsafe
    unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> Self;

    /// Get a raw pointer from the underlying handle / pointer.
    /// # Safety
    /// This function is unsafe
    unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void;
}

pub mod cert_chain;
pub mod cert_context;
pub mod cert_store;
pub mod crypt_key;
pub mod crypt_prov;
/* pub */ mod ctl_context;
pub mod key_handle;
pub mod ncrypt_key;
pub mod schannel_cred;
pub mod tls_stream;

mod alpn_list;
mod context_buffer;
mod security_context;

#[cfg(test)]
mod test;

const ACCEPT_REQUESTS: u32 = Identity::ASC_REQ_ALLOCATE_MEMORY
    | Identity::ASC_REQ_CONFIDENTIALITY
    | Identity::ASC_REQ_SEQUENCE_DETECT
    | Identity::ASC_REQ_STREAM
    | Identity::ASC_REQ_REPLAY_DETECT;

const INIT_REQUESTS: u32 = Identity::ISC_REQ_CONFIDENTIALITY
    | Identity::ISC_REQ_INTEGRITY
    | Identity::ISC_REQ_REPLAY_DETECT
    | Identity::ISC_REQ_SEQUENCE_DETECT
    | Identity::ISC_REQ_MANUAL_CRED_VALIDATION
    | Identity::ISC_REQ_ALLOCATE_MEMORY
    | Identity::ISC_REQ_STREAM
    | Identity::ISC_REQ_USE_SUPPLIED_CREDS;

/// Log the INIT_REQUESTS flags for debugging
pub fn log_init_requests() {
    info!("INIT_REQUESTS flags: 0x{:08X}", INIT_REQUESTS);
    debug!("  ISC_REQ_CONFIDENTIALITY: {}", (INIT_REQUESTS & Identity::ISC_REQ_CONFIDENTIALITY) != 0);
    debug!("  ISC_REQ_INTEGRITY: {}", (INIT_REQUESTS & Identity::ISC_REQ_INTEGRITY) != 0);
    debug!("  ISC_REQ_REPLAY_DETECT: {}", (INIT_REQUESTS & Identity::ISC_REQ_REPLAY_DETECT) != 0);
    debug!("  ISC_REQ_SEQUENCE_DETECT: {}", (INIT_REQUESTS & Identity::ISC_REQ_SEQUENCE_DETECT) != 0);
    debug!("  ISC_REQ_MANUAL_CRED_VALIDATION: {}", (INIT_REQUESTS & Identity::ISC_REQ_MANUAL_CRED_VALIDATION) != 0);
    debug!("  ISC_REQ_ALLOCATE_MEMORY: {}", (INIT_REQUESTS & Identity::ISC_REQ_ALLOCATE_MEMORY) != 0);
    debug!("  ISC_REQ_STREAM: {}", (INIT_REQUESTS & Identity::ISC_REQ_STREAM) != 0);
    debug!("  ISC_REQ_USE_SUPPLIED_CREDS: {}", (INIT_REQUESTS & Identity::ISC_REQ_USE_SUPPLIED_CREDS) != 0);
}

/// Log the ACCEPT_REQUESTS flags for debugging
pub fn log_accept_requests() {
    info!("ACCEPT_REQUESTS flags: 0x{:08X}", ACCEPT_REQUESTS);
    debug!("  ASC_REQ_ALLOCATE_MEMORY: {}", (ACCEPT_REQUESTS & Identity::ASC_REQ_ALLOCATE_MEMORY) != 0);
    debug!("  ASC_REQ_CONFIDENTIALITY: {}", (ACCEPT_REQUESTS & Identity::ASC_REQ_CONFIDENTIALITY) != 0);
    debug!("  ASC_REQ_SEQUENCE_DETECT: {}", (ACCEPT_REQUESTS & Identity::ASC_REQ_SEQUENCE_DETECT) != 0);
    debug!("  ASC_REQ_STREAM: {}", (ACCEPT_REQUESTS & Identity::ASC_REQ_STREAM) != 0);
    debug!("  ASC_REQ_REPLAY_DETECT: {}", (ACCEPT_REQUESTS & Identity::ASC_REQ_REPLAY_DETECT) != 0);
}

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    fn get_mut(&mut self) -> &mut T;
}

unsafe fn secbuf(buftype: u32, bytes: Option<&mut [u8]>) -> Identity::SecBuffer {
    let (ptr, len) = match bytes {
        Some(bytes) => {
            trace!("Creating SecBuffer with type 0x{:X}, length: {}", buftype, bytes.len());
            (bytes.as_mut_ptr(), bytes.len() as u32)
        },
        None => {
            trace!("Creating SecBuffer with type 0x{:X}, no data (null)", buftype);
            (ptr::null_mut(), 0)
        },
    };
    Identity::SecBuffer {
        BufferType: buftype,
        cbBuffer: len,
        pvBuffer: ptr as *mut c_void,
    }
}

unsafe fn secbuf_desc(bufs: &mut [Identity::SecBuffer]) -> Identity::SecBufferDesc {
    debug!("Creating SecBufferDesc with {} buffers, version: SECBUFFER_VERSION", bufs.len());
    for (i, buf) in bufs.iter().enumerate() {
        trace!("  Buffer[{}]: type=0x{:X}, length={}, ptr={:p}", i, buf.BufferType, buf.cbBuffer, buf.pvBuffer);
    }
    Identity::SecBufferDesc {
        ulVersion: Identity::SECBUFFER_VERSION,
        cBuffers: bufs.len() as u32,
        pBuffers: bufs.as_mut_ptr(),
    }
}
