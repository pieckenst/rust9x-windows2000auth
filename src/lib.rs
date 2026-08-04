// Use std for development, can switch to no_std for production
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::ffi::{CString, CStr};
#[cfg(not(feature = "std"))]
use alloc::slice;
#[cfg(not(feature = "std"))]
use alloc::format;

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::ffi::{CString, CStr};
#[cfg(feature = "std")]
use std::slice;
#[cfg(feature = "std")]
use std::format;

use core::ffi::c_char;

mod auth;
mod http;
mod tls;

pub use auth::{AuthCredentials, AuthResult, WindowsAuthClient};
pub use http::HttpClient;
pub use tls::TlsConfig;

/// Error codes for .NET interop
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthErrorCode {
    Success = 0,
    InvalidCredentials = 1,
    NetworkError = 2,
    TlsError = 3,
    AuthFailed = 4,
    InvalidParameter = 5,
    NotInitialized = 6,
    Unknown = -1,
}

/// Result structure for .NET interop
#[repr(C)]
pub struct AuthInteropResult {
    pub error_code: AuthErrorCode,
    pub error_message: *mut c_char,
    pub response_data: *mut u8,
    pub response_length: usize,
}

impl AuthInteropResult {
    pub fn success() -> Self {
        Self {
            error_code: AuthErrorCode::Success,
            error_message: std::ptr::null_mut(),
            response_data: std::ptr::null_mut(),
            response_length: 0,
        }
    }

    pub fn error(code: AuthErrorCode, message: &str) -> Self {
        let msg_cstr = CString::new(message).unwrap();
        let msg_ptr = msg_cstr.into_raw();
        Self {
            error_code: code,
            error_message: msg_ptr,
            response_data: std::ptr::null_mut(),
            response_length: 0,
        }
    }
}

/// Global authentication client instance
pub static mut AUTH_CLIENT: Option<WindowsAuthClient> = None;

/// Initialize the authentication library
#[no_mangle]
pub extern "C" fn auth_init() -> AuthErrorCode {
    unsafe {
        if AUTH_CLIENT.is_some() {
            return AuthErrorCode::InvalidParameter;
        }
        
        match WindowsAuthClient::new() {
            Ok(client) => {
                AUTH_CLIENT = Some(client);
                AuthErrorCode::Success
            }
            Err(_) => AuthErrorCode::NotInitialized,
        }
    }
}

/// Cleanup and free resources
#[no_mangle]
pub extern "C" fn auth_cleanup() {
    unsafe {
        if let Some(client) = AUTH_CLIENT.take() {
            std::mem::drop(client);
        }
    }
}

/// Free a string allocated by Rust
#[no_mangle]
pub extern "C" fn auth_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Free response data allocated by Rust
#[no_mangle]
pub extern "C" fn auth_free_data(ptr: *mut u8, length: usize) {
    if !ptr.is_null() && length > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, length, length);
        }
    }
}

/// Set credentials for authentication
#[no_mangle]
pub extern "C" fn auth_set_credentials(
    username: *const c_char,
    password: *const c_char,
    domain: *const c_char,
) -> AuthErrorCode {
    unsafe {
        if AUTH_CLIENT.is_none() {
            return AuthErrorCode::NotInitialized;
        }

        let client = AUTH_CLIENT.as_mut().unwrap();

        let username_str = if username.is_null() {
            return AuthErrorCode::InvalidParameter;
        } else {
            match CStr::from_ptr(username).to_str() {
                Ok(s) => s,
                Err(_) => return AuthErrorCode::InvalidParameter,
            }
        };

        let password_str = if password.is_null() {
            return AuthErrorCode::InvalidParameter;
        } else {
            match CStr::from_ptr(password).to_str() {
                Ok(s) => s,
                Err(_) => return AuthErrorCode::InvalidParameter,
            }
        };

        let domain_str = if domain.is_null() {
            None
        } else {
            match CStr::from_ptr(domain).to_str() {
                Ok(s) if !s.is_empty() => Some(s),
                _ => None,
            }
        };

        let creds = AuthCredentials {
            username: username_str.to_string(),
            password: password_str.to_string(),
            domain: domain_str.map(|d| d.to_string()),
        };

        client.set_credentials(creds);
        AuthErrorCode::Success
    }
}

/// Perform HTTP request with Windows Authentication
#[no_mangle]
pub extern "C" fn auth_http_request(
    url: *const c_char,
    method: *const c_char,
    body_data: *const u8,
    body_length: usize,
) -> AuthInteropResult {
    unsafe {
        if AUTH_CLIENT.is_none() {
            return AuthInteropResult::error(AuthErrorCode::NotInitialized, "Auth client not initialized");
        }

        let _client = AUTH_CLIENT.as_mut().unwrap();

        let url_str = if url.is_null() {
            return AuthInteropResult::error(AuthErrorCode::InvalidParameter, "URL is null");
        } else {
            match CStr::from_ptr(url).to_str() {
                Ok(s) => s,
                Err(_) => return AuthInteropResult::error(AuthErrorCode::InvalidParameter, "Invalid URL encoding"),
            }
        };

        let method_str = if method.is_null() {
            "GET"
        } else {
            match CStr::from_ptr(method).to_str() {
                Ok(s) if !s.is_empty() => s,
                _ => "GET",
            }
        };

        let body = if body_data.is_null() || body_length == 0 {
            None
        } else {
            Some(slice::from_raw_parts(body_data, body_length).to_vec())
        };

        let mut http_client = crate::http::HttpClient::new();
        match http_client.http_request(url_str, method_str, body) {
            Ok(response) => {
                let response_len = response.len();
                let response_ptr = response.as_ptr() as *mut u8;
                std::mem::forget(response);
                AuthInteropResult {
                    error_code: AuthErrorCode::Success,
                    error_message: std::ptr::null_mut(),
                    response_data: response_ptr,
                    response_length: response_len,
                }
            }
            Err(e) => AuthInteropResult::error(AuthErrorCode::NetworkError, &format!("HTTP request failed: {}", e)),
        }
    }
}

/// Prompt for credentials using Windows credential dialog
#[no_mangle]
pub extern "C" fn auth_prompt_credentials(
    caption: *const c_char,
    message: *const c_char,
    save_credentials: *mut bool,
) -> AuthInteropResult {
    #[cfg(windows)]
    {
        unsafe {
            if AUTH_CLIENT.is_none() {
                return AuthInteropResult::error(AuthErrorCode::NotInitialized, "Auth client not initialized");
            }

            let client = AUTH_CLIENT.as_mut().unwrap();

            let caption_str = if caption.is_null() {
                "Authentication Required"
            } else {
                match CStr::from_ptr(caption).to_str() {
                    Ok(s) => s,
                    Err(_) => "Authentication Required",
                }
            };

            let message_str = if message.is_null() {
                "Enter your credentials"
            } else {
                match CStr::from_ptr(message).to_str() {
                    Ok(s) => s,
                    Err(_) => "Enter your credentials",
                }
            };

            let save = if save_credentials.is_null() {
                false
            } else {
                *save_credentials
            };

            match client.prompt_for_windows_credentials(caption_str, message_str, save) {
                Ok(_) => AuthInteropResult::success(),
                Err(e) => AuthInteropResult::error(
                    AuthErrorCode::InvalidCredentials,
                    &format!("Credential prompt failed: {}", e),
                ),
            }
        }
    }

    #[cfg(not(windows))]
    {
        AuthInteropResult::error(AuthErrorCode::NotInitialized, "Credential prompt only available on Windows")
    }
}
