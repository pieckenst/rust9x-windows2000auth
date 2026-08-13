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
#[cfg(feature = "std")]
use std::fs::OpenOptions;
#[cfg(feature = "std")]
use std::io::Write;
#[cfg(feature = "std")]
use std::time::Duration;

use core::ffi::c_char;

#[cfg(feature = "std")]
fn log_to_file(message: &str) {
    let log_path = "E:\\code\\rust9x-windows2000auth\\rust-src\\lib_log.txt";
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

#[cfg(feature = "std")]
fn log_function_entry(function_name: &str) {
    let msg = format!("[FUNCTION_ENTRY] {}", function_name);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_function_exit(function_name: &str, result: &str) {
    let msg = format!("[FUNCTION_EXIT] {} -> {}", function_name, result);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_parameter(param_name: &str, value: &str, size: Option<usize>) {
    let size_str = size.map(|s| format!(" (size: {} bytes)", s)).unwrap_or_default();
    let msg = format!("[PARAM] {} = {}{}", param_name, value, size_str);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_memory_allocation(location: &str, size: usize) {
    let msg = format!("[MEMORY_ALLOC] {} allocated {} bytes", location, size);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_memory_free(location: &str, size: usize) {
    let msg = format!("[MEMORY_FREE] {} freed {} bytes", location, size);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_interop_conversion(from_type: &str, to_type: &str, value: &str, success: bool) {
    let status = if success { "SUCCESS" } else { "FAILED" };
    let msg = format!("[INTEROP] {} -> {} [{}] value: {}", from_type, to_type, status, value);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_object_size(object_name: &str, size: usize) {
    let msg = format!("[OBJECT_SIZE] {} = {} bytes", object_name, size);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

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
        #[cfg(feature = "std")]
        {
            log_function_entry("AuthInteropResult::success");
            log_object_size("AuthInteropResult", std::mem::size_of::<AuthInteropResult>());
            log_parameter("error_code", "Success", Some(std::mem::size_of::<AuthErrorCode>()));
            log_parameter("error_message", "null_mut()", None);
            log_parameter("response_data", "null_mut()", None);
            log_parameter("response_length", "0", Some(std::mem::size_of::<usize>()));
        }
        
        let result = Self {
            error_code: AuthErrorCode::Success,
            error_message: std::ptr::null_mut(),
            response_data: std::ptr::null_mut(),
            response_length: 0,
        };
        
        #[cfg(feature = "std")]
        log_function_exit("AuthInteropResult::success", "AuthInteropResult (success)");
        
        result
    }

    pub fn error(code: AuthErrorCode, message: &str) -> Self {
        #[cfg(feature = "std")]
        {
            log_function_entry("AuthInteropResult::error");
            log_parameter("error_code", &format!("{:?}", code), Some(std::mem::size_of::<AuthErrorCode>()));
            log_parameter("message", &format!("'{}' ({} bytes)", message, message.len()), Some(message.len()));
        }
        
        let msg_cstr = CString::new(message).unwrap();
        
        #[cfg(feature = "std")]
        {
            let msg_len = msg_cstr.as_bytes().len();
            log_memory_allocation("CString (error message)", msg_len);
            log_interop_conversion("CString", "*mut c_char", &format!("leaked ptr={:?}", msg_cstr.as_ptr()), true);
        }
        
        let msg_ptr = msg_cstr.into_raw();
        
        #[cfg(feature = "std")]
        {
            log_object_size("AuthInteropResult", std::mem::size_of::<AuthInteropResult>());
            log_parameter("error_message", &format!("ptr={:?} (leaked)", msg_ptr), None);
        }
        
        let result = Self {
            error_code: code,
            error_message: msg_ptr,
            response_data: std::ptr::null_mut(),
            response_length: 0,
        };
        
        #[cfg(feature = "std")]
        log_function_exit("AuthInteropResult::error", &format!("AuthInteropResult (error: {:?})", code));
        
        result
    }
}

/// Global authentication client instance
pub static mut AUTH_CLIENT: Option<WindowsAuthClient> = None;

/// Initialize the authentication library
#[no_mangle]
pub extern "C" fn auth_init() -> AuthErrorCode {
    #[cfg(feature = "std")]
    log_function_entry("auth_init");
    
    let init_msg = "[LIB] auth_init called";
    eprintln!("{}", init_msg);
    #[cfg(feature = "std")]
    log_to_file(init_msg);
    
    #[cfg(feature = "std")]
    {
        let auth_client_size = std::mem::size_of::<WindowsAuthClient>();
        log_object_size("WindowsAuthClient", auth_client_size);
        log_parameter("return_type", "AuthErrorCode", Some(std::mem::size_of::<AuthErrorCode>()));
    }
    
    unsafe {
        if AUTH_CLIENT.is_some() {
            let already_init_msg = "[LIB] Auth client already initialized";
            eprintln!("{}", already_init_msg);
            #[cfg(feature = "std")]
            log_to_file(already_init_msg);
            #[cfg(feature = "std")]
            log_function_exit("auth_init", "InvalidParameter (already initialized)");
            return AuthErrorCode::InvalidParameter;
        }
        
        match WindowsAuthClient::new() {
            Ok(client) => {
                #[cfg(feature = "std")]
                {
                    let client_size = std::mem::size_of_val(&client);
                    log_memory_allocation("AUTH_CLIENT", client_size);
                    log_object_size("client instance", client_size);
                }
                
                AUTH_CLIENT = Some(client);
                let success_msg = "[LIB] Auth client initialized successfully";
                eprintln!("{}", success_msg);
                #[cfg(feature = "std")]
                log_to_file(success_msg);
                #[cfg(feature = "std")]
                log_function_exit("auth_init", "Success");
                AuthErrorCode::Success
            }
            Err(e) => {
                let error_msg = format!("[LIB] Failed to initialize auth client: {:?}", e);
                eprintln!("{}", error_msg);
                #[cfg(feature = "std")]
                log_to_file(&error_msg);
                #[cfg(feature = "std")]
                log_function_exit("auth_init", "NotInitialized (error)");
                AuthErrorCode::NotInitialized
            }
        }
    }
}

/// Cleanup and free resources
#[no_mangle]
pub extern "C" fn auth_cleanup() {
    #[cfg(feature = "std")]
    log_function_entry("auth_cleanup");
    
    let cleanup_msg = "[LIB] auth_cleanup called";
    eprintln!("{}", cleanup_msg);
    #[cfg(feature = "std")]
    log_to_file(cleanup_msg);
    
    #[cfg(feature = "std")]
    log_parameter("return_type", "void", None);
    
    unsafe {
        if let Some(client) = AUTH_CLIENT.take() {
            #[cfg(feature = "std")]
            {
                let client_size = std::mem::size_of_val(&client);
                log_memory_free("AUTH_CLIENT", client_size);
                log_object_size("client being dropped", client_size);
            }
            
            std::mem::drop(client);
            let dropped_msg = "[LIB] Auth client cleaned up";
            eprintln!("{}", dropped_msg);
            #[cfg(feature = "std")]
            log_to_file(dropped_msg);
            #[cfg(feature = "std")]
            log_function_exit("auth_cleanup", "void (client dropped)");
        } else {
            let none_msg = "[LIB] No auth client to clean up";
            eprintln!("{}", none_msg);
            #[cfg(feature = "std")]
            log_to_file(none_msg);
            #[cfg(feature = "std")]
            log_function_exit("auth_cleanup", "void (no client)");
        }
    }
}

/// Free a string allocated by Rust
#[no_mangle]
pub extern "C" fn auth_free_string(ptr: *mut c_char) {
    #[cfg(feature = "std")]
    log_function_entry("auth_free_string");
    
    #[cfg(feature = "std")]
    {
        let ptr_val = if ptr.is_null() { "NULL".to_string() } else { format!("{:?}", ptr) };
        log_parameter("ptr", &ptr_val, None);
        log_parameter("return_type", "void", None);
    }
    
    if !ptr.is_null() {
        unsafe {
            #[cfg(feature = "std")]
            {
                // Estimate string length before freeing
                let cstr = CStr::from_ptr(ptr);
                let len = cstr.to_bytes().len();
                log_memory_free("CString", len);
                log_interop_conversion("*mut c_char", "CString", &format!("{:?}", ptr), true);
            }
            
            let _ = CString::from_raw(ptr);
            
            #[cfg(feature = "std")]
            log_function_exit("auth_free_string", "void (freed)");
        }
    } else {
        #[cfg(feature = "std")]
        {
            log_to_file("[MEMORY_FREE] NULL pointer - nothing to free");
            log_function_exit("auth_free_string", "void (NULL pointer)");
        }
    }
}

/// Free response data allocated by Rust
#[no_mangle]
pub extern "C" fn auth_free_data(ptr: *mut u8, length: usize) {
    #[cfg(feature = "std")]
    log_function_entry("auth_free_data");
    
    #[cfg(feature = "std")]
    {
        let ptr_val = if ptr.is_null() { "NULL".to_string() } else { format!("{:?}", ptr) };
        log_parameter("ptr", &ptr_val, None);
        log_parameter("length", &length.to_string(), Some(length));
        log_parameter("return_type", "void", None);
    }
    
    if !ptr.is_null() && length > 0 {
        unsafe {
            #[cfg(feature = "std")]
            {
                log_memory_free("Vec<u8>", length);
                log_interop_conversion("*mut u8", "Vec<u8>", &format!("ptr={:?}, len={}", ptr, length), true);
            }
            
            let _ = Vec::from_raw_parts(ptr, length, length);
            
            #[cfg(feature = "std")]
            log_function_exit("auth_free_data", "void (freed)");
        }
    } else {
        #[cfg(feature = "std")]
        {
            let reason = if ptr.is_null() { "NULL pointer" } else { "zero length" };
            log_to_file(&format!("[MEMORY_FREE] {} - nothing to free", reason));
            log_function_exit("auth_free_data", &format!("void ({})", reason));
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
    #[cfg(feature = "std")]
    log_function_entry("auth_set_credentials");
    
    let set_creds_msg = "[LIB] auth_set_credentials called";
    eprintln!("{}", set_creds_msg);
    #[cfg(feature = "std")]
    log_to_file(set_creds_msg);
    
    #[cfg(feature = "std")]
    {
        let username_ptr = if username.is_null() { "NULL".to_string() } else { format!("{:?}", username) };
        let password_ptr = if password.is_null() { "NULL".to_string() } else { format!("{:?}", password) };
        let domain_ptr = if domain.is_null() { "NULL".to_string() } else { format!("{:?}", domain) };
        
        log_parameter("username", &username_ptr, None);
        log_parameter("password", &password_ptr, None);
        log_parameter("domain", &domain_ptr, None);
        log_parameter("return_type", "AuthErrorCode", Some(std::mem::size_of::<AuthErrorCode>()));
    }
    
    unsafe {
        if AUTH_CLIENT.is_none() {
            let not_init_msg = "[LIB] Auth client not initialized for set_credentials";
            eprintln!("{}", not_init_msg);
            #[cfg(feature = "std")]
            log_to_file(not_init_msg);
            #[cfg(feature = "std")]
            log_function_exit("auth_set_credentials", "NotInitialized (client not initialized)");
            return AuthErrorCode::NotInitialized;
        }

        let client = AUTH_CLIENT.as_mut().unwrap();
        
        #[cfg(feature = "std")]
        log_object_size("AUTH_CLIENT", std::mem::size_of_val(&*client));

        let username_str = if username.is_null() {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const c_char", "str", "NULL", false);
                log_function_exit("auth_set_credentials", "InvalidParameter (NULL username)");
            }
            return AuthErrorCode::InvalidParameter;
        } else {
            match CStr::from_ptr(username).to_str() {
                Ok(s) => {
                    #[cfg(feature = "std")]
                    {
                        let len = s.len();
                        log_interop_conversion("*const c_char", "&str", &format!("'{}' ({} bytes)", s, len), true);
                        log_parameter("username_str", &format!("'{}'", s), Some(len));
                    }
                    s
                },
                Err(e) => {
                    #[cfg(feature = "std")]
                    {
                        log_interop_conversion("*const c_char", "&str", &format!("ERROR: {:?}", e), false);
                        log_function_exit("auth_set_credentials", "InvalidParameter (invalid username encoding)");
                    }
                    return AuthErrorCode::InvalidParameter;
                }
            }
        };

        let password_str = if password.is_null() {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const c_char", "str", "NULL", false);
                log_function_exit("auth_set_credentials", "InvalidParameter (NULL password)");
            }
            return AuthErrorCode::InvalidParameter;
        } else {
            match CStr::from_ptr(password).to_str() {
                Ok(s) => {
                    #[cfg(feature = "std")]
                    {
                        let len = s.len();
                        log_interop_conversion("*const c_char", "&str", &format!("'***' ({} bytes)", len), true);
                        log_parameter("password_str", &format!("'***' ({} bytes)", len), Some(len));
                    }
                    s
                },
                Err(e) => {
                    #[cfg(feature = "std")]
                    {
                        log_interop_conversion("*const c_char", "&str", &format!("ERROR: {:?}", e), false);
                        log_function_exit("auth_set_credentials", "InvalidParameter (invalid password encoding)");
                    }
                    return AuthErrorCode::InvalidParameter;
                }
            }
        };

        let domain_str = if domain.is_null() {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const c_char", "Option<&str>", "NULL", true);
                log_parameter("domain_str", "None", None);
            }
            None
        } else {
            match CStr::from_ptr(domain).to_str() {
                Ok(s) if !s.is_empty() => {
                    #[cfg(feature = "std")]
                    {
                        let len = s.len();
                        log_interop_conversion("*const c_char", "Option<&str>", &format!("Some('{}')", s), true);
                        log_parameter("domain_str", &format!("Some('{}')", s), Some(len));
                    }
                    Some(s)
                },
                Ok(_) => {
                    #[cfg(feature = "std")]
                    {
                        log_interop_conversion("*const c_char", "Option<&str>", "empty string -> None", true);
                        log_parameter("domain_str", "None (empty)", None);
                    }
                    None
                },
                Err(e) => {
                    #[cfg(feature = "std")]
                    {
                        log_interop_conversion("*const c_char", "Option<&str>", &format!("ERROR: {:?}", e), false);
                        log_parameter("domain_str", "None (invalid)", None);
                    }
                    None
                }
            }
        };

        let creds = AuthCredentials {
            username: username_str.to_string(),
            password: password_str.to_string(),
            domain: domain_str.map(|d| d.to_string()),
        };
        
        #[cfg(feature = "std")]
        {
            let creds_size = std::mem::size_of_val(&creds);
            log_object_size("AuthCredentials", creds_size);
            log_memory_allocation("AuthCredentials", creds_size);
            log_parameter("creds.username", &format!("'{}'", creds.username), Some(creds.username.len()));
            log_parameter("creds.password", &format!("'***' ({} bytes)", creds.password.len()), Some(creds.password.len()));
            log_parameter("creds.domain", &format!("{:?}", creds.domain.as_ref().map(|d| d.len())), None);
        }

        let creds_set_msg = format!("[LIB] Setting credentials for user: {}", username_str);
        eprintln!("{}", creds_set_msg);
        #[cfg(feature = "std")]
        log_to_file(&creds_set_msg);
        
        client.set_credentials(creds);
        
        let success_msg = "[LIB] Credentials set successfully";
        eprintln!("{}", success_msg);
        #[cfg(feature = "std")]
        log_to_file(success_msg);
        #[cfg(feature = "std")]
        log_function_exit("auth_set_credentials", "Success");
        
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
    result: *mut AuthInteropResult,
) {
    #[cfg(feature = "std")]
    log_function_entry("auth_http_request");
    
    let http_req_msg = "[LIB] auth_http_request called";
    eprintln!("{}", http_req_msg);
    #[cfg(feature = "std")]
    log_to_file(http_req_msg);
    
    #[cfg(feature = "std")]
    {
        let url_ptr = if url.is_null() { "NULL".to_string() } else { format!("{:?}", url) };
        let method_ptr = if method.is_null() { "NULL".to_string() } else { format!("{:?}", method) };
        let body_ptr = if body_data.is_null() { "NULL".to_string() } else { format!("{:?}", body_data) };
        let result_ptr = if result.is_null() { "NULL".to_string() } else { format!("{:?}", result) };
        
        log_parameter("url", &url_ptr, None);
        log_parameter("method", &method_ptr, None);
        log_parameter("body_data", &body_ptr, None);
        log_parameter("body_length", &body_length.to_string(), Some(body_length));
        log_parameter("result", &result_ptr, None);
    }
    
    // Initialize result to error state if null pointer
    if result.is_null() {
        #[cfg(feature = "std")]
        {
            log_function_exit("auth_http_request", "InvalidParameter (null result pointer)");
        }
        return;
    }
    
    unsafe {
        // Initialize result to a safe default state
        *result = AuthInteropResult {
            error_code: AuthErrorCode::InvalidParameter,
            error_message: core::ptr::null_mut(),
            response_data: core::ptr::null_mut(),
            response_length: 0,
        };
        
        if AUTH_CLIENT.is_none() {
            let not_init_msg = "[LIB] Auth client not initialized for http_request";
            eprintln!("{}", not_init_msg);
            #[cfg(feature = "std")]
            log_to_file(not_init_msg);
            #[cfg(feature = "std")]
            log_function_exit("auth_http_request", "NotInitialized (client not initialized)");
            *result = AuthInteropResult::error(AuthErrorCode::NotInitialized, "Auth client not initialized");
            return;
        }

        let _client = AUTH_CLIENT.as_mut().unwrap();
        
        #[cfg(feature = "std")]
        log_object_size("AUTH_CLIENT", std::mem::size_of_val(&*_client));

        let url_str = if url.is_null() {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const c_char", "&str", "NULL", false);
                log_function_exit("auth_http_request", "InvalidParameter (NULL URL)");
            }
            *result = AuthInteropResult::error(AuthErrorCode::InvalidParameter, "URL is null");
            return;
        } else {
            match CStr::from_ptr(url).to_str() {
                Ok(s) => {
                    #[cfg(feature = "std")]
                    {
                        let len = s.len();
                        log_interop_conversion("*const c_char", "&str", &format!("'{}' ({} bytes)", s, len), true);
                        log_parameter("url_str", &format!("'{}'", s), Some(len));
                    }
                    s
                },
                Err(e) => {
                    #[cfg(feature = "std")]
                    {
                        log_interop_conversion("*const c_char", "&str", &format!("ERROR: {:?}", e), false);
                        log_function_exit("auth_http_request", "InvalidParameter (invalid URL encoding)");
                    }
                    *result = AuthInteropResult::error(AuthErrorCode::InvalidParameter, "Invalid URL encoding");
                    return;
                }
            }
        };

        let method_str = if method.is_null() {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const c_char", "&str", "NULL -> 'GET'", true);
                log_parameter("method_str", "'GET' (default)", Some(3));
            }
            "GET"
        } else {
            match CStr::from_ptr(method).to_str() {
                Ok(s) if !s.is_empty() => {
                    #[cfg(feature = "std")]
                    {
                        let len = s.len();
                        log_interop_conversion("*const c_char", "&str", &format!("'{}'", s), true);
                        log_parameter("method_str", &format!("'{}'", s), Some(len));
                    }
                    s
                },
                _ => {
                    #[cfg(feature = "std")]
                    {
                        log_interop_conversion("*const c_char", "&str", "empty/invalid -> 'GET'", true);
                        log_parameter("method_str", "'GET' (fallback)", Some(3));
                    }
                    "GET"
                }
            }
        };

        let request_info = format!("[LIB] HTTP request: {} {}", method_str, url_str);
        eprintln!("{}", request_info);
        #[cfg(feature = "std")]
        log_to_file(&request_info);

        let body = if body_data.is_null() || body_length == 0 {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const u8", "Option<Vec<u8>>", "NULL/empty -> None", true);
                log_parameter("body", "None", None);
            }
            None
        } else {
            #[cfg(feature = "std")]
            {
                log_interop_conversion("*const u8", "Option<Vec<u8>>", &format!("Some({} bytes)", body_length), true);
                log_parameter("body", &format!("Some({} bytes)", body_length), Some(body_length));
                log_memory_allocation("body Vec<u8>", body_length);
            }
            Some(slice::from_raw_parts(body_data, body_length).to_vec())
        };

        #[cfg(feature = "std")]
        {
            let http_client_size = std::mem::size_of::<crate::http::HttpClient>();
            log_object_size("HttpClient", http_client_size);
            log_memory_allocation("HttpClient", http_client_size);
        }
        
        let mut http_client = crate::http::HttpClient::new();
        
        #[cfg(feature = "tls")]
        {
            // Auto-detect OS version and select appropriate TLS configuration
            // Will use legacy config for Windows 2000/XP/2003, modern config for newer systems
            let tls_config = crate::tls::TlsConfig::auto()
                .with_handshake_timeout(Duration::from_secs(30));
            http_client = http_client.with_tls(tls_config);
        }
        
        match http_client.http_request(url_str, method_str, body) {
            Ok(response) => {
                let response_len = response.len();
                let response_ptr = response.as_ptr() as *mut u8;
                std::mem::forget(response);
                
                #[cfg(feature = "std")]
                {
                    log_memory_allocation("response_data (leaked)", response_len);
                    log_interop_conversion("Vec<u8>", "*mut u8", &format!("leaked ptr={:?}, len={}", response_ptr, response_len), true);
                    log_object_size("AuthInteropResult", std::mem::size_of::<AuthInteropResult>());
                }
                
                let success_msg = format!("[LIB] HTTP request successful: {} bytes", response_len);
                eprintln!("{}", success_msg);
                #[cfg(feature = "std")]
                log_to_file(&success_msg);
                #[cfg(feature = "std")]
                log_function_exit("auth_http_request", &format!("Success ({} bytes)", response_len));
                
                *result = AuthInteropResult {
                    error_code: AuthErrorCode::Success,
                    error_message: core::ptr::null_mut(),
                    response_data: response_ptr,
                    response_length: response_len,
                };
            }
            Err(e) => {
                let error_msg = format!("[LIB] HTTP request failed: {}", e);
                eprintln!("{}", error_msg);
                #[cfg(feature = "std")]
                log_to_file(&error_msg);
                #[cfg(feature = "std")]
                log_function_exit("auth_http_request", &format!("NetworkError: {}", e));
                *result = AuthInteropResult::error(AuthErrorCode::NetworkError, &format!("HTTP request failed: {}", e));
            }
        }
    }
}

/// Prompt for credentials using Windows credential dialog
#[no_mangle]
pub extern "C" fn auth_prompt_credentials(
    caption: *const c_char,
    message: *const c_char,
    save_credentials: *mut i32,
    result: *mut AuthInteropResult,
) {
    #[cfg(feature = "std")]
    log_function_entry("auth_prompt_credentials");
    
    let prompt_msg = "[LIB] auth_prompt_credentials called";
    eprintln!("{}", prompt_msg);
    #[cfg(feature = "std")]
    log_to_file(prompt_msg);
    
    #[cfg(feature = "std")]
    {
        let caption_ptr = if caption.is_null() { "NULL".to_string() } else { format!("{:?}", caption) };
        let message_ptr = if message.is_null() { "NULL".to_string() } else { format!("{:?}", message) };
        let save_ptr = if save_credentials.is_null() { "NULL".to_string() } else { format!("{:?}", save_credentials) };
        let result_ptr = if result.is_null() { "NULL".to_string() } else { format!("{:?}", result) };
        
        log_parameter("caption", &caption_ptr, None);
        log_parameter("message", &message_ptr, None);
        log_parameter("save_credentials", &save_ptr, None);
        log_parameter("result", &result_ptr, None);
    }
    
    // Initialize result to error state if null pointer
    if result.is_null() {
        #[cfg(feature = "std")]
        {
            log_function_exit("auth_prompt_credentials", "InvalidParameter (null result pointer)");
        }
        return;
    }
    
    #[cfg(windows)]
    {
        unsafe {
            // Initialize result to a safe default state
            *result = AuthInteropResult {
                error_code: AuthErrorCode::InvalidParameter,
                error_message: core::ptr::null_mut(),
                response_data: core::ptr::null_mut(),
                response_length: 0,
            };
            
            if AUTH_CLIENT.is_none() {
                let not_init_msg = "[LIB] Auth client not initialized for prompt_credentials";
                eprintln!("{}", not_init_msg);
                #[cfg(feature = "std")]
                log_to_file(not_init_msg);
                #[cfg(feature = "std")]
                log_function_exit("auth_prompt_credentials", "NotInitialized (client not initialized)");
                *result = AuthInteropResult::error(AuthErrorCode::NotInitialized, "Auth client not initialized");
                return;
            }

            let client = AUTH_CLIENT.as_mut().unwrap();
            
            #[cfg(feature = "std")]
            log_object_size("AUTH_CLIENT", std::mem::size_of_val(&*client));

            let caption_str = if caption.is_null() {
                #[cfg(feature = "std")]
                {
                    log_interop_conversion("*const c_char", "&str", "NULL -> 'Authentication Required'", true);
                    log_parameter("caption_str", "'Authentication Required' (default)", Some(21));
                }
                "Authentication Required"
            } else {
                match CStr::from_ptr(caption).to_str() {
                    Ok(s) => {
                        #[cfg(feature = "std")]
                        {
                            let len = s.len();
                            log_interop_conversion("*const c_char", "&str", &format!("'{}'", s), true);
                            log_parameter("caption_str", &format!("'{}'", s), Some(len));
                        }
                        s
                    },
                    Err(e) => {
                        #[cfg(feature = "std")]
                        {
                            log_interop_conversion("*const c_char", "&str", &format!("ERROR: {:?} -> default", e), false);
                            log_parameter("caption_str", "'Authentication Required' (fallback)", Some(21));
                        }
                        "Authentication Required"
                    }
                }
            };

            let message_str = if message.is_null() {
                #[cfg(feature = "std")]
                {
                    log_interop_conversion("*const c_char", "&str", "NULL -> 'Enter your credentials'", true);
                    log_parameter("message_str", "'Enter your credentials' (default)", Some(22));
                }
                "Enter your credentials"
            } else {
                match CStr::from_ptr(message).to_str() {
                    Ok(s) => {
                        #[cfg(feature = "std")]
                        {
                            let len = s.len();
                            log_interop_conversion("*const c_char", "&str", &format!("'{}'", s), true);
                            log_parameter("message_str", &format!("'{}'", s), Some(len));
                        }
                        s
                    },
                    Err(e) => {
                        #[cfg(feature = "std")]
                        {
                            log_interop_conversion("*const c_char", "&str", &format!("ERROR: {:?} -> default", e), false);
                            log_parameter("message_str", "'Enter your credentials' (fallback)", Some(22));
                        }
                        "Enter your credentials"
                    }
                }
            };

            let save = if save_credentials.is_null() {
                #[cfg(feature = "std")]
                {
                    log_interop_conversion("*mut i32", "bool", "NULL -> false", true);
                    log_parameter("save", "false (default)", Some(std::mem::size_of::<i32>()));
                }
                false
            } else {
                #[cfg(feature = "std")]
                {
                    let val = *save_credentials;
                    log_interop_conversion("*mut i32", "bool", &format!("{} -> {}", val, val != 0), true);
                    log_parameter("save", &(val != 0).to_string(), Some(std::mem::size_of::<i32>()));
                }
                *save_credentials != 0
            };

            let prompt_info = format!("[LIB] Prompting for credentials - Caption: {}, Message: {}, Save: {}", caption_str, message_str, save);
            eprintln!("{}", prompt_info);
            #[cfg(feature = "std")]
            log_to_file(&prompt_info);

            match client.prompt_for_windows_credentials(caption_str, message_str, save) {
                Ok(save_result) => {
                    // Write back the save result if the pointer is not null
                    if !save_credentials.is_null() {
                        *save_credentials = if save_result { 1 } else { 0 };
                    }
                    
                    let success_msg = "[LIB] Credential prompt successful";
                    eprintln!("{}", success_msg);
                    #[cfg(feature = "std")]
                    log_to_file(success_msg);
                    #[cfg(feature = "std")]
                    log_function_exit("auth_prompt_credentials", "Success");
                    *result = AuthInteropResult::success();
                }
                Err(e) => {
                    let error_msg = format!("[LIB] Credential prompt failed: {}", e);
                    eprintln!("{}", error_msg);
                    #[cfg(feature = "std")]
                    log_to_file(&error_msg);
                    #[cfg(feature = "std")]
                    log_function_exit("auth_prompt_credentials", &format!("InvalidCredentials: {}", e));
                    *result = AuthInteropResult::error(
                        AuthErrorCode::InvalidCredentials,
                        &format!("Credential prompt failed: {}", e),
                    );
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        // Initialize result to a safe default state
        unsafe {
            *result = AuthInteropResult {
                error_code: AuthErrorCode::InvalidParameter,
                error_message: core::ptr::null_mut(),
                response_data: core::ptr::null_mut(),
                response_length: 0,
            };
        }
        
        let not_windows_msg = "[LIB] Credential prompt only available on Windows";
        eprintln!("{}", not_windows_msg);
        #[cfg(feature = "std")]
        log_to_file(not_windows_msg);
        #[cfg(feature = "std")]
        log_function_exit("auth_prompt_credentials", "NotInitialized (not Windows)");
        unsafe {
            *result = AuthInteropResult::error(AuthErrorCode::NotInitialized, "Credential prompt only available on Windows");
        }
    }
}
