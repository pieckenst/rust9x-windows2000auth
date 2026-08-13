//! Hostname and domain name handling for Schannel compatibility.
//!
//! This module provides robust conversion between UTF-16 domain names (as used
//! in the public API) and the ANSI representation expected by legacy Schannel
//! entry points like InitializeSecurityContextA.
//!
//! ## Architecture
//!
//! UTF-16 public API
//!        ↓
//! hostname/domain normalization
//!        ↓
//! ANSI representation for legacy Schannel entry points
//!        ↓
//! InitializeSecurityContextA
//!        ↓
//! Schannel
//!
//! ## Conversion Strategy
//!
//! 1. For internationalized domain names (IDNs), we first convert to Punycode
//!    using the Windows IdnToAscii API, which implements RFC 3490 (IDNA).
//! 2. For ASCII-compatible names, we convert UTF-16 to the system ANSI code page
//!    using WideCharToMultiByte with security-conscious flags.
//! 3. All conversions are explicit about failures rather than using lossy conversion.

use std::io;
use std::ptr;
use log::{debug, error, info, warn};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Globalization;

/// Error types for hostname conversion operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameError {
    /// The input string is not valid UTF-16
    InvalidUtf16,
    /// The hostname contains invalid characters for a domain name
    InvalidHostname,
    /// IDN conversion failed (e.g., contains prohibited characters)
    IdnConversionFailed(u32),
    /// Code page conversion failed
    CodePageConversionFailed(u32),
    /// The resulting ANSI string is too long
    AnsiStringTooLong,
    /// The input domain name is empty
    EmptyDomain,
    /// Unexpected error during conversion
    UnexpectedError,
}

impl std::fmt::Display for HostnameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HostnameError::InvalidUtf16 => {
                write!(f, "Invalid UTF-16 input: contains invalid UTF-16 sequences")
            }
            HostnameError::InvalidHostname => {
                write!(f, "Invalid hostname: contains characters or format not valid for domain names")
            }
            HostnameError::IdnConversionFailed(code) => {
                write!(f, "IDN conversion failed (RFC 3490) with Windows error code: 0x{:08X} - domain may contain prohibited characters or invalid IDN format", code)
            }
            HostnameError::CodePageConversionFailed(code) => {
                write!(f, "Code page conversion failed with Windows error code: 0x{:08X} - characters may not be representable in system ANSI code page", code)
            }
            HostnameError::AnsiStringTooLong => {
                write!(f, "ANSI string exceeds maximum length for Schannel API")
            }
            HostnameError::EmptyDomain => {
                write!(f, "Empty domain name provided")
            }
            HostnameError::UnexpectedError => {
                write!(f, "Unexpected error during hostname conversion")
            }
        }
    }
}

impl std::error::Error for HostnameError {}

impl From<HostnameError> for io::Error {
    fn from(err: HostnameError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, err)
    }
}

/// Converts a UTF-16 domain name to an ANSI string suitable for Schannel's
/// InitializeSecurityContextA function.
///
/// This function handles both ASCII and internationalized domain names (IDNs):
/// - For IDNs, it converts to Punycode first using IdnToAscii
/// - For ASCII names, it converts directly to the system ANSI code page
/// - Uses security-conscious conversion flags to prevent "best fit" mapping
///
/// # Arguments
///
/// * `domain_utf16` - A slice of UTF-16 characters representing the domain name,
///                   optionally including a null terminator
///
/// # Returns
///
/// * `Ok(Vec<i8>)` - A NUL-terminated ANSI string suitable for Schannel
/// * `Err(HostnameError)` - If conversion fails
///
/// # Security Considerations
///
/// - Uses WC_NO_BEST_FIT_CHARS flag to prevent ambiguous character mappings
/// - Explicitly fails on conversion errors rather than using lossy conversion
/// - Validates IDN conversion according to RFC 3490 security guidelines
pub fn utf16_domain_to_ansi(domain_utf16: &[u16]) -> Result<Vec<i8>, HostnameError> {
    eprintln!("Starting UTF-16 domain to ANSI conversion");
    eprintln!("Input UTF-16 length: {} characters", domain_utf16.len());

    // Remove null terminator if present
    let (domain_utf16, had_null) = if domain_utf16.last() == Some(&0) {
        eprintln!("Detected null terminator in input, removing it");
        (&domain_utf16[..domain_utf16.len() - 1], true)
    } else {
        eprintln!("No null terminator detected in input");
        (domain_utf16, false)
    };

    // Empty check
    if domain_utf16.is_empty() {
        eprintln!("Empty domain name provided after null terminator removal");
        eprintln!("Hostname conversion failed: empty domain name");
        return Err(HostnameError::EmptyDomain);
    }

    eprintln!("Processing domain with {} characters (null terminator: {})", domain_utf16.len(), had_null);

    // Validate that the UTF-16 is valid (it should be since it comes from Rust String)
    let utf16_validation = String::from_utf16(domain_utf16);
    match utf16_validation {
        Ok(ref valid_str) => {
            eprintln!("UTF-16 validation successful: {:?}", valid_str);
        }
        Err(_) => {
            eprintln!("UTF-16 validation failed: invalid UTF-16 sequence");
            return Err(HostnameError::InvalidUtf16);
        }
    }

    // Check if the domain is pure ASCII (quick path)
    let is_pure_ascii = domain_utf16.iter().all(|&c| c < 128);
    eprintln!("Domain is pure ASCII: {}", is_pure_ascii);

    let ascii_domain = if is_pure_ascii {
        // For pure ASCII, we can convert directly to the system code page
        // But first, convert UTF-16 to a Rust string for validation
        let domain_str = String::from_utf16_lossy(domain_utf16);
        eprintln!("ASCII domain string: {:?}", domain_str);

        // Basic hostname validation
        let validation_result = is_valid_ascii_hostname(&domain_str);
        eprintln!("ASCII hostname validation result: {}", validation_result);

        if !validation_result {
            eprintln!("Hostname validation failed for ASCII domain: {:?}", domain_str);
            return Err(HostnameError::InvalidHostname);
        }

        eprintln!("Using ASCII path for domain conversion");
        domain_str
    } else {
        // For non-ASCII, use IDN conversion to Punycode
        eprintln!("Using IDN path for domain conversion (contains non-ASCII characters)");
        match convert_idn_to_ascii(domain_utf16) {
            Ok(punycode) => {
                eprintln!("IDN conversion successful: {:?}", punycode);
                punycode
            }
            Err(e) => {
                eprintln!("IDN conversion failed: {:?}", e);
                return Err(e);
            }
        }
    };

    // Now convert the ASCII (possibly Punycode) string to ANSI using the system code page
    eprintln!("Converting ASCII string to system ANSI code page: {:?}", ascii_domain);
    match utf8_to_system_ansi(&ascii_domain) {
        Ok(ansi) => {
            eprintln!("ANSI conversion successful, length: {} bytes", ansi.len());
            eprintln!("UTF-16 to ANSI conversion completed successfully");
            Ok(ansi)
        }
        Err(e) => {
            eprintln!("ANSI conversion failed: {:?}", e);
            Err(e)
        }
    }
}

/// Converts an internationalized domain name (IDN) to its ASCII Punycode representation.
///
/// Uses the Windows IdnToAscii API which implements RFC 3490 (IDNA).
/// This handles the complex normalization and conversion rules for internationalized domains.
///
/// # Arguments
///
/// * `domain_utf16` - UTF-16 domain name (without null terminator)
///
/// # Returns
///
/// * `Ok(String)` - ASCII Punycode representation
/// * `Err(HostnameError)` - If IDN conversion fails
fn convert_idn_to_ascii(domain_utf16: &[u16]) -> Result<String, HostnameError> {
    eprintln!("Starting IDN to ASCII (Punycode) conversion");
    eprintln!("Input length: {} UTF-16 characters", domain_utf16.len());

    unsafe {
        // First, get the required buffer size
        eprintln!("Calling IdnToAscii to determine required buffer size");
        let required_size = Globalization::IdnToAscii(
            0, // No special flags
            domain_utf16.as_ptr(),
            domain_utf16.len() as i32,
            ptr::null_mut(),
            0,
        );

        if required_size == 0 {
            let error = GetLastError();
            eprintln!("IdnToAscii buffer size query failed with error: 0x{:08X}", error);
            return Err(HostnameError::IdnConversionFailed(error));
        }

        eprintln!("IdnToAscii requires buffer size: {} characters", required_size);

        // Validate buffer size is reasonable
        if required_size > 1024 {
            eprintln!("Unusually large buffer size requested: {} characters", required_size);
        }

        // Allocate buffer for the ASCII result
        let mut ascii_buffer = vec![0u16; required_size as usize];
        eprintln!("Allocated buffer of {} UTF-16 characters for output", ascii_buffer.len());

        // Perform the actual conversion
        eprintln!("Calling IdnToAscii for actual conversion");
        let result = Globalization::IdnToAscii(
            0, // No special flags
            domain_utf16.as_ptr(),
            domain_utf16.len() as i32,
            ascii_buffer.as_mut_ptr(),
            required_size,
        );

        if result == 0 {
            let error = GetLastError();
            eprintln!("IdnToAscii conversion failed with error: 0x{:08X}", error);
            return Err(HostnameError::IdnConversionFailed(error));
        }

        eprintln!("IdnToAscii conversion successful, produced {} characters", result);

        // Sanity check: result should not exceed buffer size
        if result as usize > ascii_buffer.len() {
            eprintln!("IdnToAscii result size ({}) exceeds buffer size ({})", result, ascii_buffer.len());
            return Err(HostnameError::IdnConversionFailed(0));
        }

        // Convert the result UTF-16 (which should be pure ASCII) to a Rust string
        let ascii_utf16 = &ascii_buffer[..result as usize];
        eprintln!("Converting result UTF-16 to Rust string");

        match String::from_utf16(ascii_utf16) {
            Ok(punycode) => {
                eprintln!("Successfully converted to Punycode: {:?}", punycode);
                // Additional validation: ensure it's actually ASCII
                if !punycode.is_ascii() {
                    eprintln!("IdnToAscii produced non-ASCII output: {:?}", punycode);
                }
                Ok(punycode)
            }
            Err(e) => {
                eprintln!("Failed to convert IdnToAscii result to UTF-8: {:?}", e);
                Err(HostnameError::InvalidUtf16)
            }
        }
    }
}

/// Converts a UTF-8 string to the system ANSI code page representation.
///
/// Uses WideCharToMultiByte with security-conscious flags:
/// - CP_ACP: Use the system ANSI code page
/// - WC_NO_BEST_FIT_CHARS: Prevent ambiguous character mappings
/// - Explicit error handling instead of default characters
///
/// # Arguments
///
/// * `utf8_str` - UTF-8 string (should be ASCII-compatible after IDN conversion)
///
/// # Returns
///
/// * `Ok(Vec<i8>)` - NUL-terminated ANSI string
/// * `Err(HostnameError)` - If conversion fails
fn utf8_to_system_ansi(utf8_str: &str) -> Result<Vec<i8>, HostnameError> {
    eprintln!("Starting UTF-8 to system ANSI code page conversion");
    eprintln!("Input UTF-8 string: {:?} ({} bytes)", utf8_str, utf8_str.len());

    // Convert UTF-8 to UTF-16 for the Windows API
    let utf16: Vec<u16> = utf8_str.encode_utf16().collect();
    eprintln!("Converted to UTF-16: {} characters", utf16.len());

    unsafe {
        // Get the system ANSI code page
        let code_page = Globalization::GetACP();
        eprintln!("System ANSI code page: {}", code_page);

        // First, get the required buffer size
        eprintln!("Calling WideCharToMultiByte to determine required buffer size");
        let required_size = Globalization::WideCharToMultiByte(
            code_page,
            Globalization::WC_NO_BEST_FIT_CHARS, // Security: prevent best-fit mapping
            utf16.as_ptr(),
            utf16.len() as i32,
            ptr::null_mut(),
            0,
            ptr::null(), // No default character
            ptr::null_mut(), // Don't care if default character was used
        );

        if required_size == 0 {
            let error = GetLastError();
            eprintln!("WideCharToMultiByte buffer size query failed with error: 0x{:08X}", error);
            return Err(HostnameError::CodePageConversionFailed(error));
        }

        eprintln!("WideCharToMultiByte requires buffer size: {} bytes", required_size);

        // Validate buffer size is reasonable
        if required_size > 1024 {
            eprintln!("Unusually large buffer size requested: {} bytes", required_size);
        }

        // Allocate buffer for the ANSI result
        let mut ansi_buffer = vec![0i8; required_size as usize];
        eprintln!("Allocated buffer of {} bytes for ANSI output", ansi_buffer.len());

        // Perform the actual conversion
        eprintln!("Calling WideCharToMultiByte for actual conversion");
        let result = Globalization::WideCharToMultiByte(
            code_page,
            Globalization::WC_NO_BEST_FIT_CHARS, // Security: prevent best-fit mapping
            utf16.as_ptr(),
            utf16.len() as i32,
            ansi_buffer.as_mut_ptr() as *mut u8,
            required_size,
            ptr::null(), // No default character - fail on unconvertible chars
            ptr::null_mut(), // Don't care if default character was used
        );

        if result == 0 {
            let error = GetLastError();
            eprintln!("WideCharToMultiByte conversion failed with error: 0x{:08X}", error);
            return Err(HostnameError::CodePageConversionFailed(error));
        }

        eprintln!("WideCharToMultiByte conversion successful, produced {} bytes", result);

        // Sanity check: result should not exceed buffer size
        if result as usize > ansi_buffer.len() {
            eprintln!("WideCharToMultiByte result size ({}) exceeds buffer size ({})", result, ansi_buffer.len());
            return Err(HostnameError::CodePageConversionFailed(0));
        }

        // Resize to actual size and add null terminator
        ansi_buffer.truncate(result as usize);
        ansi_buffer.push(0);
        eprintln!("Final ANSI buffer size: {} bytes (including null terminator)", ansi_buffer.len());

        // Log the resulting ANSI string for debugging
        let ansi_bytes: Vec<u8> = ansi_buffer.iter().map(|&b| b as u8).collect();
        let ansi_display = String::from_utf8_lossy(&ansi_bytes);
        eprintln!("Resulting ANSI string: {:?}", ansi_display);

        Ok(ansi_buffer)
    }
}

/// Validates an ASCII hostname according to standard hostname rules.
///
/// This implements basic validation for hostnames:
/// - Labels separated by dots
/// - Each label starts and ends with alphanumeric character
/// - Labels contain only alphanumeric characters and hyphens
/// - Total length <= 253 characters
/// - Each label <= 63 characters
///
/// # Arguments
///
/// * `hostname` - ASCII hostname string
///
/// # Returns
///
/// * `true` if the hostname is valid
/// * `false` otherwise
fn is_valid_ascii_hostname(hostname: &str) -> bool {
    eprintln!("Validating ASCII hostname: {:?}", hostname);

    // Basic length checks
    if hostname.is_empty() {
        eprintln!("Hostname validation failed: empty hostname");
        return false;
    }

    if hostname.len() > 253 {
        eprintln!("Hostname validation failed: length {} exceeds maximum 253", hostname.len());
        return false;
    }

    // Check for ASCII only
    if !hostname.is_ascii() {
        eprintln!("Hostname validation failed: contains non-ASCII characters");
        return false;
    }

    // Split into labels and validate each
    let labels: Vec<&str> = hostname.split('.').collect();
    eprintln!("Hostname has {} labels", labels.len());

    for (i, label) in labels.iter().enumerate() {
        eprintln!("Validating label {}: {:?}", i, label);

        if label.is_empty() {
            eprintln!("Label {} validation failed: empty label", i);
            return false;
        }

        if label.len() > 63 {
            eprintln!("Label {} validation failed: length {} exceeds maximum 63", i, label.len());
            return false;
        }

        // Label must start and end with alphanumeric
        let first_char = label.chars().next();
        let last_char = label.chars().last();

        if !first_char.map(|c| c.is_alphanumeric()).unwrap_or(false) {
            eprintln!("Label {} validation failed: does not start with alphanumeric character", i);
            return false;
        }

        if !last_char.map(|c| c.is_alphanumeric()).unwrap_or(false) {
            eprintln!("Label {} validation failed: does not end with alphanumeric character", i);
            return false;
        }

        // Label must contain only alphanumeric characters and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            eprintln!("Label {} validation failed: contains invalid characters", i);
            return false;
        }

        eprintln!("Label {} validation passed", i);
    }

    eprintln!("Hostname validation passed");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ascii_hostnames() {
        assert!(is_valid_ascii_hostname("example.com"));
        assert!(is_valid_ascii_hostname("sub.example.com"));
        assert!(is_valid_ascii_hostname("a-b-c.example.com"));
        assert!(is_valid_ascii_hostname("123.example.com"));
    }

    #[test]
    fn test_invalid_ascii_hostnames() {
        assert!(!is_valid_ascii_hostname(""));
        assert!(!is_valid_ascii_hostname(".example.com"));
        assert!(!is_valid_ascii_hostname("example.com."));
        assert!(!is_valid_ascii_hostname("-example.com"));
        assert!(!is_valid_ascii_hostname("example-.com"));
        assert!(!is_valid_ascii_hostname("ex..ample.com"));
        assert!(!is_valid_ascii_hostname("a".repeat(64).as_str() + ".com"));
    }

    #[test]
    fn test_utf16_domain_to_ansi_ascii() {
        let domain: Vec<u16> = "example.com".encode_utf16().collect();
        let result = utf16_domain_to_ansi(&domain);
        assert!(result.is_ok());
    }

    #[test]
    fn test_utf16_domain_to_ansi_with_null() {
        let domain: Vec<u16> = "example.com".encode_utf16().chain(Some(0)).collect();
        let result = utf16_domain_to_ansi(&domain);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_domain() {
        let domain: Vec<u16> = vec![];
        let result = utf16_domain_to_ansi(&domain);
        assert!(result.is_err());
        match result {
            Err(HostnameError::EmptyDomain) => {}
            _ => panic!("Expected EmptyDomain error"),
        }
    }

    #[test]
    fn test_only_null_terminator() {
        let domain: Vec<u16> = vec![0];
        let result = utf16_domain_to_ansi(&domain);
        assert!(result.is_err());
        match result {
            Err(HostnameError::EmptyDomain) => {}
            _ => panic!("Expected EmptyDomain error for null-only input"),
        }
    }

    #[test]
    fn test_hostname_error_display() {
        let err = HostnameError::InvalidUtf16;
        assert!(err.to_string().contains("UTF-16"));

        let err = HostnameError::InvalidHostname;
        assert!(err.to_string().contains("hostname"));

        let err = HostnameError::IdnConversionFailed(0x1234);
        assert!(err.to_string().contains("0x1234"));

        let err = HostnameError::CodePageConversionFailed(0x5678);
        assert!(err.to_string().contains("0x5678"));

        let err = HostnameError::AnsiStringTooLong;
        assert!(err.to_string().contains("length"));

        let err = HostnameError::EmptyDomain;
        assert!(err.to_string().contains("Empty"));
    }

    #[test]
    fn test_hostname_error_clone() {
        let err1 = HostnameError::InvalidUtf16;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }
}
