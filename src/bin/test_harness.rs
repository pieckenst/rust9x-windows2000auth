// Test harness for rust9x Windows Auth DLL
// This can be built as a standalone EXE for debugging alongside the DLL

use rust9x_windows_auth::{AuthErrorCode, WindowsAuthClient};

fn main() {
    println!("=== rust9x Windows Auth Test Harness ===\n");

    // Test 1: Initialize auth client
    println!("Test 1: Initializing auth client...");
    let result = unsafe { rust9x_windows_auth::auth_init() };
    if result == AuthErrorCode::Success {
        println!("✓ Auth client initialized successfully\n");
    } else {
        println!("✗ Failed to initialize auth client: {:?}\n", result);
        return;
    }

    // Test 2: Set credentials manually
    println!("Test 2: Setting credentials...");
    let username = "testuser";
    let password = "testpass123";
    let domain = std::ptr::null();

    let result = unsafe {
        rust9x_windows_auth::auth_set_credentials(
            username.as_ptr() as *const i8,
            password.as_ptr() as *const i8,
            domain,
        )
    };

    if result == AuthErrorCode::Success {
        println!("✓ Credentials set successfully\n");
    } else {
        println!("✗ Failed to set credentials: {:?}\n", result);
    }

    // Test 3: Generate NTLM negotiate token
    println!("Test 3: Generating NTLM negotiate token...");
    unsafe {
        if let Some(client) = rust9x_windows_auth::AUTH_CLIENT.as_mut() {
            match client.generate_negotiate_token("HTTP/example.com") {
                Ok(token) => {
                    println!("✓ NTLM negotiate token generated ({} bytes)", token.len());
                    println!("  Token (base64): {}", base64_encode(&token));
                    println!();
                }
                Err(e) => {
                    println!("✗ Failed to generate negotiate token: {}\n", e);
                }
            }
        }
    }

    // Test 4: Prompt for credentials (Windows only)
    #[cfg(windows)]
    {
        println!("Test 4: Prompting for Windows credentials...");
        let caption = "Authentication Required\0";
        let message = "Enter your Windows credentials\0";
        let mut save = false;

        let result = unsafe {
            rust9x_windows_auth::auth_prompt_credentials(
                caption.as_ptr() as *const i8,
                message.as_ptr() as *const i8,
                &mut save,
            )
        };

        if result.error_code == AuthErrorCode::Success {
            println!("✓ Credentials captured via dialog\n");
        } else {
            println!("✗ Credential prompt failed: {:?}\n", result.error_code);
        }
    }

    #[cfg(not(windows))]
    {
        println!("Test 4: Skipped (credential prompt only available on Windows)\n");
    }

    // Test 5: HTTP request (if network enabled)
    #[cfg(feature = "network")]
    {
        println!("Test 5: HTTP request with NTLM auth...");
        let url = "http://example.com/api/test\0";
        let method = "GET\0";
        let body_data = std::ptr::null();
        let body_length = 0;

        let result = unsafe {
            rust9x_windows_auth::auth_http_request(
                url.as_ptr() as *const i8,
                method.as_ptr() as *const i8,
                body_data,
                body_length,
            )
        };

        if result.error_code == AuthErrorCode::Success {
            println!("✓ HTTP request successful");
            if !result.response_data.is_null() && result.response_length > 0 {
                let response_data = unsafe { std::slice::from_raw_parts(result.response_data, result.response_length) };
                println!("  Response length: {} bytes", result.response_length);
                println!("  Response: {}", String::from_utf8_lossy(response_data));
            }
            println!();
        } else {
            println!("✗ HTTP request failed: {:?}", result.error_code);
            if !result.error_message.is_null() {
                let error_msg = unsafe { std::ffi::CStr::from_ptr(result.error_message) };
                println!("  Error: {}", error_msg.to_string_lossy());
            }
            println!();
        }
    }

    #[cfg(not(feature = "network"))]
    {
        println!("Test 5: Skipped (network feature not enabled)\n");
    }

    // Cleanup
    println!("Cleaning up...");
    unsafe { rust9x_windows_auth::auth_cleanup() };
    println!("✓ Cleanup complete\n");

    println!("=== Test Harness Complete ===");
}

fn base64_encode(data: &[u8]) -> String {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() {
            data[i + 1]
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2]
        } else {
            0
        };

        let chunk = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        result.push(BASE64_CHARS[((chunk >> 18) & 63) as usize] as char);
        result.push(BASE64_CHARS[((chunk >> 12) & 63) as usize] as char);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((chunk >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(BASE64_CHARS[(chunk & 63) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}
