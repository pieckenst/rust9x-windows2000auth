// Test harness for rust9x Windows Auth DLL
// Debug-oriented standalone EXE

use rust9x_windows_auth::AuthErrorCode;
use std::time::Instant;

struct TestConfig {
    server_url: String,
    target_spn: String,
    test_http: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            server_url: String::from("http://example.com/api/test"),
            target_spn: String::from("HTTP/example.com"),
            test_http: false,
        }
    }
}

fn parse_config() -> TestConfig {
    let mut config = TestConfig::default();

    // Check environment variables first
    if let Ok(url) = std::env::var("RUST9X_SERVER_URL") {
        config.server_url = url;
        println!("[CONFIG] Server URL from env: {}", config.server_url);
    }

    if let Ok(spn) = std::env::var("RUST9X_TARGET_SPN") {
        config.target_spn = spn;
        println!("[CONFIG] Target SPN from env: {}", config.target_spn);
    }

    if let Ok(_) = std::env::var("RUST9X_TEST_HTTP") {
        config.test_http = true;
        println!("[CONFIG] HTTP test enabled from env");
    }

    // Check command line arguments
    let args: Vec<String> = std::env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "--server-url" => {
                if i + 1 < args.len() {
                    config.server_url = args[i + 1].clone();
                    println!("[CONFIG] Server URL from CLI: {}", config.server_url);
                }
            }
            "--target-spn" => {
                if i + 1 < args.len() {
                    config.target_spn = args[i + 1].clone();
                    println!("[CONFIG] Target SPN from CLI: {}", config.target_spn);
                }
            }
            "--test-http" => {
                config.test_http = true;
                println!("[CONFIG] HTTP test enabled from CLI");
            }
            "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {}
        }
    }

    config
}

fn print_usage() {
    println!("Usage: test_harness [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --server-url <URL>    Set the server URL for HTTP testing");
    println!("  --target-spn <SPN>     Set the target SPN for NTLM authentication");
    println!("  --test-http            Enable HTTP testing (requires network feature)");
    println!("  --help                 Print this help message");
    println!();
    println!("Environment Variables:");
    println!("  RUST9X_SERVER_URL      Set the server URL for HTTP testing");
    println!("  RUST9X_TARGET_SPN      Set the target SPN for NTLM authentication");
    println!("  RUST9X_TEST_HTTP       Enable HTTP testing (requires network feature)");
    println!();
    println!("Examples:");
    println!("  test_harness --server-url http://localhost:8080/api --target-spn HTTP/localhost");
    println!("  RUST9X_SERVER_URL=http://localhost:8080/api test_harness");
}

fn main() {
    println!("=== rust9x Windows Auth Test Harness ===");
    println!("Starting test sequence at: {:?}", std::time::SystemTime::now());
    println!("Platform: Windows");
    println!("Target: Debug-oriented standalone EXE\n");

    let config = parse_config();
    println!("[CONFIG] Server URL: {}", config.server_url);
    println!("[CONFIG] Target SPN: {}", config.target_spn);
    println!("[CONFIG] HTTP test: {}", if config.test_http { "enabled" } else { "disabled" });
    println!();

    let test_start = Instant::now();

    // Test 1: Initialize
    println!("[TEST 1] Initializing auth client...");
    println!("[PROGRESS] Calling auth_init()...");
    let init_start = Instant::now();

    let result = unsafe {
        rust9x_windows_auth::auth_init()
    };

    let init_duration = init_start.elapsed();
    println!("[PROGRESS] auth_init() completed in {:?}", init_duration);

    if result != AuthErrorCode::Success {
        println!("✗ Initialization failed: {:?}", result);
        println!("[DEBUG] Error code: 0x{:X}", result as u32);
        println!("[DEBUG] Initialization took: {:?}", init_duration);
        println!("\n[HALT] Cannot proceed without successful initialization");
        return;
    }

    println!("✓ Auth client initialized successfully");
    println!("[DEBUG] Initialization time: {:?}", init_duration);
    println!("[DEBUG] Auth client should now be available in AUTH_CLIENT static\n");


    // Test 2: Credential capture
    #[cfg(windows)]
    {
        println!("[TEST 2] Windows Credential UI");
        println!("--------------------------------");
        println!("[PROGRESS] Preparing credential prompt parameters...");
        println!("[DEBUG] Caption: 'rust9x Windows Authentication'");
        println!("[DEBUG] Message: 'Enter Windows credentials for NTLM testing'");

        let caption = "rust9x Windows Authentication\0";
        let message = "Enter Windows credentials for NTLM testing\0";

        let mut save = false;
        println!("[DEBUG] Save checkbox initial state: false");

        println!("[PROGRESS] Calling auth_prompt_credentials()...");
        let cred_start = Instant::now();

        let result = unsafe {
            rust9x_windows_auth::auth_prompt_credentials(
                caption.as_ptr() as *const i8,
                message.as_ptr() as *const i8,
                &mut save,
            )
        };

        let cred_duration = cred_start.elapsed();
        println!("[PROGRESS] Credential prompt completed in {:?}", cred_duration);

        println!("[HARNESS] Result      : {:?}", result.error_code);
        println!("[HARNESS] Save enabled: {}", save);
        println!("[DEBUG] Credential capture duration: {:?}", cred_duration);


        if result.error_code != AuthErrorCode::Success {
            println!("✗ Credential capture failed");
            println!("[DEBUG] Error code: 0x{:X}", result.error_code as u32);

            if !result.error_message.is_null() {
                let msg = unsafe {
                    std::ffi::CStr::from_ptr(result.error_message)
                };

                println!(
                    "[HARNESS] Error: {}",
                    msg.to_string_lossy()
                );
                println!("[DEBUG] Error message pointer: {:p}", result.error_message);
            } else {
                println!("[DEBUG] No error message available (null pointer)");
            }

            println!("[PROGRESS] Cleaning up due to failure...");
            unsafe {
                rust9x_windows_auth::auth_cleanup();
            }

            println!("\n[HALT] Cannot proceed without valid credentials");
            return;
        }


        println!("✓ Credentials captured successfully");
        println!("[DEBUG] Save checkbox final state: {}", save);
        println!("[DEBUG] User interaction time: {:?}", cred_duration);
        println!("[DEBUG] Credentials should now be stored in AUTH_CLIENT\n");
    }


    // Test 3: Dump client state
    println!("[TEST 3] Credential state");
    println!("--------------------------------");
    println!("[PROGRESS] Checking AUTH_CLIENT static state...");

    unsafe {
        match rust9x_windows_auth::AUTH_CLIENT.as_ref() {

            Some(client) => {
                println!("[HARNESS] Auth client exists: YES");
                println!("[DEBUG] AUTH_CLIENT pointer: {:p}", client);
                println!("[PROGRESS] Calling debug_credentials() to inspect state...");

                // Add this method in the DLL:
                //
                // pub fn debug_credentials(&self)
                //
                // so password never leaves the library.
                //

                client.debug_credentials();
                println!("[DEBUG] Credential state inspection completed");

            }


            None => {
                println!("[HARNESS] Auth client exists: NO");
                println!("[DEBUG] AUTH_CLIENT is None - this is unexpected after successful init");
                println!("[ERROR] Auth client should exist after successful initialization");
            }
        }
    }
    println!("[DEBUG] Credential state check completed\n");


    // Test 4: NTLM negotiate
    println!("\n[TEST 4] NTLM negotiate token");
    println!("--------------------------------");
    println!("[PROGRESS] Checking if AUTH_CLIENT is available for NTLM operations...");

    unsafe {

        if let Some(client) =
            rust9x_windows_auth::AUTH_CLIENT.as_mut()
        {
            println!("[DEBUG] AUTH_CLIENT is available for NTLM operations");
            println!("[DEBUG] Target SPN: {}", config.target_spn);

            println!("[PROGRESS] Generating NTLM negotiate token...");
            let ntlm_start = Instant::now();

            match client.generate_negotiate_token(
                &config.target_spn
            ) {

                Ok(token) => {
                    let ntlm_duration = ntlm_start.elapsed();
                    println!("[PROGRESS] NTLM negotiate token generated in {:?}", ntlm_duration);

                    println!(
                        "✓ Token generated successfully"
                    );

                    println!(
                        "[NTLM] Token length: {} bytes",
                        token.len()
                    );

                    println!("[DEBUG] Token pointer: {:p}", token.as_ptr());
                    println!("[DEBUG] Token capacity: {} bytes", token.capacity());

                    // Print hex dump of first 32 bytes for debugging
                    println!("[NTLM] First 32 bytes (hex):");
                    let hex_len = std::cmp::min(32, token.len());
                    for i in 0..hex_len {
                        print!("{:02X} ", token[i]);
                        if (i + 1) % 16 == 0 {
                            println!();
                        }
                    }
                    if hex_len > 0 && hex_len % 16 != 0 {
                        println!();
                    }

                    println!(
                        "[NTLM] Base64 encoded token:"
                    );

                    println!(
                        "{}",
                        base64_encode(&token)
                    );
                    println!("[DEBUG] NTLM token generation completed in {:?}", ntlm_duration);
                }


                Err(e) => {
                    let ntlm_duration = ntlm_start.elapsed();
                    println!("[PROGRESS] NTLM token generation failed after {:?}", ntlm_duration);

                    println!(
                        "✗ NTLM negotiate token generation failed"
                    );

                    println!(
                        "[NTLM] Error: {}",
                        e
                    );
                    println!("[DEBUG] Error occurred after {:?}", ntlm_duration);
                    println!("[DEBUG] Check credentials and NTLM implementation");
                }
            }
        } else {
            println!("[ERROR] AUTH_CLIENT is not available - cannot generate NTLM token");
            println!("[DEBUG] This indicates a problem with the auth client initialization");
        }
    }
    println!("[DEBUG] NTLM negotiate test completed\n");



    // Test 5
    #[cfg(feature="network")]
    {
        if config.test_http {
            println!("\n[TEST 5] HTTP NTLM request");
            println!("--------------------------------");
            println!("[DEBUG] Network feature is enabled");
            println!("[DEBUG] HTTP test is enabled via configuration");

            let url = format!("{}\0", config.server_url);
            let method = "GET\0";

            println!("[DEBUG] Target URL: {}", config.server_url);
            println!("[DEBUG] HTTP method: GET");
            println!("[DEBUG] Request body: null (0 bytes)");
            println!("[PROGRESS] Preparing HTTP NTLM request...");

            let http_start = Instant::now();

            let result = unsafe {
                rust9x_windows_auth::auth_http_request(
                    url.as_ptr() as *const i8,
                    method.as_ptr() as *const i8,
                    std::ptr::null(),
                    0,
                )
            };

            let http_duration = http_start.elapsed();
            println!("[PROGRESS] HTTP request completed in {:?}", http_duration);

            println!(
                "[HTTP] Result: {:?}",
                result.error_code
            );
            println!("[DEBUG] HTTP error code: 0x{:X}", result.error_code as u32);
            println!("[DEBUG] HTTP request duration: {:?}", http_duration);


            if !result.error_message.is_null() {
                println!("[DEBUG] Error message pointer: {:p}", result.error_message);

                let msg = unsafe {
                    std::ffi::CStr::from_ptr(
                        result.error_message
                    )
                };

                println!(
                    "[HTTP] Message: {}",
                    msg.to_string_lossy()
                );
            } else {
                println!("[DEBUG] No error message available (null pointer)");
            }

            if result.error_code == AuthErrorCode::Success {
                println!("✓ HTTP NTLM request completed successfully");
            } else {
                println!("✗ HTTP NTLM request failed");
            }
        } else {
            println!("\n[TEST 5] HTTP NTLM request");
            println!("--------------------------------");
            println!("[DEBUG] Network feature is enabled but HTTP test is disabled via configuration");
            println!("[INFO] Use --test-http flag or RUST9X_TEST_HTTP env var to enable HTTP testing");
        }
    }

    #[cfg(not(feature="network"))]
    {
        println!("\n[TEST 5] HTTP NTLM request");
        println!("--------------------------------");
        println!("[DEBUG] Network feature is DISABLED - skipping HTTP test");
        println!("[INFO] Enable 'network' feature to run HTTP NTLM tests");
    }


    println!("\n[CLEANUP]");
    println!("[PROGRESS] Starting cleanup sequence...");
    let cleanup_start = Instant::now();

    unsafe {
        println!("[DEBUG] Calling auth_cleanup()...");
        rust9x_windows_auth::auth_cleanup();
    }

    let cleanup_duration = cleanup_start.elapsed();
    println!("[PROGRESS] Cleanup completed in {:?}", cleanup_duration);

    println!("✓ Cleanup complete");
    println!("[DEBUG] Cleanup duration: {:?}", cleanup_duration);

    let total_duration = test_start.elapsed();
    println!("\n=== Harness Finished ===");
    println!("[SUMMARY] Total test execution time: {:?}", total_duration);
    println!("[SUMMARY] Test completed at: {:?}", std::time::SystemTime::now());
    println!("[DEBUG] All operations completed");
}



fn base64_encode(data: &[u8]) -> String {

    const BASE64_CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


    let mut result = String::new();

    let mut i = 0;


    while i < data.len() {

        let b0 = data[i];

        let b1 =
            if i + 1 < data.len()
            {
                data[i + 1]
            }
            else
            {
                0
            };


        let b2 =
            if i + 2 < data.len()
            {
                data[i + 2]
            }
            else
            {
                0
            };


        let chunk =
            ((b0 as u32) << 16)
            |
            ((b1 as u32) << 8)
            |
            (b2 as u32);



        result.push(
            BASE64_CHARS[((chunk >> 18) & 63) as usize]
                as char
        );

        result.push(
            BASE64_CHARS[((chunk >> 12) & 63) as usize]
                as char
        );


        if i + 1 < data.len() {
            result.push(
                BASE64_CHARS[((chunk >> 6) & 63) as usize]
                    as char
            );
        }
        else {
            result.push('=');
        }


        if i + 2 < data.len() {
            result.push(
                BASE64_CHARS[(chunk & 63) as usize]
                    as char
            );
        }
        else {
            result.push('=');
        }


        i += 3;
    }


    result
}