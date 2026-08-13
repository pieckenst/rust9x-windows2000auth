// Test harness for rust9x Windows Auth DLL
// Debug-oriented standalone EXE

use rust9x_windows_auth::AuthErrorCode;
use std::time::Instant;

struct TestConfig {
    server_url: String,
    target_spn: String,
    test_http: bool,
    test_schannel_aw: bool,
    test_init_sec_ctx: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            server_url: String::from("http://example.com/api/test"),
            target_spn: String::from("HTTP/example.com"),
            test_http: false,
            test_schannel_aw: false,
            test_init_sec_ctx: false,
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

    if let Ok(_) = std::env::var("RUST9X_TEST_SCHANNEL_AW") {
        config.test_schannel_aw = true;
        println!("[CONFIG] Schannel A/W test enabled from env");
    }

    if let Ok(_) = std::env::var("RUST9X_TEST_INIT_SEC_CTX") {
        config.test_init_sec_ctx = true;
        println!("[CONFIG] InitializeSecurityContext test enabled from env");
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
            "--test-schannel-aw" => {
                config.test_schannel_aw = true;
                println!("[CONFIG] Schannel A/W test enabled from CLI");
            }
            "--test-init-sec-ctx" => {
                config.test_init_sec_ctx = true;
                println!("[CONFIG] InitializeSecurityContext test enabled from CLI");
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
    println!("  --server-url <URL>      Set the server URL for HTTP testing");
    println!("  --target-spn <SPN>       Set the target SPN for NTLM authentication");
    println!("  --test-http              Enable HTTP testing (requires network feature)");
    println!("  --test-schannel-aw        Enable Schannel AcquireCredentialsHandle A/W test");
    println!("  --test-init-sec-ctx       Enable Schannel InitializeSecurityContext A/W test");
    println!("  --help                   Print this help message");
    println!();
    println!("Environment Variables:");
    println!("  RUST9X_SERVER_URL        Set the server URL for HTTP testing");
    println!("  RUST9X_TARGET_SPN        Set the target SPN for NTLM authentication");
    println!("  RUST9X_TEST_HTTP         Enable HTTP testing (requires network feature)");
    println!("  RUST9X_TEST_SCHANNEL_AW  Enable Schannel AcquireCredentialsHandle A/W test");
    println!("  RUST9X_TEST_INIT_SEC_CTX Enable Schannel InitializeSecurityContext A/W test");
    println!();
    println!("Examples:");
    println!("  test_harness --server-url http://localhost:8080/api --target-spn HTTP/localhost");
    println!("  test_harness --test-schannel-aw");
    println!("  test_harness --test-init-sec-ctx");
    println!("  RUST9X_SERVER_URL=http://localhost:8080/api test_harness");
    println!("  RUST9X_TEST_SCHANNEL_AW=1 test_harness");
    println!("  RUST9X_TEST_INIT_SEC_CTX=1 test_harness");
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
    println!("[CONFIG] Schannel A/W test: {}", if config.test_schannel_aw { "enabled" } else { "disabled" });
    println!("[CONFIG] InitializeSecurityContext test: {}", if config.test_init_sec_ctx { "enabled" } else { "disabled" });
    println!();

    // Run Schannel A/W test if requested (standalone test, doesn't require auth init)
    if config.test_schannel_aw {
        println!("[TEST 0] Schannel AcquireCredentialsHandle A/W Comparison");
        println!("--------------------------------");
        println!("[PROGRESS] Running standalone Schannel API test...");
        println!("[DEBUG] This test compares AcquireCredentialsHandleA vs W with NULL parameters");
        
        #[cfg(windows)]
        {
            println!("[DEBUG] Platform: Windows - running Schannel test");
            test_schannel_acquire_credentials_aw();
        }
        
        #[cfg(not(windows))]
        {
            println!("[DEBUG] Platform: non-Windows - skipping Schannel test");
            println!("[INFO] Schannel tests are Windows-specific");
        }
        
        println!("[DEBUG] Schannel A/W test completed");
        println!("[INFO] Use --test-http or other tests to continue testing\n");
        return;
    }

    // Run InitializeSecurityContext test if requested
    if config.test_init_sec_ctx {
        println!("[TEST 0] Schannel InitializeSecurityContext A/W Comparison");
        println!("--------------------------------");
        println!("[PROGRESS] Running standalone InitializeSecurityContext test...");
        println!("[DEBUG] This test compares InitializeSecurityContextA vs W with same credential");
        
        #[cfg(windows)]
        {
            println!("[DEBUG] Platform: Windows - running InitializeSecurityContext test");
            test_initialize_security_context_aw();
        }
        
        #[cfg(not(windows))]
        {
            println!("[DEBUG] Platform: non-Windows - skipping InitializeSecurityContext test");
            println!("[INFO] Schannel tests are Windows-specific");
        }
        
        println!("[DEBUG] InitializeSecurityContext test completed");

        println!("[TEST 1] Schannel Credential/ISC Matrix Test");
        println!("--------------------------------");
        println!("[PROGRESS] Running credential/ISC matrix test...");
        println!("[DEBUG] This test all combinations of Acquire A/W with ISC A/W");
        
        #[cfg(windows)]
        {
            println!("[DEBUG] Platform: Windows - running credential/ISC matrix test");
            test_credential_isc_matrix();
        }
        
        #[cfg(not(windows))]
        {
            println!("[DEBUG] Platform: non-Windows - skipping credential/ISC matrix test");
            println!("[INFO] Schannel tests are Windows-specific");
        }
        
        println!("[DEBUG] Credential/ISC matrix test completed");
        println!("[INFO] Use --test-http or other tests to continue testing\n");
        return;
    }

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

        let mut save: i32 = 0;
        println!("[DEBUG] Save checkbox initial state: false (0)");

        println!("[PROGRESS] Calling auth_prompt_credentials()...");
        let cred_start = Instant::now();

        let mut result = rust9x_windows_auth::AuthInteropResult::success();
        unsafe {
            rust9x_windows_auth::auth_prompt_credentials(
                caption.as_ptr() as *const i8,
                message.as_ptr() as *const i8,
                &mut save,
                &mut result,
            )
        };

        let cred_duration = cred_start.elapsed();
        println!("[PROGRESS] Credential prompt completed in {:?}", cred_duration);

        println!("[HARNESS] Result      : {:?}", result.error_code);
        println!("[HARNESS] Save enabled: {}", save != 0);
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

            let mut result = rust9x_windows_auth::AuthInteropResult::success();
            unsafe {
                rust9x_windows_auth::auth_http_request(
                    url.as_ptr() as *const i8,
                    method.as_ptr() as *const i8,
                    std::ptr::null(),
                    0,
                    &mut result,
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


#[cfg(windows)]
fn test_schannel_acquire_credentials_aw() {
    use std::mem;
    use std::ptr;
    use windows_sys::Win32::Foundation;
    use windows_sys::Win32::Security::Authentication::Identity;
    use windows_sys::Win32::Security::Credentials;
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

#[cfg(windows)]
fn test_initialize_security_context_aw() {
    use std::mem;
    use std::ptr;
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

#[cfg(windows)]
fn test_credential_isc_matrix() {
    use std::mem;
    use std::ptr;
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
        *mut Credentials::SecHandle, *mut Identity::SecBufferDesc, *mut u32, *mut Foundation::FILETIME,
    ) -> i32;

    type InitializeSecurityContextWFunc = unsafe extern "system" fn(
        *const Credentials::SecHandle, *const Credentials::SecHandle, *const u16,
        u32, u32, u32, *const Identity::SecBufferDesc, u32,
        *mut Credentials::SecHandle, *mut Identity::SecBufferDesc, *mut u32, *mut Foundation::FILETIME,
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
                    Identity::UNISP_NAME_W as *mut u16,
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
                let mut names_buffer: [u16; 256] = mem::zeroed();
                let query_status = query_a_func(
                    &cred,
                    Identity::SECPKG_CRED_ATTR_NAMES,
                    names_buffer.as_mut_ptr() as *mut core::ffi::c_void,
                );
                eprintln!("  QueryCredentialsAttributesA: 0x{:08X}", query_status);
            }

            if let Some(query_w_ptr) = query_w_raw {
                let query_w_func: QueryCredentialsAttributesWFunc = mem::transmute(query_w_ptr);
                let mut names_buffer: [u16; 256] = mem::zeroed();
                let query_status = query_w_func(
                    &cred,
                    Identity::SECPKG_CRED_ATTR_NAMES,
                    names_buffer.as_mut_ptr() as *mut core::ffi::c_void,
                );
                eprintln!("  QueryCredentialsAttributesW: 0x{:08X}", query_status);
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