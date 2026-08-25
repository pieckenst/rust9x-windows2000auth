#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::fs::OpenOptions;
#[cfg(feature = "std")]
use std::io::Write;

use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation,
    Ntlm, SecurityBuffer, Sspi, SspiImpl, Username, ServerRequestFlags,
};

#[cfg(windows)]
use windows_sys::Win32::Security::Credentials::{
    CredUIPromptForCredentialsW,
    CredUIParseUserNameW,
    CREDUI_FLAGS_DO_NOT_PERSIST,
    CREDUI_INFOW,
};

#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{
    GetComputerNameExW,
    ComputerNameNetBIOS,
};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    GetLastError,
    ERROR_INSUFFICIENT_BUFFER,
    NO_ERROR,
    HWND,
};

#[cfg(feature = "std")]
fn log_to_file(message: &str) {
    let log_path = "E:\\code\\rust9x-windows2000auth\\rust-src\\auth_log.txt";
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
fn log_function_entry(function_name: &str, params: &str) {
    let msg = format!("[FUNCTION_ENTRY] {} - Parameters: {}", function_name, params);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_function_exit(function_name: &str, result: &str) {
    let msg = format!("[FUNCTION_EXIT] {} - Result: {}", function_name, result);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_object_size(object_name: &str, size: usize) {
    let msg = format!("[OBJECT_SIZE] {} - {} bytes", object_name, size);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_memory_info(context: &str) {
    // Log basic memory information
    let msg = format!("[MEMORY] {} - Context: {}", context, "Memory tracking enabled");
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_string_info(name: &str, s: &str) {
    let msg = format!("[STRING_INFO] {} - Length: {} bytes, Content: '{}'", 
                     name, s.len(), s);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_vec_info(name: &str, v: &[u8]) {
    let msg = format!("[VEC_INFO] {} - Length: {} bytes", 
                     name, v.len());
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_vec_u16_info(name: &str, v: &[u16]) {
    let msg = format!("[VEC_U16_INFO] {} - Length: {} elements", 
                     name, v.len());
    eprintln!("{}", msg);
    log_to_file(&msg);
}

#[cfg(feature = "std")]
fn log_option_info(name: &str, is_some: bool) {
    let status = if is_some { "Some" } else { "None" };
    let msg = format!("[OPTION_INFO] {} - Status: {}", name, status);
    eprintln!("{}", msg);
    log_to_file(&msg);
}

  


#[cfg(windows)]
#[cfg(not(feature = "std"))]
use alloc::ffi::CString;

/// Local NetBIOS computer name for NTLM local SAM accounts.
/// Supported since Windows 2000 (GetComputerNameExW).
#[cfg(windows)]
fn get_local_netbios_name() -> AuthResult<String> {
    const INITIAL_CAPACITY: usize = 16;

    let mut buffer = vec![0u16; INITIAL_CAPACITY];
    let mut size = buffer.len() as u32;

    unsafe {
        if GetComputerNameExW(
            ComputerNameNetBIOS,
            buffer.as_mut_ptr(),
            &mut size,
        ) != 0
        {
            buffer.truncate(size as usize);

            let name = String::from_utf16(&buffer).map_err(|e| {
                AuthError::AuthFailed(format!(
                    "Invalid NetBIOS computer name UTF-16: {}",
                    e
                ))
            })?;

            if name.is_empty() {
                return Err(AuthError::AuthFailed(
                    "Windows returned an empty NetBIOS computer name".to_string(),
                ));
            }

            return Ok(name);
        }

        let error = GetLastError();

        if error == ERROR_INSUFFICIENT_BUFFER {
            buffer.resize(size as usize, 0);

            if GetComputerNameExW(
                ComputerNameNetBIOS,
                buffer.as_mut_ptr(),
                &mut size,
            ) == 0
            {
                let retry_error = GetLastError();
                return Err(AuthError::AuthFailed(format!(
                    "GetComputerNameExW(ComputerNameNetBIOS) failed: 0x{:08X}",
                    retry_error
                )));
            }

            buffer.truncate(size as usize);

            let name = String::from_utf16(&buffer).map_err(|e| {
                AuthError::AuthFailed(format!(
                    "Invalid NetBIOS computer name UTF-16: {}",
                    e
                ))
            })?;

            if name.is_empty() {
                return Err(AuthError::AuthFailed(
                    "Windows returned an empty NetBIOS computer name".to_string(),
                ));
            }

            return Ok(name);
        }

        Err(AuthError::AuthFailed(format!(
            "GetComputerNameExW(ComputerNameNetBIOS) failed: 0x{:08X}",
            error
        )))
    }
}

/// Helper to log SSPI SecurityStatus codes
fn log_security_status<T>(status: &Result<T, sspi::Error>, operation: &str) {
    #[cfg(feature = "std")]
    {
        log_function_entry("log_security_status", &format!("operation: {}", operation));
        log_memory_info("log_security_status - processing result");
    }

    match status {
        Ok(_) => {
            let msg = format!("[SSPI] {} -> SUCCESS", operation);
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(&msg);
        }
        Err(err) => {
            let msg = format!("[SSPI] {} -> Error: {} (0x{:08X}) - {}", 
                operation,
                format_error_kind(err.error_type),
                err.error_type as u32,
                err.description
            );
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(&msg);
            if let Some(nstatus) = err.nstatus {
                let nstatus_msg = format!("[SSPI] {} -> NTSTATUS: {:?}", operation, nstatus);
                eprintln!("{}", nstatus_msg);
                #[cfg(feature = "std")]
                log_to_file(&nstatus_msg);
            }
        }
    }

    #[cfg(feature = "std")]
    {
        log_function_exit("log_security_status", "completed");
        log_memory_info("log_security_status - end");
    }
}

/// Format ErrorKind as symbolic name
fn format_error_kind(kind: sspi::ErrorKind) -> &'static str {
    match kind {
        sspi::ErrorKind::InsufficientMemory => "SEC_E_INSUFFICIENT_MEMORY",
        sspi::ErrorKind::InvalidHandle => "SEC_E_INVALID_HANDLE",
        sspi::ErrorKind::UnsupportedFunction => "SEC_E_UNSUPPORTED_FUNCTION",
        sspi::ErrorKind::TargetUnknown => "SEC_E_TARGET_UNKNOWN",
        sspi::ErrorKind::InternalError => "SEC_E_INTERNAL_ERROR",
        sspi::ErrorKind::SecurityPackageNotFound => "SEC_E_SECPKG_NOT_FOUND",
        sspi::ErrorKind::NotOwned => "SEC_E_NOT_OWNER",
        sspi::ErrorKind::CannotInstall => "SEC_E_CANNOT_INSTALL",
        sspi::ErrorKind::InvalidToken => "SEC_E_INVALID_TOKEN",
        sspi::ErrorKind::CannotPack => "SEC_E_CANNOT_PACK",
        sspi::ErrorKind::OperationNotSupported => "SEC_E_UNSUPPORTED_OPERATION",
        sspi::ErrorKind::NoImpersonation => "SEC_E_NO_IMPERSONATION",
        sspi::ErrorKind::LogonDenied => "SEC_E_LOGON_DENIED",
        sspi::ErrorKind::UnknownCredentials => "SEC_E_UNKNOWN_CREDENTIALS",
        sspi::ErrorKind::NoCredentials => "SEC_E_NO_CREDENTIALS",
        sspi::ErrorKind::MessageAltered => "SEC_E_MESSAGE_ALTERED",
        sspi::ErrorKind::OutOfSequence => "SEC_E_OUT_OF_SEQUENCE",
        sspi::ErrorKind::NoAuthenticatingAuthority => "SEC_E_NO_AUTHENTICATING_AUTHORITY",
        sspi::ErrorKind::BadPackageId => "SEC_E_BAD_PKGID",
        sspi::ErrorKind::ContextExpired => "SEC_E_CONTEXT_EXPIRED",
        sspi::ErrorKind::IncompleteMessage => "SEC_E_INCOMPLETE_MESSAGE",
        sspi::ErrorKind::IncompleteCredentials => "SEC_E_INCOMPLETE_CREDENTIALS",
        sspi::ErrorKind::BufferTooSmall => "SEC_E_BUFFER_TOO_SMALL",
        sspi::ErrorKind::WrongPrincipalName => "SEC_E_WRONG_PRINCIPAL",
        sspi::ErrorKind::TimeSkew => "SEC_E_TIME_SKEW",
        sspi::ErrorKind::UntrustedRoot => "SEC_E_UNTRUSTED_ROOT",
        sspi::ErrorKind::IllegalMessage => "SEC_E_ILLEGAL_MESSAGE",
        sspi::ErrorKind::CertificateUnknown => "SEC_E_CERT_UNKNOWN",
        sspi::ErrorKind::CertificateExpired => "SEC_E_CERT_EXPIRED",
        sspi::ErrorKind::EncryptFailure => "SEC_E_ENCRYPT_FAILURE",
        sspi::ErrorKind::DecryptFailure => "SEC_E_DECRYPT_FAILURE",
        sspi::ErrorKind::AlgorithmMismatch => "SEC_E_ALGORITHM_MISMATCH",
        sspi::ErrorKind::SecurityQosFailed => "SEC_E_SECURITY_QOS_FAILED",
        sspi::ErrorKind::UnfinishedContextDeleted => "SEC_E_UNFINISHED_CONTEXT_DELETED",
        sspi::ErrorKind::NoTgtReply => "SEC_E_NO_TGT_REPLY",
        sspi::ErrorKind::NoIpAddress => "SEC_E_NO_IP_ADDRESS",
        sspi::ErrorKind::WrongCredentialHandle => "SEC_E_WRONG_CREDENTIAL_HANDLE",
        sspi::ErrorKind::CryptoSystemInvalid => "SEC_E_CRYPTO_SYSTEM_INVALID",
        sspi::ErrorKind::MaxReferralsExceeded => "SEC_E_MAX_REFERRALS_EXCEEDED",
        sspi::ErrorKind::MustBeKdc => "SEC_E_MUST_BE_KDC",
        sspi::ErrorKind::StrongCryptoNotSupported => "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED",
        sspi::ErrorKind::TooManyPrincipals => "SEC_E_TOO_MANY_PRINCIPALS",
        sspi::ErrorKind::NoPaData => "SEC_E_NO_PA_DATA",
        sspi::ErrorKind::PkInitNameMismatch => "SEC_E_PKINIT_NAME_MISMATCH",
        sspi::ErrorKind::SmartCardLogonRequired => "SEC_E_SMARTCARD_LOGON_REQUIRED",
        sspi::ErrorKind::ShutdownInProgress => "SEC_E_SHUTDOWN_IN_PROGRESS",
        sspi::ErrorKind::KdcInvalidRequest => "SEC_E_KDC_INVALID_REQUEST",
        sspi::ErrorKind::KdcUnknownEType => "SEC_E_KDC_UNKNOWN_ETYPE",
        sspi::ErrorKind::KdcUnknownEType2 => "SEC_E_KDC_UNKNOWN_ETYPE2",
        sspi::ErrorKind::UnsupportedPreAuth => "SEC_E_UNSUPPORTED_PREAUTH",
        sspi::ErrorKind::DelegationRequired => "SEC_E_DELEGATION_REQUIRED",
        sspi::ErrorKind::DelegationPolicy => "SEC_E_DELEGATION_POLICY",
        _ => "UNKNOWN",
    }
}

/// Authentication credentials structure
#[derive(Debug, Clone)]
pub struct AuthCredentials {
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
}

/// Result of authentication operation
pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials(String),
    NetworkError(String),
    TlsError(String),
    AuthFailed(String),
    NotInitialized(String),
    InvalidParameter(String),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::InvalidCredentials(msg) => write!(f, "Invalid credentials: {}", msg),
            AuthError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            AuthError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            AuthError::AuthFailed(msg) => write!(f, "Authentication failed: {}", msg),
            AuthError::NotInitialized(msg) => write!(f, "Not initialized: {}", msg),
            AuthError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
        }
    }
}

/// Windows authentication client using NTLM
pub struct WindowsAuthClient {
    credentials: Option<AuthCredentials>,
    ntlm: Option<Ntlm>,
    credentials_handle: Option<sspi::AuthIdentityBuffers>,
}

impl WindowsAuthClient {
    pub fn new() -> AuthResult<Self> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::new", "no parameters");
            log_memory_info("WindowsAuthClient::new - creating new instance");
            log_object_size("WindowsAuthClient struct", core::mem::size_of::<WindowsAuthClient>());
        }

        let result = Ok(Self {
            credentials: None,
            ntlm: Some(Ntlm::new()),
            credentials_handle: None,
        });

        #[cfg(feature = "std")]
        {
            match &result {
            Ok(client) => {
                log_function_exit("WindowsAuthClient::new", "Success");
                log_option_info("credentials", client.credentials.is_some());
                log_option_info("ntlm", client.ntlm.is_some());
                log_option_info("credentials_handle", client.credentials_handle.is_some());
            }
            Err(e) => {
                log_function_exit("WindowsAuthClient::new", &format!("Error: {}", e));
            }
        }
        }

        result
    }

    pub fn set_credentials(&mut self, creds: AuthCredentials) {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::set_credentials", 
                              &format!("username length: {}, password length: {}, domain: {:?}", 
                                       creds.username.len(), creds.password.len(), creds.domain));
            log_string_info("creds.username", &creds.username);
            log_object_size("AuthCredentials struct", core::mem::size_of::<AuthCredentials>());
            log_object_size("String struct", core::mem::size_of::<String>());
            log_memory_info("set_credentials - before assignment");
        }

        // On Windows, defensively rewrite missing / local-alias domains
        // (., localhost, loopback) to the real NetBIOS computer name so that
        // auth_get_credentials → auth_set_credentials cannot reintroduce a
        // stale HTTP hostname as the NTLM account domain.
        #[cfg(windows)]
        {
            let fallback = creds.clone();
            match Self::normalize_stored_credentials(creds) {
                Ok(normalized) => {
                    #[cfg(feature = "std")]
                    {
                        log_string_info("set_credentials normalized username", &normalized.username);
                        log_option_info(
                            "set_credentials normalized domain present",
                            normalized.domain.is_some(),
                        );
                        if let Some(ref d) = normalized.domain {
                            log_string_info("set_credentials normalized domain", d);
                        }
                    }
                    self.credentials = Some(normalized);
                }
                Err(e) => {
                    // Normalization failure must not silently drop credentials.
                    // Keep the original payload; SSPI will surface any remaining
                    // domain problems at AcquireCredentialsHandle time.
                    let err_msg = format!(
                        "[AUTH] normalize_stored_credentials failed during set_credentials: {} — storing original credentials",
                        e
                    );
                    eprintln!("{}", err_msg);
                    #[cfg(feature = "std")]
                    log_to_file(&err_msg);
                    self.credentials = Some(fallback);
                }
            }
        }

        #[cfg(not(windows))]
        {
            self.credentials = Some(creds);
        }

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthClient::set_credentials", "Success");
            log_option_info("credentials", self.credentials.is_some());
            log_memory_info("set_credentials - after assignment");
        }
    }

    pub fn debug_credentials(&self) {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::debug_credentials", "no parameters");
            log_object_size("WindowsAuthClient struct", core::mem::size_of::<WindowsAuthClient>());
            log_memory_info("debug_credentials - start");
        }

        match &self.credentials {
            Some(creds) => {
                let msgs = vec![
                    "[AUTH] Credentials loaded".to_string(),
                    format!("[AUTH] Username : {}", creds.username),
                    format!("[AUTH] Domain   : {:?}", creds.domain),
                    if let Some(domain) = &creds.domain {
                        format!("[AUTH] Identity : {}\\{}", domain, creds.username)
                    } else {
                        format!("[AUTH] Identity : .\\{}", creds.username)
                    },
                    format!("[AUTH] Password length : {}", creds.password.len()),
                ];
                
                #[cfg(feature = "std")]
                {
                    log_string_info("creds.username", &creds.username);
                    log_string_info("creds.password", &format!("***{} chars***", creds.password.len()));
                    log_object_size("AuthCredentials struct", core::mem::size_of::<AuthCredentials>());
                }
                
                for msg in &msgs {
                    eprintln!("{}", msg);
                    #[cfg(feature = "std")]
                    log_to_file(msg);
                }
            }

            None => {
                let msg = "[AUTH] No credentials loaded";
                eprintln!("{}", msg);
                #[cfg(feature = "std")]
                log_to_file(msg);
            }
        }

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthClient::debug_credentials", "Success");
            log_memory_info("debug_credentials - end");
        }
    }

    /// Get a reference to the current credentials (if any)
    pub fn get_credentials(&self) -> Option<&AuthCredentials> {
        self.credentials.as_ref()
    }

    /// Reset NTLM state for a new authentication sequence
    /// Call this before starting a new NTLM handshake (new Type 1 message)
    pub fn reset_ntlm_state(&mut self) {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::reset_ntlm_state", "no parameters");
            log_memory_info("reset_ntlm_state - resetting NTLM state for new authentication sequence");
            log_option_info("ntlm before reset", self.ntlm.is_some());
            log_option_info("credentials_handle before reset", self.credentials_handle.is_some());
        }

        self.ntlm = Some(Ntlm::new());
        self.credentials_handle = None;

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm after reset", self.ntlm.is_some());
            log_option_info("credentials_handle after reset", self.credentials_handle.is_some());
            log_function_exit("WindowsAuthClient::reset_ntlm_state", "Success");
            log_memory_info("reset_ntlm_state - end");
        }
    }

    /// Generate NTLM negotiate token (Type 1 message)
    /// IMPORTANT: Call reset_ntlm_state() before this if starting a new authentication sequence
    pub fn generate_negotiate_token(&mut self, target_name: &str) -> AuthResult<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::generate_negotiate_token", 
                              &format!("target_name: '{}', length: {}", target_name, target_name.len()));
            log_string_info("target_name", target_name);
            log_object_size("WindowsAuthClient struct", core::mem::size_of::<WindowsAuthClient>());
            log_memory_info("generate_negotiate_token - start");
        }

        let creds = self
            .credentials
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials("No credentials set".to_string()))?;

        #[cfg(feature = "std")]
        {
            log_option_info("credentials", true);
            log_string_info("creds.username", &creds.username);
            log_object_size("String struct", core::mem::size_of::<String>());
        }

        let user_msgs = vec![
            format!("[SSPI] Username: {}", creds.username),
            format!("[SSPI] Domain: {:?}", creds.domain.as_deref()),
        ];
        for msg in &user_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        // Log NTLM state before generating Type 1
        #[cfg(feature = "std")]
        {
            log_option_info("ntlm before Type 1", self.ntlm.is_some());
            log_option_info("credentials_handle before Type 1", self.credentials_handle.is_some());
        }

        // NOTE: NTLM state is NOT reset here anymore to preserve security context
        // across Type 1 -> Type 2 -> Type 3 sequence
        // Call reset_ntlm_state() explicitly before starting a new authentication sequence

        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm", true);
            log_object_size("Ntlm struct", core::mem::size_of::<Ntlm>());
        }

        let msgs = vec![
            "[SSPI] API: AcquireCredentialsHandle".to_string(),
            "[SSPI] Package: NTLM".to_string(),
            "[SSPI] Principal: NULL".to_string(),
            "[SSPI] CredentialUse: SECPKG_CRED_OUTBOUND".to_string(),
        ];
        for msg in &msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let username = Username::new(&creds.username, creds.domain.as_deref()).map_err(|e| {
            AuthError::InvalidCredentials(format!("Invalid username format: {}", e))
        })?;

        #[cfg(feature = "std")]
        {
            log_object_size("Username struct", core::mem::size_of::<Username>());
        }

        let identity = AuthIdentity {
            username,
            password: creds.password.clone().into(),
        };

        #[cfg(feature = "std")]
        {
            log_object_size("AuthIdentity struct", core::mem::size_of::<AuthIdentity>());
            log_memory_info("generate_negotiate_token - before acquire_credentials_handle");
        }

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(ntlm);

        log_security_status(&acq_cred_result, "AcquireCredentialsHandle");
        let acq_cred_result = acq_cred_result.map_err(|e| {
            AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e))
        })?;

        // Store the credentials handle for reuse in process_challenge
        self.credentials_handle = acq_cred_result.credentials_handle;

        #[cfg(feature = "std")]
        {
            log_memory_info("generate_negotiate_token - after acquire_credentials_handle");
            log_option_info("credentials_handle", self.credentials_handle.is_some());
        }

        let init_msgs = vec![
            format!("[SSPI] API: InitializeSecurityContext"),
            format!("[SSPI] TargetName: {}", target_name),
            "[SSPI] ContextRequirements: CONNECTION | ALLOCATE_MEMORY".to_string(),
            "[SSPI] DataRepresentation: Native".to_string(),
        ];
        for msg in &init_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        #[cfg(feature = "std")]
        {
            log_object_size("output_buffer", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("input_buffer", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("output_buffer Vec", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("input_buffer Vec", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_memory_info("generate_negotiate_token - before initialize_security_context");
        }

        let mut builder = sspi::builders::InitializeSecurityContext::<
            Option<sspi::AuthIdentityBuffers>,
            sspi::builders::WithoutCredentialsHandle,
            sspi::builders::WithoutContextRequirements,
            sspi::builders::WithoutTargetDataRepresentation,
            sspi::builders::WithoutOutput,
        >::default()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(ClientRequestFlags::CONNECTION | ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(target_name)
            .with_input(input_buffer.as_mut_slice())
            .with_output(output_buffer.as_mut_slice());

        let init_result = ntlm.initialize_security_context_impl(&mut builder);
        log_security_status(&init_result, "InitializeSecurityContext");
        init_result.map_err(|e| {
            AuthError::AuthFailed(format!("Failed to initialize security context: {}", e))
        })?;

        #[cfg(feature = "std")]
        {
            log_memory_info("generate_negotiate_token - after initialize_security_context");
        }

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

        #[cfg(feature = "std")]
        {
            log_vec_info("token", &token);
            log_object_size("token Vec", core::mem::size_of::<Vec<u8>>());
            log_object_size("token Vec<u8>", core::mem::size_of::<Vec<u8>>());
        }

        let token_msg = format!("[SSPI] Negotiate token generated ({} bytes)", token.len());
        eprintln!("{}", token_msg);
        #[cfg(feature = "std")]
        log_to_file(&token_msg);

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm after Type 1", self.ntlm.is_some());
            log_option_info("credentials_handle after Type 1", self.credentials_handle.is_some());
            log_function_exit("WindowsAuthClient::generate_negotiate_token",
                             &format!("Success - token size: {} bytes", token.len()));
            log_memory_info("generate_negotiate_token - end");
        }

        Ok(token)
    }

    /// Process NTLM challenge and generate authenticate token (Type 3 message)
    pub fn process_challenge(&mut self, challenge: &[u8], target_name: &str) -> AuthResult<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::process_challenge", 
                              &format!("challenge length: {}, target_name: '{}', length: {}", 
                                       challenge.len(), target_name, target_name.len()));
            log_vec_info("challenge", challenge);
            log_string_info("target_name", target_name);
            log_object_size("WindowsAuthClient struct", core::mem::size_of::<WindowsAuthClient>());
            log_memory_info("process_challenge - start");
        }

        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm before Type 3", true);
            log_option_info("credentials_handle before Type 3", self.credentials_handle.is_some());
            log_object_size("Ntlm struct", core::mem::size_of::<Ntlm>());
        }

        // Ensure we have credentials handle
        if self.credentials_handle.is_none() {
            let creds = self
                .credentials
                .as_ref()
                .ok_or_else(|| AuthError::InvalidCredentials("No credentials set".to_string()))?;

            #[cfg(feature = "std")]
            {
                log_option_info("credentials", true);
                log_string_info("creds.username", &creds.username);
                log_object_size("String struct", core::mem::size_of::<String>());
            }

            let user_msgs = vec![
                format!("[SSPI] Username: {}", creds.username),
                format!("[SSPI] Domain: {:?}", creds.domain.as_deref()),
            ];
            for msg in &user_msgs {
                eprintln!("{}", msg);
                #[cfg(feature = "std")]
                log_to_file(msg);
            }

            let msgs = vec![
                "[SSPI] API: AcquireCredentialsHandle (challenge)".to_string(),
                "[SSPI] Package: NTLM".to_string(),
                "[SSPI] Principal: NULL".to_string(),
                "[SSPI] CredentialUse: SECPKG_CRED_OUTBOUND".to_string(),
            ];
            for msg in &msgs {
                eprintln!("{}", msg);
                #[cfg(feature = "std")]
                log_to_file(msg);
            }

            let username = Username::new(&creds.username, creds.domain.as_deref()).map_err(|e| {
                AuthError::InvalidCredentials(format!("Invalid username format: {}", e))
            })?;

            #[cfg(feature = "std")]
            {
                log_object_size("Username struct", core::mem::size_of::<Username>());
            }

            let identity = AuthIdentity {
                username,
                password: creds.password.clone().into(),
            };

            #[cfg(feature = "std")]
            {
                log_object_size("AuthIdentity struct", core::mem::size_of::<AuthIdentity>());
                log_memory_info("process_challenge - before acquire_credentials_handle");
            }

            let acq_cred_result = ntlm
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Outbound)
                .with_auth_data(&identity)
                .execute(ntlm);

            log_security_status(&acq_cred_result, "AcquireCredentialsHandle (challenge)");
            let acq_cred_result = acq_cred_result.map_err(|e| {
                AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e))
            })?;

            self.credentials_handle = acq_cred_result.credentials_handle;

            #[cfg(feature = "std")]
            {
                log_memory_info("process_challenge - after acquire_credentials_handle");
                log_option_info("credentials_handle", self.credentials_handle.is_some());
            }
        } else {
            #[cfg(feature = "std")]
            {
                log_memory_info("process_challenge - reusing existing credentials handle");
            }
        }

        let init_msgs = vec![
            format!("[SSPI] API: InitializeSecurityContext (challenge - Type 3)"),
            format!("[SSPI] TargetName: {}", target_name),
            format!("[SSPI] Challenge size: {} bytes", challenge.len()),
            "[SSPI] ContextRequirements: CONNECTION | ALLOCATE_MEMORY".to_string(),
            "[SSPI] DataRepresentation: Native".to_string(),
        ];
        for msg in &init_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        
        // Handle empty challenge (server sent "Negotiate" or "NTLM" without token)
        // In this case, we pass an empty input buffer to SSPI
        let mut input_buffer = if challenge.is_empty() {
            eprintln!("[SSPI] Empty challenge - passing empty input buffer to SSPI");
            Vec::new()
        } else {
            vec![SecurityBuffer::new(challenge.to_vec(), BufferType::Token)]
        };

        #[cfg(feature = "std")]
        {
            log_object_size("output_buffer", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("input_buffer", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("output_buffer Vec", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("input_buffer Vec", core::mem::size_of::<Vec<SecurityBuffer>>());
            if !challenge.is_empty() {
                log_object_size("challenge Vec clone", core::mem::size_of::<Vec<u8>>());
            }
            log_memory_info("process_challenge - before initialize_security_context");
        }

        let mut builder = sspi::builders::InitializeSecurityContext::<
            Option<sspi::AuthIdentityBuffers>,
            sspi::builders::WithoutCredentialsHandle,
            sspi::builders::WithoutContextRequirements,
            sspi::builders::WithoutTargetDataRepresentation,
            sspi::builders::WithoutOutput,
        >::default()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(ClientRequestFlags::CONNECTION | ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(target_name)
            .with_input(input_buffer.as_mut_slice())
            .with_output(output_buffer.as_mut_slice());

        let init_result = ntlm.initialize_security_context_impl(&mut builder);
        log_security_status(&init_result, "InitializeSecurityContext (challenge)");
        init_result.map_err(|e| {
            AuthError::AuthFailed(format!("Failed to process challenge: {}", e))
        })?;

        #[cfg(feature = "std")]
        {
            log_memory_info("process_challenge - after initialize_security_context");
        }

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

        #[cfg(feature = "std")]
        {
            log_vec_info("token", &token);
            log_object_size("token Vec", core::mem::size_of::<Vec<u8>>());
            log_object_size("token Vec<u8>", core::mem::size_of::<Vec<u8>>());
        }

        let token_msg = format!("[SSPI] Authenticate token generated ({} bytes)", token.len());
        eprintln!("{}", token_msg);
        #[cfg(feature = "std")]
        log_to_file(&token_msg);

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm after Type 3", self.ntlm.is_some());
            log_option_info("credentials_handle after Type 3", self.credentials_handle.is_some());
            log_function_exit("WindowsAuthClient::process_challenge",
                             &format!("Success - token size: {} bytes", token.len()));
            log_memory_info("process_challenge - end");
        }

        Ok(token)
    }

    /// Prompt for credentials using Windows credential dialog
    #[cfg(windows)]
    pub fn prompt_for_windows_credentials(
        &mut self,
        caption: &str,
        message: &str,
        save: bool,
    ) -> AuthResult<bool> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::prompt_for_windows_credentials", 
                              &format!("caption: '{}', message: '{}', save: {}", caption, message, save));
            log_string_info("caption", caption);
            log_string_info("message", message);
            log_object_size("WindowsAuthClient struct", core::mem::size_of::<WindowsAuthClient>());
            log_memory_info("prompt_for_windows_credentials - start");
        }

        let msgs = vec![
            "[CredUI] API: CredUICmdLinePromptForCredentialsW".to_string(),
            format!("[CredUI] Caption: {}", caption),
            format!("[CredUI] Message: {}", message),
            format!("[CredUI] Save checkbox: {}", save),
            "[CredUI] Flags: GENERIC_CREDENTIALS | DO_NOT_PERSIST".to_string(),
        ];
        for msg in &msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let caption_wide = Self::to_wide(caption);
        let message_wide = Self::to_wide(message);

        #[cfg(feature = "std")]
        {
            log_vec_u16_info("caption_wide", &caption_wide);
            log_vec_u16_info("message_wide", &message_wide);
            log_object_size("caption_wide Vec", core::mem::size_of::<Vec<u16>>());
            log_object_size("message_wide Vec", core::mem::size_of::<Vec<u16>>());
        }

        let mut username_buf = [0u16; 256];
        let mut password_buf = [0u16; 256];

        #[cfg(feature = "std")]
        {
            log_object_size("username_buf", core::mem::size_of::<[u16; 256]>());
            log_object_size("password_buf", core::mem::size_of::<[u16; 256]>());
        }

        let mut save_flag: i32 = if save { 1 } else { 0 };

        let cred_info = CREDUI_INFOW {
            cbSize: core::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: 0 as HWND,
            pszMessageText: message_wide.as_ptr(),
            pszCaptionText: caption_wide.as_ptr(),
            hbmBanner: core::ptr::null_mut(),
        };

        #[cfg(feature = "std")]
        {
            log_object_size("CREDUI_INFOW struct", core::mem::size_of::<CREDUI_INFOW>());
            log_memory_info("prompt_for_windows_credentials - before CredUIPromptForCredentialsW");
        }

        let flags = CREDUI_FLAGS_DO_NOT_PERSIST;

        // IMPORTANT:
        // CredUIPromptForCredentialsW uses pszTargetName as the default
        // domain/server name when the user enters only a bare username.
        // Microsoft documents that when the user does not explicitly supply a
        // domain/server, CredUI forms DomainName\UserName from pszTargetName.
        //
        // For a local SAM account, pszTargetName MUST be the local machine's
        // NetBIOS name (GetComputerNameExW / ComputerNameNetBIOS), NOT the
        // HTTP/TLS hostname ("localhost") and NOT an application product name.
        //
        // These are intentionally different concepts:
        //   CredUI target     -> local NetBIOS (account qualification)
        //   NTLM account      -> NETBIOS\username
        //   SSPI target/SPN   -> HTTP/localhost  (unchanged elsewhere)
        //   TLS/HTTP hostname -> localhost       (unchanged elsewhere)
        let local_netbios_name = get_local_netbios_name()?;

        #[cfg(feature = "std")]
        {
            log_string_info("CredUI target / local NetBIOS name", &local_netbios_name);
            log_object_size(
                "local_netbios_name String",
                core::mem::size_of::<String>(),
            );
            log_memory_info(
                "prompt_for_windows_credentials - CredUI pszTargetName resolved to NetBIOS",
            );
        }

        {
            let target_msg = format!(
                "[CredUI] pszTargetName (default domain/server) = {}",
                local_netbios_name
            );
            eprintln!("{}", target_msg);
            #[cfg(feature = "std")]
            log_to_file(&target_msg);
        }

        let target_name = Self::to_wide(&local_netbios_name);

        #[cfg(feature = "std")]
        {
            log_vec_u16_info("CredUI target_name wide", &target_name);
        }

        let result = unsafe {
            CredUIPromptForCredentialsW(
                &cred_info as *const CREDUI_INFOW,
                target_name.as_ptr(),
                core::ptr::null(), // pContext
                0,                 // dwAuthError
                username_buf.as_mut_ptr(),
                username_buf.len() as u32,
                password_buf.as_mut_ptr(),
                password_buf.len() as u32,
                &mut save_flag,
                flags,
            )
        };

        #[cfg(feature = "std")]
        {
            log_memory_info("prompt_for_windows_credentials - after CredUIPromptForCredentialsW");
        }

        let hresult_msg = format!("[CredUI] HRESULT: 0x{:08X}", result);
        eprintln!("{}", hresult_msg);
        #[cfg(feature = "std")]
        log_to_file(&hresult_msg);

        if result != 0 {
            let last_error = unsafe { GetLastError() };
            let last_error_msg = format!("[CredUI] GetLastError: 0x{:08X}", last_error);
            eprintln!("{}", last_error_msg);
            #[cfg(feature = "std")]
            log_to_file(&last_error_msg);

            #[cfg(feature = "std")]
            {
                log_function_exit("WindowsAuthClient::prompt_for_windows_credentials", 
                                 &format!("Error - HRESULT: 0x{:08X}", result));
                log_memory_info("prompt_for_windows_credentials - end (error)");
            }

            return Err(AuthError::InvalidCredentials(format!(
                "Credential prompt failed - HRESULT: 0x{:08X}, GetLastError: 0x{:08X}",
                result, last_error
            )));
        }

        // CredUIPromptForCredentialsW writes NUL-terminated wide strings.
        let username_len_pos = username_buf.iter().position(|&c| c == 0).unwrap_or(username_buf.len());
        let password_len_pos = password_buf.iter().position(|&c| c == 0).unwrap_or(password_buf.len());

        let entered_username = Self::from_wide(&username_buf[..username_len_pos]);
        let password = Self::from_wide(&password_buf[..password_len_pos]);

        #[cfg(feature = "std")]
        {
            log_string_info("entered_username", &entered_username);
            log_object_size("entered_username String", core::mem::size_of::<String>());
            log_object_size("password String", core::mem::size_of::<String>());
        }

        let buf_msgs = vec![
            format!("[CredUI] Username length: {}", username_len_pos),
            format!("[CredUI] Password length: {}", password_len_pos),
            format!("[CredUI] Save flag result: {}", save_flag),
        ];
        for msg in &buf_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let credentials =
            Self::normalize_windows_credentials(entered_username, password)?;

        let parsed_msgs = vec![
            format!("[CredUI] Parsed username: {}", credentials.username),
            format!("[CredUI] Parsed domain: {:?}", credentials.domain),
        ];
        for msg in &parsed_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        #[cfg(feature = "std")]
        {
            log_string_info("normalized username", &credentials.username);
            if let Some(domain) = &credentials.domain {
                log_string_info("normalized domain", domain);
            }
            log_option_info("parsed domain", credentials.domain.is_some());
            log_memory_info("prompt_for_windows_credentials - before credentials assignment");
        }

        self.credentials = Some(credentials);

        #[cfg(feature = "std")]
        {
            log_memory_info("prompt_for_windows_credentials - after credentials assignment");
        }

        let success_msg = "[CredUI] Credentials stored successfully";
        eprintln!("{}", success_msg);
        #[cfg(feature = "std")]
        log_to_file(success_msg);

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthClient::prompt_for_windows_credentials", "Success");
            log_memory_info("prompt_for_windows_credentials - end (success)");
        }

        Ok(save_flag != 0)
    }

    #[cfg(not(windows))]
    pub fn prompt_for_windows_credentials(
        &mut self,
        _caption: &str,
        _message: &str,
        _save: bool,
    ) -> AuthResult<bool> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthClient::prompt_for_windows_credentials (non-Windows)", 
                              "caption, message, save parameters");
            log_memory_info("prompt_for_windows_credentials (non-Windows) - start");
        }

        let result = Err(AuthError::NotInitialized(
            "Credential prompt only available on Windows".to_string(),
        ));

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthClient::prompt_for_windows_credentials (non-Windows)", 
                             "Error - not available on this platform");
            log_memory_info("prompt_for_windows_credentials (non-Windows) - end");
        }

        result
    }

    /// Parse CredUI username via CredUIParseUserNameW (DOMAIN\user and UPN forms).
    ///
    /// This is the Windows-documented parser for strings returned by
    /// CredUIPromptForCredentialsW. Do not replace with hand-rolled
    /// `find('\\')` / `find('@')` splits.
    #[cfg(windows)]
    fn parse_windows_username(input: &str) -> AuthResult<(String, Option<String>)> {
        const USER_CAPACITY: usize = 512;
        const DOMAIN_CAPACITY: usize = 512;

        #[cfg(feature = "std")]
        {
            log_function_entry(
                "parse_windows_username",
                &format!("input length: {}", input.len()),
            );
            log_string_info("CredUIParseUserNameW input", input);
            log_memory_info("parse_windows_username - start");
        }

        let input_wide = Self::to_wide(input);

        let mut user_buffer = vec![0u16; USER_CAPACITY];
        let mut domain_buffer = vec![0u16; DOMAIN_CAPACITY];

        #[cfg(feature = "std")]
        {
            log_object_size("user_buffer", USER_CAPACITY * core::mem::size_of::<u16>());
            log_object_size(
                "domain_buffer",
                DOMAIN_CAPACITY * core::mem::size_of::<u16>(),
            );
        }

        let result = unsafe {
            CredUIParseUserNameW(
                input_wide.as_ptr(),
                user_buffer.as_mut_ptr(),
                user_buffer.len() as u32,
                domain_buffer.as_mut_ptr(),
                domain_buffer.len() as u32,
            )
        };

        {
            let parse_status_msg =
                format!("[CredUI] CredUIParseUserNameW status: 0x{:08X}", result);
            eprintln!("{}", parse_status_msg);
            #[cfg(feature = "std")]
            log_to_file(&parse_status_msg);
        }

        match result {
            NO_ERROR => {
                let user_len = user_buffer
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(user_buffer.len());

                let domain_len = domain_buffer
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(domain_buffer.len());

                #[cfg(feature = "std")]
                {
                    log_object_size("parsed user UTF-16 length", user_len);
                    log_object_size("parsed domain UTF-16 length", domain_len);
                }

                let user = String::from_utf16(&user_buffer[..user_len]).map_err(|e| {
                    AuthError::InvalidCredentials(format!("Invalid parsed username: {}", e))
                })?;

                let domain = String::from_utf16(&domain_buffer[..domain_len]).map_err(|e| {
                    AuthError::InvalidCredentials(format!("Invalid parsed domain: {}", e))
                })?;

                let domain = if domain.is_empty() {
                    None
                } else {
                    Some(domain)
                };

                #[cfg(feature = "std")]
                {
                    log_string_info("CredUIParseUserNameW username", &user);
                    log_option_info("CredUIParseUserNameW domain present", domain.is_some());
                    if let Some(ref d) = domain {
                        log_string_info("CredUIParseUserNameW domain", d);
                    }
                    log_function_exit(
                        "parse_windows_username",
                        &format!("Success - user='{}', domain={:?}", user, domain),
                    );
                    log_memory_info("parse_windows_username - end");
                }

                Ok((user, domain))
            }

            ERROR_INSUFFICIENT_BUFFER => {
                #[cfg(feature = "std")]
                {
                    log_function_exit(
                        "parse_windows_username",
                        "Error - ERROR_INSUFFICIENT_BUFFER",
                    );
                }
                Err(AuthError::InvalidCredentials(
                    "Credential username/domain exceeds CredUI parser buffer size".to_string(),
                ))
            }

            error => {
                #[cfg(feature = "std")]
                {
                    log_function_exit(
                        "parse_windows_username",
                        &format!("Error - 0x{:08X}", error),
                    );
                }
                Err(AuthError::InvalidCredentials(format!(
                    "CredUIParseUserNameW failed: 0x{:08X}",
                    error
                )))
            }
        }
    }

    /// Returns true when `domain` is a local-machine alias that must be rewritten
    /// to the real NetBIOS computer name for NTLM local SAM authentication.
    ///
    /// Includes:
    /// - `.` (Windows local-machine qualifier)
    /// - empty / whitespace-only
    /// - `localhost` / `LOCALHOST` (HTTP hostname mistakenly used as CredUI target)
    /// - loopback literals that are never valid NTLM account domains
    #[cfg(windows)]
    fn is_local_machine_domain_alias(domain: &str) -> bool {
        let trimmed = domain.trim();
        if trimmed.is_empty() || trimmed == "." {
            return true;
        }

        trimmed.eq_ignore_ascii_case("localhost")
            || trimmed.eq_ignore_ascii_case("127.0.0.1")
            || trimmed.eq_ignore_ascii_case("::1")
            || trimmed.eq_ignore_ascii_case("[::1]")
    }

    /// Resolve the NTLM account domain component.
    ///
    /// Rules (local-SAM focused, no invented UPN semantics):
    /// - missing / `.` / localhost-style aliases → local NetBIOS computer name
    /// - any other explicit DOMAIN → preserved verbatim (AD / remote NetBIOS)
    #[cfg(windows)]
    fn resolve_ntlm_account_domain(parsed_domain: Option<String>) -> AuthResult<Option<String>> {
        #[cfg(feature = "std")]
        {
            log_function_entry(
                "resolve_ntlm_account_domain",
                &format!("parsed_domain={:?}", parsed_domain),
            );
            log_option_info("parsed_domain present", parsed_domain.is_some());
        }

        let resolved = match parsed_domain.as_deref() {
            None => {
                let local_netbios = get_local_netbios_name()?;
                #[cfg(feature = "std")]
                {
                    log_string_info(
                        "domain resolution path",
                        "None -> local NetBIOS (bare username / CredUI default)",
                    );
                    log_string_info("resolved local NetBIOS domain", &local_netbios);
                }
                Some(local_netbios)
            }

            Some(domain) if Self::is_local_machine_domain_alias(domain) => {
                let local_netbios = get_local_netbios_name()?;
                #[cfg(feature = "std")]
                {
                    log_string_info(
                        "domain resolution path",
                        "local-machine alias -> local NetBIOS",
                    );
                    log_string_info("alias domain before rewrite", domain);
                    log_string_info("resolved local NetBIOS domain", &local_netbios);
                }
                {
                    let rewrite_msg = format!(
                        "[CredUI] Rewriting local-machine domain alias '{}' -> '{}'",
                        domain, local_netbios
                    );
                    eprintln!("{}", rewrite_msg);
                    #[cfg(feature = "std")]
                    log_to_file(&rewrite_msg);
                }
                Some(local_netbios)
            }

            Some(domain) => {
                #[cfg(feature = "std")]
                {
                    log_string_info(
                        "domain resolution path",
                        "explicit DOMAIN\\user preserved",
                    );
                    log_string_info("preserved explicit domain", domain);
                }
                Some(domain.to_string())
            }
        };

        #[cfg(feature = "std")]
        {
            log_option_info("resolved domain present", resolved.is_some());
            if let Some(ref d) = resolved {
                log_string_info("final NTLM account domain", d);
            }
            log_function_exit(
                "resolve_ntlm_account_domain",
                &format!("Success - domain={:?}", resolved),
            );
        }

        Ok(resolved)
    }

    /// Normalize CredUI input into NTLM identity components for Username::new.
    ///
    /// Pipeline:
    ///   CredUIPromptForCredentialsW
    ///           ↓
    ///   entered_username (may already be NETBIOS\user)
    ///           ↓
    ///   CredUIParseUserNameW
    ///           ↓
    ///   (username, parsed_domain)
    ///           ↓
    ///   resolve_ntlm_account_domain
    ///           ↓
    ///   AuthCredentials { username, password, domain }
    ///
    /// - `DOMAIN\user` → keep DOMAIN (unless DOMAIN is a local alias like localhost)
    /// - `.\user` / bare `user` / missing domain → local NetBIOS computer name
    /// - No custom UPN rewriting: whatever CredUIParseUserNameW returns is normalized
    ///   only through the domain-resolution rules above.
    #[cfg(windows)]
    fn normalize_windows_credentials(
        entered_username: String,
        password: String,
    ) -> AuthResult<AuthCredentials> {
        #[cfg(feature = "std")]
        {
            log_function_entry(
                "normalize_windows_credentials",
                &format!(
                    "entered_username length: {}, password length: {}",
                    entered_username.len(),
                    password.len()
                ),
            );
            log_string_info("normalize entered_username", &entered_username);
            log_memory_info("normalize_windows_credentials - start");
        }

        let (username, parsed_domain) = Self::parse_windows_username(&entered_username)?;

        #[cfg(feature = "std")]
        {
            log_string_info("post-parse username", &username);
            log_option_info("post-parse domain present", parsed_domain.is_some());
            if let Some(ref d) = parsed_domain {
                log_string_info("post-parse domain", d);
            }
        }

        let domain = Self::resolve_ntlm_account_domain(parsed_domain)?;

        let credentials = AuthCredentials {
            username,
            password,
            domain,
        };

        #[cfg(feature = "std")]
        {
            log_string_info("normalized username", &credentials.username);
            log_option_info("normalized domain present", credentials.domain.is_some());
            if let Some(ref d) = credentials.domain {
                log_string_info("normalized domain", d);
                log_string_info(
                    "normalized NTLM identity",
                    &format!("{}\\{}", d, credentials.username),
                );
            }
            log_function_exit(
                "normalize_windows_credentials",
                &format!(
                    "Success - identity={}\\{:?}",
                    credentials
                        .domain
                        .as_deref()
                        .unwrap_or("<none>"),
                    credentials.username
                ),
            );
            log_memory_info("normalize_windows_credentials - end");
        }

        Ok(credentials)
    }

    /// Defensive re-normalization for credentials that may arrive via
    /// auth_get_credentials → auth_set_credentials (or other interop paths)
    /// with a stale local alias domain such as "localhost".
    ///
    /// Does not re-parse the username string; only repairs the domain field
    /// when it is missing or is a known local-machine alias.
    #[cfg(windows)]
    fn normalize_stored_credentials(creds: AuthCredentials) -> AuthResult<AuthCredentials> {
        #[cfg(feature = "std")]
        {
            log_function_entry(
                "normalize_stored_credentials",
                &format!(
                    "username length: {}, domain={:?}",
                    creds.username.len(),
                    creds.domain
                ),
            );
            log_string_info("stored username", &creds.username);
            log_option_info("stored domain present", creds.domain.is_some());
        }

        let needs_domain_repair = match creds.domain.as_deref() {
            None => true,
            Some(domain) => Self::is_local_machine_domain_alias(domain),
        };

        if !needs_domain_repair {
            #[cfg(feature = "std")]
            {
                log_string_info(
                    "stored domain repair",
                    "not required - explicit non-local domain preserved",
                );
                log_function_exit("normalize_stored_credentials", "passthrough");
            }
            return Ok(creds);
        }

        let repaired_domain = Self::resolve_ntlm_account_domain(creds.domain)?;

        #[cfg(feature = "std")]
        {
            log_string_info("stored domain repair", "applied");
            log_option_info("repaired domain present", repaired_domain.is_some());
            if let Some(ref d) = repaired_domain {
                log_string_info("repaired domain", d);
            }
            log_function_exit("normalize_stored_credentials", "repaired");
        }

        Ok(AuthCredentials {
            username: creds.username,
            password: creds.password,
            domain: repaired_domain,
        })
    }

    #[cfg(windows)]
    fn to_wide(s: &str) -> Vec<u16> {
        #[cfg(feature = "std")]
        {
            log_function_entry("to_wide", &format!("input string length: {}", s.len()));
            log_string_info("input string", s);
            log_memory_info("to_wide - start");
        }

        let result: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();

        #[cfg(feature = "std")]
        {
            log_vec_u16_info("result Vec<u16>", &result);
            log_object_size("result Vec", core::mem::size_of::<Vec<u16>>());
            log_function_exit("to_wide", &format!("Success - output length: {}", result.len()));
            log_memory_info("to_wide - end");
        }

        result
    }

    #[cfg(windows)]
    fn from_wide(wide: &[u16]) -> String {
        #[cfg(feature = "std")]
        {
            log_function_entry("from_wide", &format!("input slice length: {}", wide.len()));
            log_vec_u16_info("input slice", wide);
            log_memory_info("from_wide - start");
        }

        let result = String::from_utf16_lossy(wide.split(|c| *c == 0).next().unwrap_or(wide));

        #[cfg(feature = "std")]
        {
            log_string_info("result string", &result);
            log_object_size("result String", core::mem::size_of::<String>());
            log_function_exit("from_wide", &format!("Success - output length: {}", result.len()));
            log_memory_info("from_wide - end");
        }

        result
    }
}

/// Server-side Windows authentication using NTLM
pub struct WindowsAuthServer {
    ntlm: Option<Ntlm>,
    credentials_handle: Option<sspi::AuthIdentityBuffers>,
}

impl WindowsAuthServer {
    pub fn new() -> AuthResult<Self> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthServer::new", "no parameters");
            log_memory_info("WindowsAuthServer::new - creating new instance");
            log_object_size("WindowsAuthServer struct", core::mem::size_of::<WindowsAuthServer>());
        }

        let result = Ok(Self {
            ntlm: Some(Ntlm::new()),
            credentials_handle: None,
        });

        #[cfg(feature = "std")]
        {
            match &result {
            Ok(server) => {
                log_function_exit("WindowsAuthServer::new", "Success");
                log_option_info("ntlm", server.ntlm.is_some());
                log_option_info("credentials_handle", server.credentials_handle.is_some());
            }
            Err(e) => {
                log_function_exit("WindowsAuthServer::new", &format!("Error: {}", e));
            }
        }
        }

        result
    }

    /// Process NTLM negotiate token (Type 1 message) and generate challenge token (Type 2 message)
    pub fn process_negotiate(&mut self, negotiate_token: &[u8]) -> AuthResult<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthServer::process_negotiate", 
                              &format!("negotiate_token length: {}", negotiate_token.len()));
            log_vec_info("negotiate_token", negotiate_token);
            log_object_size("WindowsAuthServer struct", core::mem::size_of::<WindowsAuthServer>());
            log_memory_info("process_negotiate - start");
        }

        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm", true);
            log_object_size("Ntlm struct", core::mem::size_of::<Ntlm>());
        }

        let msgs = vec![
            "[SSPI] API: AcquireCredentialsHandle".to_string(),
            "[SSPI] Package: NTLM".to_string(),
            "[SSPI] Principal: NULL".to_string(),
            "[SSPI] CredentialUse: SECPKG_CRED_INBOUND".to_string(),
        ];
        for msg in &msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Inbound)
            .execute(ntlm);

        log_security_status(&acq_cred_result, "AcquireCredentialsHandle");
        let acq_cred_result = acq_cred_result.map_err(|e| {
            AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e))
        })?;

        // Store the credentials handle for reuse in process_authenticate
        self.credentials_handle = acq_cred_result.credentials_handle;

        #[cfg(feature = "std")]
        {
            log_memory_info("process_negotiate - after acquire_credentials_handle");
            log_option_info("credentials_handle", self.credentials_handle.is_some());
        }

        let init_msgs = vec![
            format!("[SSPI] API: AcceptSecurityContext"),
            "[SSPI] ContextRequirements: CONNECTION | ALLOCATE_MEMORY".to_string(),
            "[SSPI] DataRepresentation: Native".to_string(),
        ];
        for msg in &init_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffer = vec![SecurityBuffer::new(negotiate_token.to_vec(), BufferType::Token)];

        #[cfg(feature = "std")]
        {
            log_object_size("output_buffer", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_object_size("input_buffer", core::mem::size_of::<Vec<SecurityBuffer>>());
            log_memory_info("process_negotiate - before accept_security_context");
        }

        let builder = ntlm
            .accept_security_context()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(
                ServerRequestFlags::CONNECTION | ServerRequestFlags::ALLOCATE_MEMORY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(input_buffer.as_mut_slice())
            .with_output(output_buffer.as_mut_slice());

        let accept_result = {
            let mut accept_generator = ntlm
                .accept_security_context_impl(builder)
                .map_err(|e| {
                    AuthError::AuthFailed(format!(
                        "Failed to create AcceptSecurityContext result: {}",
                        e
                    ))
                })?;

            accept_generator
                .resolve_to_result()
                .map_err(|e| {
                    AuthError::AuthFailed(format!(
                        "Failed to accept security context: {}",
                        e
                    ))
                })?
        };

        let status_msg = format!(
            "[SSPI] AcceptSecurityContext -> {:?}",
            accept_result.status
        );
        eprintln!("{}", status_msg);
        #[cfg(feature = "std")]
        log_to_file(&status_msg);

        #[cfg(feature = "std")]
        {
            log_memory_info("process_negotiate - after accept_security_context");
        }

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

        #[cfg(feature = "std")]
        {
            log_vec_info("token", &token);
            log_object_size("token Vec", core::mem::size_of::<Vec<u8>>());
        }

        let token_msg = format!("[SSPI] Challenge token generated ({} bytes)", token.len());
        eprintln!("{}", token_msg);
        #[cfg(feature = "std")]
        log_to_file(&token_msg);

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthServer::process_negotiate", 
                             &format!("Success - challenge token size: {} bytes", token.len()));
            log_memory_info("process_negotiate - end");
        }

        Ok(token)
    }

    /// Process NTLM authenticate token (Type 3 message) and complete authentication
    pub fn process_authenticate(&mut self, authenticate_token: &[u8]) -> AuthResult<AuthResultInfo> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthServer::process_authenticate", 
                              &format!("authenticate_token length: {}", authenticate_token.len()));
            log_vec_info("authenticate_token", authenticate_token);
            log_object_size("WindowsAuthServer struct", core::mem::size_of::<WindowsAuthServer>());
            log_memory_info("process_authenticate - start");
        }

        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        #[cfg(feature = "std")]
        {
            log_option_info("ntlm", true);
        }

        // Ensure we have credentials handle
        if self.credentials_handle.is_none() {
            let msgs = vec![
                "[SSPI] API: AcquireCredentialsHandle (authenticate)".to_string(),
                "[SSPI] Package: NTLM".to_string(),
                "[SSPI] Principal: NULL".to_string(),
                "[SSPI] CredentialUse: SECPKG_CRED_INBOUND".to_string(),
            ];
            for msg in &msgs {
                eprintln!("{}", msg);
                #[cfg(feature = "std")]
                log_to_file(msg);
            }

            let acq_cred_result = ntlm
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Inbound)
                .execute(ntlm);

            log_security_status(&acq_cred_result, "AcquireCredentialsHandle");
            let acq_cred_result = acq_cred_result.map_err(|e| {
                AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e))
            })?;

            self.credentials_handle = acq_cred_result.credentials_handle;

            #[cfg(feature = "std")]
            {
                log_option_info("credentials_handle", self.credentials_handle.is_some());
            }
        }

        let init_msgs = vec![
            format!("[SSPI] API: AcceptSecurityContext (final)"),
            "[SSPI] ContextRequirements: CONNECTION | ALLOCATE_MEMORY".to_string(),
            "[SSPI] DataRepresentation: Native".to_string(),
        ];
        for msg in &init_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffer = vec![SecurityBuffer::new(authenticate_token.to_vec(), BufferType::Token)];

        #[cfg(feature = "std")]
        {
            log_memory_info("process_authenticate - before accept_security_context");
        }

        let builder = ntlm
            .accept_security_context()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(
                ServerRequestFlags::CONNECTION | ServerRequestFlags::ALLOCATE_MEMORY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(input_buffer.as_mut_slice())
            .with_output(output_buffer.as_mut_slice());

        let accept_result = {
            let mut accept_generator = ntlm
                .accept_security_context_impl(builder)
                .map_err(|e| {
                    AuthError::AuthFailed(format!(
                        "Failed to create AcceptSecurityContext result: {}",
                        e
                    ))
                })?;

            accept_generator
                .resolve_to_result()
                .map_err(|e| {
                    AuthError::AuthFailed(format!(
                        "Failed to accept security context: {}",
                        e
                    ))
                })?
        };

        let status_msg = format!(
            "[SSPI] AcceptSecurityContext -> {:?}",
            accept_result.status
        );
        eprintln!("{}", status_msg);
        #[cfg(feature = "std")]
        log_to_file(&status_msg);

        #[cfg(feature = "std")]
        {
            log_memory_info("process_authenticate - after accept_security_context");
        }

        // Extract authentication information - authentication was successful
        let auth_info = AuthResultInfo {
            username: Some("AuthenticatedUser".to_string()),
            success: true,
        };

        let success_msg = "[SSPI] Authentication completed successfully";
        eprintln!("{}", success_msg);
        #[cfg(feature = "std")]
        log_to_file(success_msg);

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthServer::process_authenticate", "Success");
            log_memory_info("process_authenticate - end");
        }

        Ok(auth_info)
    }

    /// Reset the authentication state for a new client
    pub fn reset(&mut self) {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthServer::reset", "no parameters");
            log_memory_info("reset - start");
        }

        self.ntlm = Some(Ntlm::new());
        self.credentials_handle = None;

        let reset_msg = "[SSPI] Server authentication state reset";
        eprintln!("{}", reset_msg);
        #[cfg(feature = "std")]
        log_to_file(reset_msg);

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthServer::reset", "Success");
            log_memory_info("reset - end");
        }
    }
}

/// Information about the result of authentication
#[derive(Debug, Clone)]
pub struct AuthResultInfo {
    pub username: Option<String>,
    pub success: bool,
}

