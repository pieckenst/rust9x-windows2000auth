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
    Ntlm, SecurityBuffer, Sspi, SspiImpl, Username,
};

#[cfg(windows)]
use windows_sys::Win32::Security::Credentials::{
    CredUIPromptForCredentialsW, CREDUI_FLAGS_DO_NOT_PERSIST,
    CREDUI_INFOW,
};

#[cfg(windows)]
use windows_sys::Win32::Foundation::HWND;
#[cfg(windows)]
use windows_sys::Win32::Foundation::GetLastError;

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

  


#[cfg(windows)]
#[cfg(not(feature = "std"))]
use alloc::ffi::CString;

/// Helper to log SSPI SecurityStatus codes
fn log_security_status<T>(status: &Result<T, sspi::Error>, operation: &str) {
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
}

impl WindowsAuthClient {
    pub fn new() -> AuthResult<Self> {
        Ok(Self {
            credentials: None,
            ntlm: Some(Ntlm::new()),
        })
    }

    pub fn set_credentials(&mut self, creds: AuthCredentials) {
        self.credentials = Some(creds);
    }

    pub fn debug_credentials(&self) {
        match &self.credentials {
            Some(creds) => {
                let msgs = vec![
                    format!("[AUTH] Credentials loaded"),
                    format!("[AUTH] Username : {}", creds.username),
                    format!("[AUTH] Domain   : {:?}", creds.domain),
                    if let Some(domain) = &creds.domain {
                        format!("[AUTH] Identity : {}\\{}", domain, creds.username)
                    } else {
                        format!("[AUTH] Identity : .\\{}", creds.username)
                    },
                    format!("[AUTH] Password length : {}", creds.password.len()),
                ];
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
    }

    /// Generate NTLM negotiate token (Type 1 message)
    pub fn generate_negotiate_token(&mut self, target_name: &str) -> AuthResult<Vec<u8>> {
        let msgs = vec![
            "[SSPI] API: AcquireCredentialsHandle",
            "[SSPI] Package: NTLM",
            "[SSPI] Principal: NULL",
            "[SSPI] CredentialUse: SECPKG_CRED_OUTBOUND",
        ];
        for msg in &msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        let creds = self
            .credentials
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials("No credentials set".to_string()))?;

        let user_msgs = vec![
            format!("[SSPI] Username: {}", creds.username),
            format!("[SSPI] Domain: {:?}", creds.domain.as_deref()),
        ];
        for msg in &user_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let username = Username::new(&creds.username, creds.domain.as_deref()).map_err(|e| {
            AuthError::InvalidCredentials(format!("Invalid username format: {}", e))
        })?;

        let identity = AuthIdentity {
            username,
            password: creds.password.clone().into(),
        };

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(ntlm);

        log_security_status(&acq_cred_result, "AcquireCredentialsHandle");
        let mut acq_cred_result = acq_cred_result.map_err(|e| {
            AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e))
        })?;

        let init_msgs = vec![
            format!("[SSPI] API: InitializeSecurityContext"),
            format!("[SSPI] TargetName: {}", target_name),
            "[SSPI] ContextRequirements: CONNECTION | ALLOCATE_MEMORY",
            "[SSPI] DataRepresentation: Native",
        ];
        for msg in &init_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut builder = sspi::builders::InitializeSecurityContext::<
            Option<sspi::AuthIdentityBuffers>,
            sspi::builders::WithoutCredentialsHandle,
            sspi::builders::WithoutContextRequirements,
            sspi::builders::WithoutTargetDataRepresentation,
            sspi::builders::WithoutOutput,
        >::default()
            .with_credentials_handle(&mut acq_cred_result.credentials_handle)
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

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

        let token_msg = format!("[SSPI] Negotiate token generated ({} bytes)", token.len());
        eprintln!("{}", token_msg);
        #[cfg(feature = "std")]
        log_to_file(&token_msg);
        Ok(token)
    }

    /// Process NTLM challenge and generate authenticate token (Type 3 message)
    pub fn process_challenge(&mut self, challenge: &[u8], target_name: &str) -> AuthResult<Vec<u8>> {
        let msgs = vec![
            "[SSPI] API: AcquireCredentialsHandle (challenge)",
            "[SSPI] Package: NTLM",
            "[SSPI] Principal: NULL",
            "[SSPI] CredentialUse: SECPKG_CRED_OUTBOUND",
        ];
        for msg in &msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        let creds = self
            .credentials
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials("No credentials set".to_string()))?;

        let user_msgs = vec![
            format!("[SSPI] Username: {}", creds.username),
            format!("[SSPI] Domain: {:?}", creds.domain.as_deref()),
        ];
        for msg in &user_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let username = Username::new(&creds.username, creds.domain.as_deref()).map_err(|e| {
            AuthError::InvalidCredentials(format!("Invalid username format: {}", e))
        })?;

        let identity = AuthIdentity {
            username,
            password: creds.password.clone().into(),
        };

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(ntlm);

        log_security_status(&acq_cred_result, "AcquireCredentialsHandle (challenge)");
        let mut acq_cred_result = acq_cred_result.map_err(|e| {
            AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e))
        })?;

        let init_msgs = vec![
            format!("[SSPI] API: InitializeSecurityContext (challenge - Type 3)"),
            format!("[SSPI] TargetName: {}", target_name),
            format!("[SSPI] Challenge size: {} bytes", challenge.len()),
            "[SSPI] ContextRequirements: CONNECTION | ALLOCATE_MEMORY",
            "[SSPI] DataRepresentation: Native",
        ];
        for msg in &init_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffer = vec![SecurityBuffer::new(challenge.to_vec(), BufferType::Token)];

        let mut builder = sspi::builders::InitializeSecurityContext::<
            Option<sspi::AuthIdentityBuffers>,
            sspi::builders::WithoutCredentialsHandle,
            sspi::builders::WithoutContextRequirements,
            sspi::builders::WithoutTargetDataRepresentation,
            sspi::builders::WithoutOutput,
        >::default()
            .with_credentials_handle(&mut acq_cred_result.credentials_handle)
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

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

        let token_msg = format!("[SSPI] Authenticate token generated ({} bytes)", token.len());
        eprintln!("{}", token_msg);
        #[cfg(feature = "std")]
        log_to_file(&token_msg);
        Ok(token)
    }

    /// Prompt for credentials using Windows credential dialog
    #[cfg(windows)]
    pub fn prompt_for_windows_credentials(
        &mut self,
        caption: &str,
        message: &str,
        save: bool,
    ) -> AuthResult<()> {
        let msgs = vec![
            "[CredUI] API: CredUICmdLinePromptForCredentialsW",
            format!("[CredUI] Caption: {}", caption),
            format!("[CredUI] Message: {}", message),
            format!("[CredUI] Save checkbox: {}", save),
            "[CredUI] Flags: GENERIC_CREDENTIALS | DO_NOT_PERSIST",
        ];
        for msg in &msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        let caption_wide = Self::to_wide(caption);
        let message_wide = Self::to_wide(message);

        let mut username_buf = [0u16; 256];
        let mut password_buf = [0u16; 256];

        let mut save_flag: i32 = if save { 1 } else { 0 };

        let cred_info = CREDUI_INFOW {
            cbSize: core::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: 0 as HWND,
            pszMessageText: message_wide.as_ptr(),
            pszCaptionText: caption_wide.as_ptr(),
            hbmBanner: core::ptr::null_mut(),
        };

        let flags = CREDUI_FLAGS_DO_NOT_PERSIST;
        let target_name = Self::to_wide("rust9x");


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

            return Err(AuthError::InvalidCredentials(format!(
                "Credential prompt failed - HRESULT: 0x{:08X}, GetLastError: 0x{:08X}",
                result, last_error
            )));
        }

        // CredUICmdLinePromptForCredentialsW writes NUL-terminated wide strings.
        // Find NUL terminators to determine actual lengths.
        let username_len_pos = username_buf.iter().position(|&c| c == 0).unwrap_or(username_buf.len());
        let password_len_pos = password_buf.iter().position(|&c| c == 0).unwrap_or(password_buf.len());

        // Convert using your from_wide helper
        let username = Self::from_wide(&username_buf[..username_len_pos]);
        let password = Self::from_wide(&password_buf[..password_len_pos]);
        let _domain = String::new(); // Domain is embedded in username (DOMAIN\user or user@domain)

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

        // Parse username in format "DOMAIN\username" or "username@domain"
        let (username, domain) = if let Some(pos) = username.find('\\') {
            let (d, u) = username.split_at(pos);

            (
                u[1..].to_string(),
                Some(d.to_string())
            )
        } else if let Some(pos) = username.find('@') {
            let (u, d) = username.split_at(pos);
            (
                u.to_string(),
                Some(d[1..].to_string())
            )
        } else {
            (
                username,
                None // No domain specified
            )
        };

        let parsed_msgs = vec![
            format!("[CredUI] Parsed username: {}", username),
            format!("[CredUI] Parsed domain: {:?}", domain),
        ];
        for msg in &parsed_msgs {
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(msg);
        }

        self.credentials = Some(AuthCredentials {
            username,
            password,
            domain,
        });

        let success_msg = "[CredUI] Credentials stored successfully";
        eprintln!("{}", success_msg);
        #[cfg(feature = "std")]
        log_to_file(success_msg);
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn prompt_for_windows_credentials(
        &mut self,
        _caption: &str,
        _message: &str,
        _save: bool,
    ) -> AuthResult<()> {
        Err(AuthError::NotInitialized(
            "Credential prompt only available on Windows".to_string(),
        ))
    }

    #[cfg(windows)]
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    #[cfg(windows)]
    fn from_wide(wide: &[u16]) -> String {
        String::from_utf16_lossy(wide.split(|c| *c == 0).next().unwrap_or(wide))
    }
}

