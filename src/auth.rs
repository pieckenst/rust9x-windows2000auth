#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation,
    Ntlm, SecurityBuffer, Sspi, SspiImpl, Username,
};

#[cfg(windows)]
use windows_sys::Win32::Security::Credentials::{
    CredUICmdLinePromptForCredentialsW, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
    CREDUI_INFOW,
};

#[cfg(windows)]
use windows_sys::Win32::Foundation::HWND;

#[cfg(windows)]
#[cfg(not(feature = "std"))]
use alloc::ffi::CString;

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

    /// Generate NTLM negotiate token (Type 1 message)
    pub fn generate_negotiate_token(&mut self, target_name: &str) -> AuthResult<Vec<u8>> {
        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        let creds = self
            .credentials
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials("No credentials set".to_string()))?;

        let username = Username::new(&creds.username, creds.domain.as_deref()).map_err(|e| {
            AuthError::InvalidCredentials(format!("Invalid username format: {}", e))
        })?;

        let identity = AuthIdentity {
            username,
            password: creds.password.clone().into(),
        };

        let mut acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(ntlm)
            .map_err(|e| AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e)))?;

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
            .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(target_name)
            .with_input(input_buffer.as_mut_slice())
            .with_output(output_buffer.as_mut_slice());

        ntlm.initialize_security_context_impl(&mut builder)
            .map_err(|e| AuthError::AuthFailed(format!("Failed to initialize security context: {}", e)))?;

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

        Ok(token)
    }

    /// Process NTLM challenge and generate authenticate token (Type 3 message)
    pub fn process_challenge(&mut self, challenge: &[u8], target_name: &str) -> AuthResult<Vec<u8>> {
        let ntlm = self
            .ntlm
            .as_mut()
            .ok_or_else(|| AuthError::NotInitialized("NTLM not initialized".to_string()))?;

        let creds = self
            .credentials
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials("No credentials set".to_string()))?;

        let username = Username::new(&creds.username, creds.domain.as_deref()).map_err(|e| {
            AuthError::InvalidCredentials(format!("Invalid username format: {}", e))
        })?;

        let identity = AuthIdentity {
            username,
            password: creds.password.clone().into(),
        };

        let mut acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(ntlm)
            .map_err(|e| AuthError::AuthFailed(format!("Failed to acquire credentials: {}", e)))?;

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
            .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(target_name)
            .with_input(input_buffer.as_mut_slice())
            .with_output(output_buffer.as_mut_slice());

        ntlm.initialize_security_context_impl(&mut builder)
            .map_err(|e| AuthError::AuthFailed(format!("Failed to process challenge: {}", e)))?;

        let token = output_buffer
            .into_iter()
            .next()
            .map(|buf| buf.buffer)
            .unwrap_or_default();

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
        use core::ptr;

        let caption_wide = Self::to_wide(caption);
        let message_wide = Self::to_wide(message);

        let mut username_buf = [0u16; 256];
        let mut password_buf = [0u16; 256];
        let mut domain_buf = [0u16; 16];

        let mut username_len = username_buf.len() as u32;
        let mut password_len = password_buf.len() as u32;
        let mut domain_len = domain_buf.len() as u32;

        let mut save_flag = if save { 1 } else { 0 };

        let cred_info = CREDUI_INFOW {
            cbSize: core::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: 0 as HWND,
            pszMessageText: message_wide.as_ptr(),
            pszCaptionText: caption_wide.as_ptr(),
            hbmBanner: core::ptr::null_mut(),
        };

        let flags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST;

        let result = unsafe {
            CredUICmdLinePromptForCredentialsW(
                ptr::null(),
                ptr::null_mut(),
                &cred_info as *const CREDUI_INFOW as u32,
                username_buf.as_mut_ptr(),
                username_len,
                password_buf.as_mut_ptr(),
                password_len,
                &mut save_flag,
                flags,
            )
        };

        if result != 0 {
            return Err(AuthError::InvalidCredentials(
                "Credential prompt cancelled or failed".to_string(),
            ));
        }

        let username = Self::from_wide(&username_buf[..username_len as usize]);
        let password = Self::from_wide(&password_buf[..password_len as usize]);
        let domain = Self::from_wide(&domain_buf[..domain_len as usize]);

        // Parse username in format "DOMAIN\username" or "username@domain"
        let (username, domain) = if let Some(pos) = username.find('\\') {
            let (d, u) = username.split_at(pos);
            (u.to_string(), Some(d.to_string()))
        } else if let Some(pos) = username.find('@') {
            let (u, d) = username.split_at(pos);
            (u.to_string(), Some(d[1..].to_string()))
        } else {
            (username, if domain.is_empty() { None } else { Some(domain) })
        };

        self.credentials = Some(AuthCredentials {
            username,
            password,
            domain,
        });

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

