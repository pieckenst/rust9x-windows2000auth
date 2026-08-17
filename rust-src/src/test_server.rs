#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use std::fs::OpenOptions;

use crate::auth::{WindowsAuthServer, AuthResult, AuthError};
use crate::auth::AuthResultInfo;

#[cfg(feature = "std")]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

#[cfg(feature = "std")]
fn read_http_request(stream: &mut TcpStream) -> AuthResult<HttpRequest> {
    let mut buffer = [0u8; 4096];
    let mut total_read = 0;
    
    // Read until we find \r\n\r\n (end of headers)
    loop {
        let bytes_read = stream.read(&mut buffer[total_read..]).map_err(|e| {
            AuthError::NetworkError(format!("Failed to read HTTP request: {}", e))
        })?;
        
        if bytes_read == 0 {
            return Err(AuthError::NetworkError("Connection closed during HTTP read".to_string()));
        }
        
        total_read += bytes_read;
        
        // Check for end of headers
        if buffer[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        
        if total_read >= buffer.len() {
            return Err(AuthError::NetworkError("HTTP request too large".to_string()));
        }
    }
    
    let request_str = String::from_utf8_lossy(&buffer[..total_read]);
    let lines: Vec<&str> = request_str.lines().collect();
    
    if lines.is_empty() {
        return Err(AuthError::NetworkError("Empty HTTP request".to_string()));
    }
    
    // Parse request line: "GET /path HTTP/1.1"
    let request_line: Vec<&str> = lines[0].split_whitespace().collect();
    if request_line.len() < 2 {
        return Err(AuthError::NetworkError("Invalid HTTP request line".to_string()));
    }
    
    let method = request_line[0].to_string();
    let path = request_line[1].to_string();
    
    // Parse headers
    let mut headers = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break; // End of headers
        }
        
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    
    Ok(HttpRequest {
        method,
        path,
        headers,
    })
}

#[cfg(feature = "std")]
fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(data)
}

#[cfg(feature = "std")]
fn base64_decode(data: &str) -> AuthResult<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.decode(data).map_err(|e| {
        AuthError::AuthFailed(format!("Base64 decode failed: {}", e))
    })
}

#[cfg(feature = "std")]
fn log_to_file(message: &str) {
    let log_path = "E:\\code\\rust9x-windows2000auth\\rust-src\\test_server_log.txt";
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

/// Test Windows Authentication Server
/// 
/// This server implements NTLM authentication to test client-side Windows authentication.
/// It follows the NTLM protocol:
/// 1. Client sends negotiate message (Type 1)
/// 2. Server responds with challenge (Type 2)  
/// 3. Client responds with authenticate message (Type 3)
/// 4. Server validates and completes authentication
pub struct WindowsAuthTestServer {
    server: WindowsAuthServer,
    address: String,
    port: u16,
}

impl WindowsAuthTestServer {
    /// Create a new test authentication server
    pub fn new(address: &str, port: u16) -> AuthResult<Self> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthTestServer::new", 
                              &format!("address: '{}', port: {}", address, port));
        }

        let server = WindowsAuthServer::new()?;
        
        let result = Ok(Self {
            server,
            address: address.to_string(),
            port,
        });

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthTestServer::new", "Success");
        }

        result
    }

    /// Start the test server and handle incoming connections
    #[cfg(feature = "std")]
    pub fn start(&mut self) -> AuthResult<()> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthTestServer::start", "no parameters");
        }

        let bind_address = format!("{}:{}", self.address, self.port);
        let listener = TcpListener::bind(&bind_address).map_err(|e| {
            AuthError::NetworkError(format!("Failed to bind to {}: {}", bind_address, e))
        })?;

        let start_msg = format!("[SERVER] Test Windows Auth server listening on {}", bind_address);
        eprintln!("{}", start_msg);
        log_to_file(&start_msg);

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthTestServer::start", "Server started");
        }

        for stream in listener.incoming() {
            match stream {
                Ok(client_stream) => {
                    if let Err(e) = self.handle_client(client_stream) {
                        let error_msg = format!("[SERVER] Error handling client: {:?}", e);
                        eprintln!("{}", error_msg);
                        log_to_file(&error_msg);
                    }
                }
                Err(e) => {
                    let error_msg = format!("[SERVER] Error accepting connection: {:?}", e);
                    eprintln!("{}", error_msg);
                    log_to_file(&error_msg);
                }
            }
        }

        Ok(())
    }

    /// Handle a single client connection
    #[cfg(feature = "std")]
    fn handle_client(&mut self, mut stream: TcpStream) -> AuthResult<()> {
        #[cfg(feature = "std")]
        {
            log_function_entry("WindowsAuthTestServer::handle_client", "stream");
        }

        let client_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or("unknown".to_string());
        let connect_msg = format!("[SERVER] Client connected from {}", client_addr);
        eprintln!("{}", connect_msg);
        log_to_file(&connect_msg);

        // Reset server state for new client
        self.server.reset();

        // 1. Read HTTP request
        let request = read_http_request(&mut stream)?;
        let request_msg = format!("[SERVER] Received HTTP request: {} {}", request.method, request.path);
        eprintln!("{}", request_msg);
        log_to_file(&request_msg);

        // 2. Extract Authorization header
        let auth = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
            .ok_or_else(|| AuthError::AuthFailed(
                "Missing Authorization header".to_string()
            ))?;

        let value = auth.1.trim();

        if !value.starts_with("NTLM ") {
            return Err(AuthError::AuthFailed(
                "Authorization header is not NTLM".to_string()
            ));
        }

        let b64 = value[5..].trim();
        let auth_msg = format!("[SERVER] Found NTLM Authorization header");
        eprintln!("{}", auth_msg);
        log_to_file(&auth_msg);

        // 3. Base64 decode Type 1
        let negotiate_token = base64_decode(b64)?;
        let decode_msg = format!("[SERVER] Decoded Type 1 token ({} bytes)", negotiate_token.len());
        eprintln!("{}", decode_msg);
        log_to_file(&decode_msg);

        // 4. Feed ONLY the NTLM token to SSPI
        let challenge_token = self.server.process_negotiate(&negotiate_token)?;
        let challenge_msg = format!("[SERVER] Generated Type 2 challenge ({} bytes)", challenge_token.len());
        eprintln!("{}", challenge_msg);
        log_to_file(&challenge_msg);

        // 5. Send HTTP 401 with WWW-Authenticate
        let challenge_b64 = base64_encode(&challenge_token);

        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\n\
             WWW-Authenticate: NTLM {}\r\n\
             Content-Length: 0\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            challenge_b64
        );

        stream.write_all(response.as_bytes()).map_err(|e| {
            AuthError::NetworkError(format!("Failed to send 401 response: {}", e))
        })?;

        let response_msg = format!("[SERVER] Sent 401 with NTLM challenge");
        eprintln!("{}", response_msg);
        log_to_file(&response_msg);

        // 6. Read second HTTP request
        let request = read_http_request(&mut stream)?;
        let request2_msg = format!("[SERVER] Received second HTTP request: {} {}", request.method, request.path);
        eprintln!("{}", request2_msg);
        log_to_file(&request2_msg);

        // 7. Extract Type 3
        let auth = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
            .ok_or_else(|| AuthError::AuthFailed(
                "Missing NTLM authenticate header".to_string()
            ))?;

        let value = auth.1.trim();

        if !value.starts_with("NTLM ") {
            return Err(AuthError::AuthFailed(
                "Second Authorization header is not NTLM".to_string()
            ));
        }

        let authenticate_token = base64_decode(value[5..].trim())?;
        let auth3_msg = format!("[SERVER] Decoded Type 3 token ({} bytes)", authenticate_token.len());
        eprintln!("{}", auth3_msg);
        log_to_file(&auth3_msg);

        // 8. Feed ONLY Type 3 to SSPI
        let result = self.server.process_authenticate(&authenticate_token)?;
        
        let result_msg = format!("[SERVER] Authentication result: success={}, username={:?}", 
                                 result.success, result.username);
        eprintln!("{}", result_msg);
        log_to_file(&result_msg);

        // 9. Return normal HTTP success
        let body = b"AUTH_SUCCESS";

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );

        stream.write_all(response.as_bytes()).map_err(|e| {
            AuthError::NetworkError(format!("Failed to send 200 response: {}", e))
        })?;
        stream.write_all(body).map_err(|e| {
            AuthError::NetworkError(format!("Failed to send body: {}", e))
        })?;

        let final_msg = format!("[SERVER] Authentication completed for {}", client_addr);
        eprintln!("{}", final_msg);
        log_to_file(&final_msg);

        #[cfg(feature = "std")]
        {
            log_function_exit("WindowsAuthTestServer::handle_client", "Success");
        }

        Ok(())
    }

    /// Get the server address
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Get the server port
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(not(feature = "std"))]
impl WindowsAuthTestServer {
    pub fn new(_address: &str, _port: u16) -> AuthResult<Self> {
        Err(AuthError::NotInitialized("Test server requires std feature".to_string()))
    }

    pub fn start(&mut self) -> AuthResult<()> {
        Err(AuthError::NotInitialized("Test server requires std feature".to_string()))
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_server_creation() {
        let server = WindowsAuthTestServer::new("127.0.0.1", 0).unwrap();
        assert_eq!(server.address(), "127.0.0.1");
        assert_eq!(server.port(), 0);
    }

    #[test]
    fn test_server_reset() {
        let mut server = WindowsAuthTestServer::new("127.0.0.1", 0).unwrap();
        server.server.reset();
        // If we get here without panic, reset works
    }
}