#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::format;

#[cfg(feature = "std")]
use std::string::{String, ToString};
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::format;
#[cfg(feature = "std")]
use std::fs::OpenOptions;
#[cfg(feature = "std")]
use std::io::Write;

#[cfg(feature = "network")]
use std::net::TcpStream;
#[cfg(feature = "network")]
use std::io::{Read, BufReader, BufRead};

#[cfg(feature = "tls")]
use native_tls::TlsConnector;

use crate::auth::{AuthError, AuthResult, WindowsAuthClient};

#[cfg(feature = "std")]
fn log_to_file(message: &str) {
    let log_path = "E:\\code\\rust9x-windows2000auth\\rust-src\\http_log.txt";
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

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// HTTP response with comprehensive parsing
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: HttpHeaders,
    pub body: Vec<u8>,
    pub version: HttpVersion,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
    Http2,
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct HttpHeaders {
    headers: Vec<(String, String)>,
}

impl HttpHeaders {
    pub fn new() -> Self {
        Self { headers: Vec::new() }
    }

    pub fn add(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_lowercase(), value.to_string()));
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        let name_lower = name.to_lowercase();
        self.headers.iter()
            .find(|(k, _)| k == &name_lower)
            .map(|(_, v)| v)
    }

    pub fn get_all(&self, name: &str) -> Vec<&String> {
        let name_lower = name.to_lowercase();
        self.headers.iter()
            .filter(|(k, _)| k == &name_lower)
            .map(|(_, v)| v)
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding")
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn should_close(&self) -> bool {
        // Check Connection header for explicit close
        if let Some(conn) = self.get("connection") {
            if conn.to_lowercase().contains("close") {
                return true;
            }
        }
        
        // HTTP/1.0 defaults to close unless keep-alive
        // HTTP/1.1 defaults to keep-alive unless close
        false
    }

    pub fn keep_alive(&self) -> bool {
        if let Some(conn) = self.get("connection") {
            return conn.to_lowercase().contains("keep-alive");
        }
        false
    }
}

/// HTTP client with Windows Authentication support and proper persistent connections
pub struct HttpClient {
    #[cfg(feature = "tls")]
    tls_connector: Option<TlsConnector>,
    #[cfg(feature = "network")]
    connection: Option<HttpConnection>,
}

#[cfg(feature = "network")]
struct HttpConnection {
    stream: Box<dyn ReadWrite>,
    url: ParsedUrl,
    last_used: std::time::Instant,
    is_active: bool,
}

#[cfg(feature = "network")]
impl HttpConnection {
    fn new(stream: Box<dyn ReadWrite>, url: ParsedUrl) -> Self {
        Self {
            stream,
            url,
            last_used: std::time::Instant::now(),
            is_active: true,
        }
    }

    fn is_expired(&self) -> bool {
        // Connections expire after 2 minutes of inactivity
        self.last_used.elapsed() > std::time::Duration::from_secs(120)
    }

    fn close(&mut self) {
        if self.is_active {
            // For generic ReadWrite trait, we can't call shutdown directly
            // The connection will be closed when dropped
            self.is_active = false;
        }
    }
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "tls")]
            tls_connector: None,
            #[cfg(feature = "network")]
            connection: None,
        }
    }

    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, config: crate::tls::TlsConfig) -> Self {
        // Validate configuration first
        if let Err(e) = config.validate() {
            let msg = format!("[HTTP] TLS configuration validation failed: {}", e);
            eprintln!("{}", msg);
            #[cfg(feature = "std")]
            log_to_file(&msg);
            return self;
        }
        
        match config.build_connector() {
            Ok(connector) => {
                self.tls_connector = Some(connector);
                let msg = "[HTTP] TLS connector built successfully";
                eprintln!("{}", msg);
                #[cfg(feature = "std")]
                log_to_file(msg);
            }
            Err(e) => {
                let msg = format!("[HTTP] Failed to build TLS connector: {}", e);
                eprintln!("{}", msg);
                #[cfg(feature = "std")]
                log_to_file(&msg);
            }
        }
        self
    }

    /// Perform HTTP request with Negotiate/NTLM authentication and proper persistent connection handling
    pub fn http_request(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> AuthResult<Vec<u8>> {
        let parsed_url = self.parse_url(url)?;
        
        let start_msg = format!("[HTTP] Starting {} request to {}", method, parsed_url.address);
        eprintln!("{}", start_msg);
        #[cfg(feature = "std")]
        log_to_file(&start_msg);
        
        #[cfg(feature = "network")]
        {
            self.perform_request_with_ntlm(&parsed_url, method, body)
        }

        #[cfg(not(feature = "network"))]
        {
            Err(AuthError::NetworkError("Networking not enabled".to_string()))
        }
    }

    #[cfg(feature = "network")]
    fn perform_request_with_ntlm(
        &mut self,
        url: &ParsedUrl,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> AuthResult<Vec<u8>> {
        // Generate NTLM negotiate token first to avoid borrow conflicts
        let target_name = format!("HTTP/{}", url.host);
        let target_msg = format!("[HTTP] Target name for authentication: {}", target_name);
        eprintln!("{}", target_msg);
        #[cfg(feature = "std")]
        log_to_file(&target_msg);
        
        let negotiate_token = {
            let auth_client = self.get_auth_client()?;
            auth_client.generate_negotiate_token(&target_name)?
        };
        let negotiate_b64 = self.base64_encode(&negotiate_token);

        let negotiate_msg = format!("[HTTP] Negotiate token: {} bytes", negotiate_token.len());
        eprintln!("{}", negotiate_msg);
        #[cfg(feature = "std")]
        log_to_file(&negotiate_msg);

        // Try to reuse existing connection if available and compatible
        let mut connection = if let Some(mut conn) = self.connection.take() {
            if !conn.is_expired() && conn.url.host == url.host && conn.url.port == url.port {
                conn
            } else {
                conn.close();
                self.establish_connection(url)?
            }
        } else {
            self.establish_connection(url)?
        };

        // Send initial request with Negotiate header (Negotiate can use NTLM under the hood)
        let request = self.build_request(url, method, &body, &format!("Negotiate {}", negotiate_b64), true);
        
        let send_msg = format!("[HTTP] Sending initial request ({} bytes)", request.len());
        eprintln!("{}", send_msg);
        #[cfg(feature = "std")]
        log_to_file(&send_msg);
        
        connection.stream.write_all(request.as_bytes())
            .map_err(|e| AuthError::NetworkError(format!("Failed to send request: {}", e)))?;
        connection.last_used = std::time::Instant::now();

        // Read and parse initial response
        let initial_response = self.read_response(&mut connection.stream)?;
        
        let status_msg = format!("[HTTP] Initial response: {} {}", initial_response.status_code, initial_response.status_text);
        eprintln!("{}", status_msg);
        #[cfg(feature = "std")]
        log_to_file(&status_msg);

        // Check if we need NTLM authentication
        let final_response = if initial_response.status_code == 401 && 
                             initial_response.headers.contains("www-authenticate") {
            
            let challenge_msg = "[HTTP] Received 401 - extracting NTLM challenge";
            eprintln!("{}", challenge_msg);
            #[cfg(feature = "std")]
            log_to_file(challenge_msg);
            
            // CRITICAL FIX: Check if server closed the connection after 401
            // If Connection: close is present or HTTP/1.0 without keep-alive, we must reconnect
            let needs_reconnect = initial_response.headers.should_close() || 
                                  (initial_response.version == HttpVersion::Http1_0 && !initial_response.headers.keep_alive());
            
            if needs_reconnect {
                let reconnect_msg = "[HTTP] Server closed connection after 401 - establishing new connection for Type 3";
                eprintln!("{}", reconnect_msg);
                #[cfg(feature = "std")]
                log_to_file(reconnect_msg);
                
                connection.close();
                connection = self.establish_connection(url)?;
            } else {
                let keepalive_msg = "[HTTP] Server kept connection alive - reusing for Type 3";
                eprintln!("{}", keepalive_msg);
                #[cfg(feature = "std")]
                log_to_file(keepalive_msg);
            }
            
            // Extract Negotiate/NTLM challenge from WWW-Authenticate header
            if let Some(challenge) = self.extract_auth_challenge(&initial_response) {
                let challenge_size_msg = format!("[HTTP] Challenge size: {} bytes", challenge.len());
                eprintln!("{}", challenge_size_msg);
                #[cfg(feature = "std")]
                log_to_file(&challenge_size_msg);
                
                // Process challenge and get authenticate token
                // If challenge is empty, regenerate negotiate token (server sent initial challenge)
                // If challenge has data, process it as normal NTLM challenge
                let auth_token = if challenge.is_empty() {
                    eprintln!("[HTTP] Empty challenge - regenerating negotiate token");
                    let auth_client = self.get_auth_client()?;
                    auth_client.generate_negotiate_token(&target_name)?
                } else {
                    let auth_client = self.get_auth_client()?;
                    auth_client.process_challenge(&challenge, &target_name)?
                };
                let auth_b64 = self.base64_encode(&auth_token);
                
                let auth_msg = format!("[HTTP] Authenticate token: {} bytes", auth_token.len());
                eprintln!("{}", auth_msg);
                #[cfg(feature = "std")]
                log_to_file(&auth_msg);
                
                // Send authenticated request with Negotiate header
                let auth_request = self.build_request(url, method, &body, &format!("Negotiate {}", auth_b64), false);
                
                let auth_send_msg = format!("[HTTP] Sending auth request ({} bytes)", auth_request.len());
                eprintln!("{}", auth_send_msg);
                #[cfg(feature = "std")]
                log_to_file(&auth_send_msg);
                
                connection.stream.write_all(auth_request.as_bytes())
                    .map_err(|e| AuthError::NetworkError(format!("Failed to send auth request: {}", e)))?;
                connection.last_used = std::time::Instant::now();
                
                // Read final response
                let final_response = self.read_response(&mut connection.stream)?;
                
                let final_status_msg = format!("[HTTP] Final response: {} {}", final_response.status_code, final_response.status_text);
                eprintln!("{}", final_status_msg);
                #[cfg(feature = "std")]
                log_to_file(&final_status_msg);
                
                final_response
            } else {
                return Err(AuthError::AuthFailed("Could not extract Negotiate/NTLM challenge from 401 response".to_string()));
            }
        } else {
            initial_response
        };

        // Handle connection persistence
        if final_response.headers.should_close() {
            connection.close();
        } else if final_response.headers.keep_alive() {
            // Keep connection alive for reuse
            self.connection = Some(connection);
        } else {
            // Close connection by default
            connection.close();
        }

        // Check for error status codes
        if final_response.status_code >= 400 {
            let error_msg = format!("HTTP request failed with status: {} {}", 
                                   final_response.status_code, final_response.status_text);
            return Err(AuthError::NetworkError(error_msg));
        }

        let final_msg = format!("[HTTP] Request completed successfully, body size: {} bytes", final_response.body.len());
        eprintln!("{}", final_msg);
        #[cfg(feature = "std")]
        log_to_file(&final_msg);
        
        Ok(final_response.body)
    }

    #[cfg(feature = "network")]
    fn establish_connection(&self, url: &ParsedUrl) -> AuthResult<HttpConnection> {
        let stream = TcpStream::connect(&url.address)
            .map_err(|e| AuthError::NetworkError(format!("Failed to connect: {}", e)))?;

        let connect_msg = format!("[HTTP] Connected to {}", url.address);
        eprintln!("{}", connect_msg);
        #[cfg(feature = "std")]
        log_to_file(&connect_msg);

        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| AuthError::NetworkError(format!("Failed to set timeout: {}", e)))?;

        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| AuthError::NetworkError(format!("Failed to set write timeout: {}", e)))?;

        #[cfg(feature = "tls")]
        let stream = if url.is_https {
            let tls_connector = self.tls_connector.as_ref()
                .ok_or_else(|| AuthError::TlsError("TLS not configured".to_string()))?;

            let tls_msg = format!("[HTTP] Starting TLS handshake with {}", url.host);
            eprintln!("{}", tls_msg);
            #[cfg(feature = "std")]
            log_to_file(&tls_msg);

            match tls_connector.connect(&url.host, stream) {
                Ok(tls_stream) => {
                    let tls_success_msg = format!("[HTTP] TLS handshake successful with {}", url.host);
                    eprintln!("{}", tls_success_msg);
                    #[cfg(feature = "std")]
                    log_to_file(&tls_success_msg);

                    Box::new(tls_stream) as Box<dyn ReadWrite>
                }
                Err(e) => {
                    let error_msg = format!("[HTTP] TLS handshake failed with {}: {}. This may indicate the system doesn't support the required TLS version. For Windows 2000, consider using HTTP instead of HTTPS.", url.host, e);
                    eprintln!("{}", error_msg);
                    #[cfg(feature = "std")]
                    log_to_file(&error_msg);
                    
                    return Err(AuthError::TlsError(format!("TLS handshake failed: {}. For Windows 2000 compatibility, use HTTP instead of HTTPS or ensure the system has the required TLS support.", e)));
                }
            }
        } else {
            Box::new(stream) as Box<dyn ReadWrite>
        };

        #[cfg(not(feature = "tls"))]
        let stream = Box::new(stream) as Box<dyn ReadWrite>;

        Ok(HttpConnection::new(stream, url.clone()))
    }

    #[cfg(feature = "network")]
    fn read_response(&self, stream: &mut dyn ReadWrite) -> AuthResult<HttpResponse> {
        let mut reader = BufReader::new(stream);
        
        // Read raw response bytes for logging before parsing
        let mut raw_response = Vec::new();
        let mut buffer = [0u8; 4096]; // Use larger buffer for efficiency
        let mut headers_found = false;
        let mut content_length: Option<usize> = None;
        let mut is_chunked = false;
        let mut headers_end_pos: Option<usize> = None;
        
        // First, read until we have the complete headers
        while !headers_found {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    if raw_response.is_empty() {
                        return Err(AuthError::NetworkError("Connection closed before receiving response".to_string()));
                    }
                    break;
                }
                Ok(n) => {
                    raw_response.extend_from_slice(&buffer[..n]);
                    
                    // Check if we've found the end of headers
                    if let Some(headers_end) = self.find_headers_end(&raw_response) {
                        headers_found = true;
                        headers_end_pos = Some(headers_end);
                        
                        // Parse headers from raw response to determine body length
                        let headers_str = String::from_utf8_lossy(&raw_response[..headers_end]);
                        for line in headers_str.lines() {
                            let line_lower = line.to_lowercase();
                            if line_lower.starts_with("content-length:") {
                                if let Some(len_str) = line.strip_prefix("content-length:")
                                    .or_else(|| line.strip_prefix("Content-Length:"))
                                {
                                    content_length = len_str.trim().parse::<usize>().ok();
                                }
                            } else if line_lower.starts_with("transfer-encoding:") {
                                is_chunked = line_lower.contains("chunked");
                            }
                        }
                    }
                }
                Err(e) => return Err(AuthError::NetworkError(format!("Failed to read response headers: {}", e))),
            }
        }
        
        let headers_end = headers_end_pos.unwrap();
        
        // Now read the body based on the transfer encoding
        if let Some(cl) = content_length {
            // Fixed-length body: read exactly content_length bytes
            let current_body_len = raw_response.len() - headers_end;
            let remaining = cl.saturating_sub(current_body_len);
            
            if remaining > 0 {
                let mut body_buffer = vec![0u8; remaining];
                reader.read_exact(&mut body_buffer)
                    .map_err(|e| AuthError::NetworkError(format!("Failed to read response body: {}", e)))?;
                raw_response.extend_from_slice(&body_buffer);
            }
        } else if is_chunked {
            // Chunked encoding: read until we get the terminating chunk
            loop {
                // Check if we already have the terminating chunk
                if raw_response.ends_with(b"0\r\n\r\n") {
                    break;
                }
                
                match reader.read(&mut buffer) {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        raw_response.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) => return Err(AuthError::NetworkError(format!("Failed to read chunked body: {}", e))),
                }
            }
        } else {
            // Connection-close: read until connection closes or we get a reasonable amount of data
            // Read a bit more data, but don't block forever
            let mut total_body_read = raw_response.len() - headers_end;
            let max_body_size = 1024 * 1024; // 1MB max body size for connection-close
            
            while total_body_read < max_body_size {
                match reader.read(&mut buffer) {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        raw_response.extend_from_slice(&buffer[..n]);
                        total_body_read += n;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Non-blocking mode - we have what we can get
                        break;
                    }
                    Err(e) => return Err(AuthError::NetworkError(format!("Failed to read response body: {}", e))),
                }
            }
        }
        
        // Log the raw response
        let raw_hex = hex::encode(&raw_response);
        let raw_text = String::from_utf8_lossy(&raw_response);
        
        let log_msg = format!(
            "----- RAW HTTP RESPONSE -----\n\
             Size: {} bytes\n\
             Hex (first 500 bytes): {}\n\
             Text:\n{}\n\
             -----------------------------",
            raw_response.len(),
            &raw_hex.chars().take(1000).collect::<String>(),
            raw_text
        );
        
        eprintln!("{}", log_msg);
        #[cfg(feature = "std")]
        log_to_file(&log_msg);
        
        // Parse the response from the raw bytes
        let headers_section = String::from_utf8_lossy(&raw_response[..headers_end]);
        let mut lines = headers_section.lines();
        
        // Parse status line
        let status_line = lines.next()
            .ok_or_else(|| AuthError::NetworkError("Missing status line".to_string()))?;
        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        
        if status_parts.len() < 2 {
            return Err(AuthError::NetworkError(format!("Invalid status line: {}", status_line)));
        }
        
        let version = match status_parts.get(0) {
            Some(&"HTTP/1.0") => HttpVersion::Http1_0,
            Some(&"HTTP/1.1") => HttpVersion::Http1_1,
            Some(&"HTTP/2") => HttpVersion::Http2,
            Some(v) => HttpVersion::Unknown(v.to_string()),
            None => return Err(AuthError::NetworkError("Missing HTTP version".to_string())),
        };
        
        let status_code = status_parts.get(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| AuthError::NetworkError("Invalid status code".to_string()))?;
        
        let status_text = status_parts[2..].join(" ");
        
        // Parse headers
        let mut headers = HttpHeaders::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            
            if let Some(colon_pos) = line.find(':') {
                let name = &line[..colon_pos];
                let value = line[colon_pos + 1..].trim();
                headers.add(name, value);
            }
        }
        
        // The raw_response should already contain the complete body based on our reading logic
        // We just need to extract it properly based on the transfer encoding
        let body = if headers.is_chunked() {
            // For chunked, parse the chunked encoding from the raw body data
            let body_data = &raw_response[headers_end..];
            self.parse_chunked_body_from_bytes(body_data)?
        } else if let Some(content_length) = headers.content_length() {
            // For fixed-length, the raw_response should already contain exactly content_length bytes after headers
            // But validate this to be safe
            let expected_body_len = content_length;
            let actual_body_len = raw_response.len() - headers_end;
            
            if actual_body_len < expected_body_len {
                return Err(AuthError::NetworkError(format!(
                    "Incomplete body: expected {} bytes but only have {} bytes", 
                    expected_body_len, actual_body_len
                )));
            }
            
            raw_response[headers_end..headers_end + expected_body_len].to_vec()
        } else {
            // For connection-close (no content-length, not chunked), everything after headers is the body
            raw_response[headers_end..].to_vec()
        };
        
        Ok(HttpResponse {
            status_code,
            status_text,
            headers,
            body,
            version,
        })
    }

    #[cfg(feature = "network")]
    fn read_line(&self, reader: &mut BufReader<&mut dyn ReadWrite>) -> AuthResult<String> {
        let mut line = String::new();
        reader.read_line(&mut line)
            .map_err(|e| AuthError::NetworkError(format!("Failed to read line: {}", e)))?;
        
        // Remove CRLF
        if line.ends_with("\r\n") {
            line.pop();
            line.pop();
        } else if line.ends_with('\n') {
            line.pop();
        }
        
        Ok(line)
    }

    #[cfg(feature = "network")]
    fn parse_chunked_body_from_bytes(&self, data: &[u8]) -> AuthResult<Vec<u8>> {
        let mut body = Vec::new();
        let mut pos = 0;
        
        while pos < data.len() {
            // Find the end of the chunk size line (CRLF)
            let line_end = data[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| AuthError::NetworkError("Invalid chunked encoding: missing CRLF after chunk size".to_string()))?;
            
            let chunk_size_line = String::from_utf8_lossy(&data[pos..pos + line_end]);
            let chunk_size = usize::from_str_radix(chunk_size_line.trim(), 16)
                .map_err(|e| AuthError::NetworkError(format!("Invalid chunk size: {}", e)))?;
            
            pos += line_end + 1; // Skip the newline
            
            if chunk_size == 0 {
                // Final chunk - we're done
                break;
            }
            
            // Read chunk data
            if pos + chunk_size > data.len() {
                return Err(AuthError::NetworkError("Invalid chunked encoding: chunk data incomplete".to_string()));
            }
            
            body.extend_from_slice(&data[pos..pos + chunk_size]);
            pos += chunk_size;
            
            // Skip CRLF after chunk data
            if pos + 2 > data.len() {
                return Err(AuthError::NetworkError("Invalid chunked encoding: missing CRLF after chunk data".to_string()));
            }
            if &data[pos..pos + 2] == b"\r\n" {
                pos += 2;
            } else if data[pos] == b'\n' {
                pos += 1; // Handle just LF
            } else {
                return Err(AuthError::NetworkError("Invalid chunked encoding: missing CRLF after chunk data".to_string()));
            }
        }
        
        Ok(body)
    }

    #[cfg(feature = "network")]
    fn read_fixed_body(&self, reader: &mut BufReader<&mut dyn ReadWrite>, content_length: usize) -> AuthResult<Vec<u8>> {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)
            .map_err(|e| AuthError::NetworkError(format!("Failed to read body: {}", e)))?;
        Ok(body)
    }

    #[cfg(feature = "network")]
    fn read_chunked_body(&self, reader: &mut BufReader<&mut dyn ReadWrite>) -> AuthResult<Vec<u8>> {
        let mut body = Vec::new();
        
        loop {
            // Read chunk size line
            let chunk_size_line = self.read_line(reader)?;
            let chunk_size = usize::from_str_radix(chunk_size_line.trim(), 16)
                .map_err(|e| AuthError::NetworkError(format!("Invalid chunk size: {}", e)))?;
            
            if chunk_size == 0 {
                // Read trailing headers if any
                loop {
                    let line = self.read_line(reader)?;
                    if line.is_empty() {
                        break;
                    }
                }
                break;
            }
            
            // Read chunk data
            let mut chunk = vec![0u8; chunk_size];
            reader.read_exact(&mut chunk)
                .map_err(|e| AuthError::NetworkError(format!("Failed to read chunk: {}", e)))?;
            body.extend_from_slice(&chunk);
            
            // Read CRLF after chunk
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf)
                .map_err(|e| AuthError::NetworkError(format!("Failed to read chunk CRLF: {}", e)))?;
        }
        
        Ok(body)
    }

    #[cfg(feature = "network")]
    fn read_until_close(&self, reader: &mut BufReader<&mut dyn ReadWrite>) -> AuthResult<Vec<u8>> {
        let mut body = Vec::new();
        let mut buffer = [0u8; 4096];
        
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&buffer[..n]),
                Err(e) => return Err(AuthError::NetworkError(format!("Failed to read body: {}", e))),
            }
        }
        
        Ok(body)
    }

    #[cfg(feature = "network")]
    fn get_auth_client(&self) -> AuthResult<&mut WindowsAuthClient> {
        unsafe {
            crate::AUTH_CLIENT.as_mut()
                .ok_or_else(|| AuthError::NotInitialized("Auth client not initialized".to_string()))
        }
    }

    fn parse_url(&self, url: &str) -> AuthResult<ParsedUrl> {
        let url_lower = url.to_lowercase();
        
        let is_https = url_lower.starts_with("https://");
        let is_http = url_lower.starts_with("http://");
        
        if !is_https && !is_http {
            return Err(AuthError::NetworkError("URL must start with http:// or https://".to_string()));
        }
        
        let after_proto = if is_https {
            &url[8..]
        } else {
            &url[7..]
        };
        
        let (host, path) = if let Some(slash_pos) = after_proto.find('/') {
            let (h, p) = after_proto.split_at(slash_pos);
            (h, if p.is_empty() { "/" } else { p })
        } else {
            (after_proto, "/")
        };
        
        let (host, port) = if let Some(colon_pos) = host.find(':') {
            let (h, p) = host.split_at(colon_pos);
            (h, p[1..].parse::<u16>().unwrap_or(if is_https { 443 } else { 80 }))
        } else {
            (host, if is_https { 443 } else { 80 })
        };
        
        Ok(ParsedUrl {
            host: host.to_string(),
            port,
            path: path.to_string(),
            is_https,
            address: format!("{}:{}", host, port),
        })
    }

    fn build_request(&self, url: &ParsedUrl, method: &str, body: &Option<Vec<u8>>, auth_header: &str, keep_alive: bool) -> String {
        let body_len = body.as_ref().map(|b| b.len()).unwrap_or(0);
        
        let mut request = format!(
            "{} {} HTTP/1.1\r\n",
            method,
            url.path
        );
        
        request.push_str(&format!("Host: {}\r\n", url.host));
        request.push_str(&format!("Authorization: {}\r\n", auth_header));
        request.push_str("User-Agent: rust9x-windows-auth/1.0\r\n");
        request.push_str("Accept: */*\r\n");
        
        if keep_alive {
            request.push_str("Connection: keep-alive\r\n");
        } else {
            request.push_str("Connection: close\r\n");
        }
        
        if body_len > 0 {
            request.push_str(&format!("Content-Length: {}\r\n", body_len));
            request.push_str("Content-Type: application/json\r\n");
        }
        
        request.push_str("\r\n");
        
        if let Some(body_data) = body {
            request.push_str(&String::from_utf8_lossy(body_data));
        }
        
        request
    }

    fn extract_auth_challenge(&self, response: &HttpResponse) -> Option<Vec<u8>> {
        for header_value in response.headers.get_all("www-authenticate") {
            // Handle both "Negotiate <token>" and "NTLM <token>" formats
            // Server may send either "Negotiate" (with or without token) or "NTLM <token>"
            let header_lower = header_value.to_lowercase();
            
            // Check for Negotiate header
            if header_lower.starts_with("negotiate") {
                let after_negotiate = &header_value[9..].trim(); // Skip "Negotiate"
                if after_negotiate.is_empty() {
                    // Server sent "Negotiate" with no token - this is a valid initial challenge
                    // Return empty challenge to trigger the authentication sequence
                    eprintln!("[HTTP] Server sent Negotiate without token - this is valid for initial challenge");
                    return Some(Vec::new());
                } else {
                    // Server sent "Negotiate <token>" - extract the token
                    if let Some(challenge) = self.base64_decode(after_negotiate) {
                        eprintln!("[HTTP] Extracted Negotiate challenge token: {} bytes", challenge.len());
                        return Some(challenge);
                    }
                }
            }
            
            // Check for NTLM header (fallback for servers that only support NTLM)
            if header_lower.starts_with("ntlm") {
                let after_ntlm = &header_value[4..].trim(); // Skip "NTLM"
                if after_ntlm.is_empty() {
                    // Server sent "NTLM" with no token - valid initial challenge
                    eprintln!("[HTTP] Server sent NTLM without token - this is valid for initial challenge");
                    return Some(Vec::new());
                } else {
                    // Server sent "NTLM <token>" - extract the token
                    if let Some(challenge) = self.base64_decode(after_ntlm) {
                        eprintln!("[HTTP] Extracted NTLM challenge token: {} bytes", challenge.len());
                        return Some(challenge);
                    }
                }
            }
        }
        None
    }

    fn base64_encode(&self, data: &[u8]) -> String {
        const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        let mut result = String::new();
        let mut i = 0;
        
        while i < data.len() {
            let b0 = data[i];
            let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
            let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
            
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

    fn base64_decode(&self, input: &str) -> Option<Vec<u8>> {
        const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        let mut result = Vec::new();
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        
        for c in input.bytes() {
            let val = if c == b'=' {
                0
            } else {
                BASE64_CHARS.iter().position(|&x| x == c)?
            };
            
            buffer = (buffer << 6) | (val as u32);
            bits += 6;
            
            if bits >= 8 {
                bits -= 8;
                result.push((buffer >> bits) as u8);
            }
        }
        
        Some(result)
    }

    // Kept for API compatibility - used for simple response completion checking
    fn find_headers_end(&self, buf: &[u8]) -> Option<usize> {
        let pattern = b"\r\n\r\n";
        buf.windows(pattern.len())
            .position(|window| window == pattern)
            .map(|pos| pos + pattern.len())
    }

    // Kept for API compatibility - used for simple response completion checking
    fn is_complete_response(&self, buf: &[u8]) -> bool {
        if let Some(headers_end) = self.find_headers_end(buf) {
            let headers = String::from_utf8_lossy(&buf[..headers_end]);
            
            // Check for Content-Length
            if let Some(cl_line) = headers.lines().find(|l| l.to_lowercase().starts_with("content-length:")) {
                if let Some(len_str) = cl_line.strip_prefix("content-length:")
                    .or_else(|| cl_line.strip_prefix("Content-Length:"))
                {
                    if let Ok(content_len) = len_str.trim().parse::<usize>() {
                        let body_start = headers_end;
                        return buf.len() >= body_start + content_len;
                    }
                }
            }
            
            // If no Content-Length, check for chunked or connection close
            if headers.contains("Transfer-Encoding: chunked") {
                // Simplified check - in production, need proper chunked parsing
                return buf.ends_with(b"0\r\n\r\n");
            }
            
            // For simple responses without Content-Length, assume complete if we have some data
            return buf.len() > headers_end;
        }
        false
    }
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    is_https: bool,
    address: String,
}

impl Drop for HttpClient {
    fn drop(&mut self) {
        #[cfg(feature = "network")]
        {
            if let Some(mut conn) = self.connection.take() {
                conn.close();
            }
        }
    }
}
