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

#[cfg(feature = "network")]
use std::net::TcpStream;

#[cfg(feature = "tls")]
use native_tls::TlsConnector;

use crate::auth::{AuthError, AuthResult, WindowsAuthClient};

trait ReadWrite: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> ReadWrite for T {}

/// HTTP client with Windows Authentication support
pub struct HttpClient {
    #[cfg(feature = "tls")]
    tls_connector: Option<TlsConnector>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "tls")]
            tls_connector: None,
        }
    }

    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, config: crate::tls::TlsConfig) -> Self {
        match config.build_connector() {
            Ok(connector) => {
                self.tls_connector = Some(connector);
            }
            Err(e) => {
                eprintln!("Failed to build TLS connector: {}", e);
            }
        }
        self
    }

    /// Perform HTTP request with NTLM authentication
    pub fn http_request(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> AuthResult<Vec<u8>> {
        let parsed_url = self.parse_url(url)?;
        
        #[cfg(feature = "network")]
        {
            let stream = TcpStream::connect(&parsed_url.address)
                .map_err(|e| AuthError::NetworkError(format!("Failed to connect: {}", e)))?;

            stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .map_err(|e| AuthError::NetworkError(format!("Failed to set timeout: {}", e)))?;

            #[cfg(feature = "tls")]
            let mut stream = if parsed_url.is_https {
                let tls_connector = self.tls_connector.as_ref()
                    .ok_or_else(|| AuthError::TlsError("TLS not configured".to_string()))?;

                let tls_stream = tls_connector.connect(&parsed_url.host, stream)
                    .map_err(|e| AuthError::TlsError(format!("TLS handshake failed: {}", e)))?;

                Box::new(tls_stream) as Box<dyn ReadWrite>
            } else {
                Box::new(stream) as Box<dyn ReadWrite>
            };

            #[cfg(not(feature = "tls"))]
            let mut stream = Box::new(stream) as Box<dyn ReadWrite>;

            self.perform_http_request(&mut stream, &parsed_url, method, body)
        }

        #[cfg(not(feature = "network"))]
        {
            Err(AuthError::NetworkError("Networking not enabled".to_string()))
        }
    }

    #[cfg(feature = "network")]
    fn perform_http_request(
        &mut self,
        stream: &mut dyn ReadWrite,
        url: &ParsedUrl,
        method: &str,
        body: Option<Vec<u8>>,
    ) -> AuthResult<Vec<u8>> {

        let auth_client = self.get_auth_client()?;
        
        // Generate NTLM negotiate token
        let target_name = &format!("HTTP/{}", url.host);
        let negotiate_token = auth_client.generate_negotiate_token(target_name)?;
        let negotiate_b64 = self.base64_encode(&negotiate_token);

        // Build initial request with Authorization header
        let request = self.build_request(url, method, &body, &format!("NTLM {}", negotiate_b64));
        
        stream.write_all(request.as_bytes())
            .map_err(|e| AuthError::NetworkError(format!("Failed to send request: {}", e)))?;

        // Read response
        let mut response_buf = Vec::new();
        let mut temp_buf = [0u8; 4096];
        
        loop {
            let n = stream.read(&mut temp_buf)
                .map_err(|e| AuthError::NetworkError(format!("Failed to read response: {}", e)))?;
            if n == 0 {
                break;
            }
            response_buf.extend_from_slice(&temp_buf[..n]);
            
            // Check if we have complete headers
            if let Some(pos) = self.find_headers_end(&response_buf) {
                let headers = String::from_utf8_lossy(&response_buf[..pos]).to_string();
                
                // Check for 401 Unauthorized with WWW-Authenticate
                if headers.contains("401") && headers.contains("WWW-Authenticate:") {
                    // Extract NTLM challenge
                    if let Some(challenge) = self.extract_ntlm_challenge(&headers) {
                        // Process challenge and get authenticate token
                        let auth_token = auth_client.process_challenge(&challenge, target_name)?;
                        let auth_b64 = self.base64_encode(&auth_token);
                        
                        // Send request with Authorization header
                        let auth_request = self.build_request(url, method, &body, &format!("NTLM {}", auth_b64));
                        
                        stream.write_all(auth_request.as_bytes())
                            .map_err(|e| AuthError::NetworkError(format!("Failed to send auth request: {}", e)))?;
                        
                        // Read final response
                        response_buf.clear();
                        loop {
                            let n = stream.read(&mut temp_buf)
                                .map_err(|e| AuthError::NetworkError(format!("Failed to read final response: {}", e)))?;
                            if n == 0 {
                                break;
                            }
                            response_buf.extend_from_slice(&temp_buf[..n]);
                            
                            // Check for complete response
                            if self.is_complete_response(&response_buf) {
                                break;
                            }
                        }
                    }
                }
                
                // If we got a non-401 response, break
                if !headers.contains("401") {
                    break;
                }
            }
        }

        Ok(response_buf)
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

    fn build_request(&self, url: &ParsedUrl, method: &str, body: &Option<Vec<u8>>, auth_header: &str) -> String {
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

    fn find_headers_end(&self, buf: &[u8]) -> Option<usize> {
        let pattern = b"\r\n\r\n";
        buf.windows(pattern.len())
            .position(|window| window == pattern)
            .map(|pos| pos + pattern.len())
    }

    fn extract_ntlm_challenge(&self, headers: &str) -> Option<Vec<u8>> {
        for line in headers.lines() {
            if line.to_lowercase().starts_with("www-authenticate:") {
                if let Some(ntlm_start) = line.find("NTLM ") {
                    let challenge_b64 = &line[ntlm_start + 5..].trim();
                    return self.base64_decode(challenge_b64);
                }
            }
        }
        None
    }

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
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    is_https: bool,
    address: String,
}
