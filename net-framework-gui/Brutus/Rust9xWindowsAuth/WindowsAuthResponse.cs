using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace Rust9xWindowsAuth
{
    /// <summary>
    /// Response structure for Windows authentication endpoint
    /// Handles the complex JSON response with JWT tokens, user info, and Windows auth details
    /// Compatible with .NET Framework 2.0
    /// </summary>
    [Serializable]
    public class WindowsAuthResponse
    {
        private string _id;
        private string _token;
        private UserInfo _user;
        private WindowsAuthInfo _windowsAuth;

        /// <summary>
        /// JSON $id field
        /// </summary>
        public string Id
        {
            get { return _id; }
            set { _id = value; }
        }

        /// <summary>
        /// JWT authentication token
        /// </summary>
        public string Token
        {
            get { return _token; }
            set { _token = value; }
        }

        /// <summary>
        /// User information from the authentication response
        /// </summary>
        public UserInfo User
        {
            get { return _user; }
            set { _user = value; }
        }

        /// <summary>
        /// Detailed Windows authentication information
        /// </summary>
        public WindowsAuthInfo WindowsAuth
        {
            get { return _windowsAuth; }
            set { _windowsAuth = value; }
        }

        /// <summary>
        /// Check if the response contains valid authentication data
        /// </summary>
        public bool IsValid
        {
            get
            {
                return !string.IsNullOrEmpty(_token) && 
                       _user != null && 
                       _user.UserId > 0;
            }
        }

        /// <summary>
        /// Check if the Windows account needs linking
        /// </summary>
        public bool NeedsAccountLinking
        {
            get
            {
                return _user != null && _user.DoesWindowsAccountNeedLinking;
            }
        }

        /// <summary>
        /// Get the user ID from the response
        /// </summary>
        public int UserId
        {
            get
            {
                return _user != null ? _user.UserId : 0;
            }
        }

        /// <summary>
        /// Get the user login name
        /// </summary>
        public string UserLogin
        {
            get
            {
                return _user != null ? _user.Login : null;
            }
        }

        /// <summary>
        /// Get the user role (0 = user, 1 = admin)
        /// </summary>
        public int UserRole
        {
            get
            {
                return _user != null ? _user.Role : 0;
            }
        }

        /// <summary>
        /// Check if the user is an administrator
        /// </summary>
        public bool IsAdministrator
        {
            get
            {
                return UserRole == 1;
            }
        }
    }

    /// <summary>
    /// User information from authentication response
    /// </summary>
    [Serializable]
    public class UserInfo
    {
        private string _id;
        private int _userId;
        private string _login;
        private string _email;
        private int _role;
        private bool _isWindowsAuth;
        private bool _doesWindowsAccountNeedLinking;

        public string Id
        {
            get { return _id; }
            set { _id = value; }
        }

        public int UserId
        {
            get { return _userId; }
            set { _userId = value; }
        }

        public string Login
        {
            get { return _login; }
            set { _login = value; }
        }

        public string Email
        {
            get { return _email; }
            set { _email = value; }
        }

        public int Role
        {
            get { return _role; }
            set { _role = value; }
        }

        public bool IsWindowsAuth
        {
            get { return _isWindowsAuth; }
            set { _isWindowsAuth = value; }
        }

        public bool DoesWindowsAccountNeedLinking
        {
            get { return _doesWindowsAccountNeedLinking; }
            set { _doesWindowsAccountNeedLinking = value; }
        }
    }

    /// <summary>
    /// Detailed Windows authentication information
    /// </summary>
    [Serializable]
    public class WindowsAuthInfo
    {
        private string _id;
        private string _protocol;
        private bool _isNtlm;
        private bool _isNegotiate;
        private bool _isKerberos;
        private AuthenticationDetails _authenticationDetails;
        private HttpHeadersInfo _httpHeaders;

        public string Id
        {
            get { return _id; }
            set { _id = value; }
        }

        public string Protocol
        {
            get { return _protocol; }
            set { _protocol = value; }
        }

        public bool IsNtlm
        {
            get { return _isNtlm; }
            set { _isNtlm = value; }
        }

        public bool IsNegotiate
        {
            get { return _isNegotiate; }
            set { _isNegotiate = value; }
        }

        public bool IsKerberos
        {
            get { return _isKerberos; }
            set { _isKerberos = value; }
        }

        public AuthenticationDetails AuthenticationDetails
        {
            get { return _authenticationDetails; }
            set { _authenticationDetails = value; }
        }

        public HttpHeadersInfo HttpHeaders
        {
            get { return _httpHeaders; }
            set { _httpHeaders = value; }
        }
    }

    /// <summary>
    /// Detailed authentication information from Windows
    /// </summary>
    [Serializable]
    public class AuthenticationDetails
    {
        private string _id;
        private string _authenticationType;
        private bool _isAuthenticated;
        private bool _isGuest;
        private bool _isSystem;
        private bool _isAnonymous;
        private string _userSid;
        private string _ownerSid;
        private string _impersonationLevel;
        private string _token;
        private string[] _groups;

        public string Id
        {
            get { return _id; }
            set { _id = value; }
        }

        public string AuthenticationType
        {
            get { return _authenticationType; }
            set { _authenticationType = value; }
        }

        public bool IsAuthenticated
        {
            get { return _isAuthenticated; }
            set { _isAuthenticated = value; }
        }

        public bool IsGuest
        {
            get { return _isGuest; }
            set { _isGuest = value; }
        }

        public bool IsSystem
        {
            get { return _isSystem; }
            set { _isSystem = value; }
        }

        public bool IsAnonymous
        {
            get { return _isAnonymous; }
            set { _isAnonymous = value; }
        }

        public string UserSid
        {
            get { return _userSid; }
            set { _userSid = value; }
        }

        public string OwnerSid
        {
            get { return _ownerSid; }
            set { _ownerSid = value; }
        }

        public string ImpersonationLevel
        {
            get { return _impersonationLevel; }
            set { _impersonationLevel = value; }
        }

        public string Token
        {
            get { return _token; }
            set { _token = value; }
        }

        public string[] Groups
        {
            get { return _groups; }
            set { _groups = value; }
        }
    }

    /// <summary>
    /// HTTP headers from Windows authentication
    /// </summary>
    [Serializable]
    public class HttpHeadersInfo
    {
        private string _id;
        private string _authorization;
        private string _wwwAuthenticate;

        public string Id
        {
            get { return _id; }
            set { _id = value; }
        }

        public string Authorization
        {
            get { return _authorization; }
            set { _authorization = value; }
        }

        public string WwwAuthenticate
        {
            get { return _wwwAuthenticate; }
            set { _wwwAuthenticate = value; }
        }
    }

    /// <summary>
    /// Helper class for parsing JWT tokens (basic implementation for .NET 2.0)
    /// </summary>
    public class JwtTokenHelper
    {
        /// <summary>
        /// Decode JWT token payload (without verification - for development only)
        /// </summary>
        /// <param name="token">JWT token string</param>
        /// <returns>Decoded payload as string</returns>
        public static string DecodePayload(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token))
                    return null;

                string[] parts = token.Split('.');
                if (parts.Length != 3)
                    return null;

                string payload = parts[1];
                
                // Add padding if needed
                int padding = 4 - (payload.Length % 4);
                if (padding != 4)
                {
                    payload += new string('=', padding);
                }

                byte[] decodedBytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
                return Encoding.UTF8.GetString(decodedBytes);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("JWT decode error: " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Extract specific claim from JWT token
        /// </summary>
        /// <param name="token">JWT token string</param>
        /// <param name="claimName">Name of the claim to extract</param>
        /// <returns>Claim value or null if not found</returns>
        public static string GetClaim(string token, string claimName)
        {
            try
            {
                string payload = DecodePayload(token);
                if (string.IsNullOrEmpty(payload))
                    return null;

                // Simple JSON parsing for claim extraction
                string searchPattern = "\"" + claimName + "\":\"";
                int startIndex = payload.IndexOf(searchPattern);
                if (startIndex == -1)
                    return null;

                startIndex += searchPattern.Length;
                int endIndex = payload.IndexOf("\"", startIndex);
                if (endIndex == -1)
                    return null;

                return payload.Substring(startIndex, endIndex - startIndex);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("JWT claim extraction error: " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Extract numeric claim from JWT token
        /// </summary>
        /// <param name="token">JWT token string</param>
        /// <param name="claimName">Name of the claim to extract</param>
        /// <returns>Claim value or 0 if not found</returns>
        public static int GetNumericClaim(string token, string claimName)
        {
            try
            {
                string payload = DecodePayload(token);
                if (string.IsNullOrEmpty(payload))
                    return 0;

                // Simple JSON parsing for numeric claim extraction
                string searchPattern = "\"" + claimName + "\":";
                int startIndex = payload.IndexOf(searchPattern);
                if (startIndex == -1)
                    return 0;

                startIndex += searchPattern.Length;
                int endIndex = payload.IndexOf(",", startIndex);
                if (endIndex == -1)
                    endIndex = payload.IndexOf("}", startIndex);

                if (endIndex == -1)
                    return 0;

                string valueString = payload.Substring(startIndex, endIndex - startIndex).Trim();
                int result;
                if (int.TryParse(valueString, out result))
                    return result;

                return 0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("JWT numeric claim extraction error: " + ex.Message);
                return 0;
            }
        }

        /// <summary>
        /// Extract boolean claim from JWT token
        /// </summary>
        /// <param name="token">JWT token string</param>
        /// <param name="claimName">Name of the claim to extract</param>
        /// <returns>Claim value or false if not found</returns>
        public static bool GetBooleanClaim(string token, string claimName)
        {
            try
            {
                string payload = DecodePayload(token);
                if (string.IsNullOrEmpty(payload))
                    return false;

                // Simple JSON parsing for boolean claim extraction
                string searchPattern = "\"" + claimName + "\":";
                int startIndex = payload.IndexOf(searchPattern);
                if (startIndex == -1)
                    return false;

                startIndex += searchPattern.Length;
                int endIndex = payload.IndexOf(",", startIndex);
                if (endIndex == -1)
                    endIndex = payload.IndexOf("}", startIndex);

                if (endIndex == -1)
                    return false;

                string valueString = payload.Substring(startIndex, endIndex - startIndex).Trim().ToLower();
                return valueString == "true";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("JWT boolean claim extraction error: " + ex.Message);
                return false;
            }
        }
    }
}