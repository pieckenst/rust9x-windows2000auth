using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;

namespace Rust9xWindowsAuth
{
    /// <summary>
    /// Secure container for authentication credentials with memory protection
    /// Designed for .NET Framework 2.0 compatibility with production-grade security
    /// </summary>
    public class CredentialContainer : IDisposable
    {
        private SecureString _username;
        private SecureString _password;
        private SecureString _domain;
        private bool _disposed;
        private DateTime _creationTime;
        private readonly object _lockObject = new object();

        /// <summary>
        /// Maximum age for credentials in seconds before they're considered stale
        /// </summary>
        private const int MaxCredentialAgeSeconds = 300; // 5 minutes

        /// <summary>
        /// Create an empty credential container
        /// </summary>
        public CredentialContainer()
        {
            try
            {
                _username = new SecureString();
                _password = new SecureString();
                _domain = new SecureString();
                _creationTime = DateTime.UtcNow;
                _disposed = false;
                Debug.WriteLine("CredentialContainer: Empty container created");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialContainer: Exception in constructor: " + ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Create a credential container with pre-populated values
        /// </summary>
        /// <param name="username">Username (will be converted to SecureString)</param>
        /// <param name="password">Password (will be converted to SecureString)</param>
        /// <param name="domain">Domain (optional, will be converted to SecureString)</param>
        public CredentialContainer(string username, string password, string domain)
            : this()
        {
            try
            {
                if (!string.IsNullOrEmpty(username))
                {
                    foreach (char c in username)
                    {
                        _username.AppendChar(c);
                    }
                }

                if (!string.IsNullOrEmpty(password))
                {
                    foreach (char c in password)
                    {
                        _password.AppendChar(c);
                    }
                }

                if (!string.IsNullOrEmpty(domain))
                {
                    foreach (char c in domain)
                    {
                        _domain.AppendChar(c);
                    }
                }

                // Make strings read-only after population
                _username.MakeReadOnly();
                _password.MakeReadOnly();
                _domain.MakeReadOnly();
                
                Debug.WriteLine("CredentialContainer: Container created with credentials");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialContainer: Exception in parameterized constructor: " + ex.Message);
                // Clean up any partial data
                try
                {
                    _username.Clear();
                    _password.Clear();
                    _domain.Clear();
                }
                catch
                {
                    // Ignore cleanup errors
                }
                throw;
            }
        }

        /// <summary>
        /// Create a credential container from SecureString objects
        /// </summary>
        /// <param name="username">Username as SecureString</param>
        /// <param name="password">Password as SecureString</param>
        /// <param name="domain">Domain as SecureString (optional)</param>
        public CredentialContainer(SecureString username, SecureString password, SecureString domain)
            : this()
        {
            try
            {
                if (username != null)
                {
                    _username = username;
                    if (!_username.IsReadOnly())
                    {
                        _username.MakeReadOnly();
                    }
                }

                if (password != null)
                {
                    _password = password;
                    if (!_password.IsReadOnly())
                    {
                        _password.MakeReadOnly();
                    }
                }

                if (domain != null)
                {
                    _domain = domain;
                    if (!_domain.IsReadOnly())
                    {
                        _domain.MakeReadOnly();
                    }
                }
                
                Debug.WriteLine("CredentialContainer: Container created from SecureStrings");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialContainer: Exception in SecureString constructor: " + ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Check if credentials are valid and not expired
        /// </summary>
        public bool IsValid
        {
            get
            {
                lock (_lockObject)
                {
                    try
                    {
                        if (_disposed)
                        {
                            Debug.WriteLine("CredentialContainer: IsValid - container is disposed");
                            return false;
                        }

                        // Check if credentials have expired
                        TimeSpan age = DateTime.UtcNow - _creationTime;
                        if (age.TotalSeconds > MaxCredentialAgeSeconds)
                        {
                            Debug.WriteLine("CredentialContainer: IsValid - credentials expired");
                            return false;
                        }

                        // Check if we have at least username and password
                        bool valid = _username.Length > 0 && _password.Length > 0;
                        Debug.WriteLine("CredentialContainer: IsValid = " + valid);
                        return valid;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("CredentialContainer: Exception in IsValid: " + ex.Message);
                        return false;
                    }
                }
            }
        }

        /// <summary>
        /// Get username as plain text (use with caution - immediately clear after use)
        /// </summary>
        /// <returns>Username as string</returns>
        public string GetUsername()
        {
            lock (_lockObject)
            {
                if (_disposed || _username == null)
                {
                    Debug.WriteLine("CredentialContainer: GetUsername - container disposed or username null");
                    return null;
                }

                IntPtr ptr = IntPtr.Zero;
                try
                {
                    ptr = Marshal.SecureStringToBSTR(_username);
                    string result = Marshal.PtrToStringBSTR(ptr);
                    Debug.WriteLine("CredentialContainer: GetUsername - username retrieved successfully");
                    return result;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialContainer: Exception in GetUsername: " + ex.Message);
                    return null;
                }
                finally
                {
                    if (ptr != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeBSTR(ptr);
                    }
                }
            }
        }

        /// <summary>
        /// Get password as plain text (use with caution - immediately clear after use)
        /// </summary>
        /// <returns>Password as string</returns>
        public string GetPassword()
        {
            lock (_lockObject)
            {
                if (_disposed || _password == null)
                {
                    Debug.WriteLine("CredentialContainer: GetPassword - container disposed or password null");
                    return null;
                }

                IntPtr ptr = IntPtr.Zero;
                try
                {
                    ptr = Marshal.SecureStringToBSTR(_password);
                    string result = Marshal.PtrToStringBSTR(ptr);
                    Debug.WriteLine("CredentialContainer: GetPassword - password retrieved successfully");
                    return result;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialContainer: Exception in GetPassword: " + ex.Message);
                    return null;
                }
                finally
                {
                    if (ptr != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeBSTR(ptr);
                    }
                }
            }
        }

        /// <summary>
        /// Get domain as plain text (use with caution - immediately clear after use)
        /// </summary>
        /// <returns>Domain as string or null if not set</returns>
        public string GetDomain()
        {
            lock (_lockObject)
            {
                if (_disposed || _domain == null || _domain.Length == 0)
                {
                    Debug.WriteLine("CredentialContainer: GetDomain - container disposed or domain null/empty");
                    return null;
                }

                IntPtr ptr = IntPtr.Zero;
                try
                {
                    ptr = Marshal.SecureStringToBSTR(_domain);
                    string result = Marshal.PtrToStringBSTR(ptr);
                    Debug.WriteLine("CredentialContainer: GetDomain - domain retrieved successfully");
                    return result;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialContainer: Exception in GetDomain: " + ex.Message);
                    return null;
                }
                finally
                {
                    if (ptr != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeBSTR(ptr);
                    }
                }
            }
        }

        /// <summary>
        /// Get the SecureString objects directly for advanced usage
        /// </summary>
        /// <param name="username">Output username SecureString</param>
        /// <param name="password">Output password SecureString</param>
        /// <param name="domain">Output domain SecureString</param>
        public void GetSecureStrings(out SecureString username, out SecureString password, out SecureString domain)
        {
            lock (_lockObject)
            {
                username = _disposed ? null : _username;
                password = _disposed ? null : _password;
                domain = _disposed ? null : _domain;
                Debug.WriteLine("CredentialContainer: GetSecureStrings called");
            }
        }

        /// <summary>
        /// Check if credentials are present and valid
        /// </summary>
        /// <returns>True if credentials are available</returns>
        public bool HasCredentials()
        {
            lock (_lockObject)
            {
                bool hasCreds = !_disposed && _username != null && _username.Length > 0 &&
                                _password != null && _password.Length > 0;
                Debug.WriteLine("CredentialContainer: HasCredentials = " + hasCreds);
                return hasCreds;
            }
        }

        /// <summary>
        /// Clear all credentials from memory
        /// </summary>
        public void Clear()
        {
            lock (_lockObject)
            {
                try
                {
                    Debug.WriteLine("CredentialContainer: Clear called");
                    if (_username != null)
                    {
                        _username.Clear();
                        _username.Dispose();
                        _username = new SecureString();
                    }

                    if (_password != null)
                    {
                        _password.Clear();
                        _password.Dispose();
                        _password = new SecureString();
                    }

                    if (_domain != null)
                    {
                        _domain.Clear();
                        _domain.Dispose();
                        _domain = new SecureString();
                    }

                    _creationTime = DateTime.UtcNow;
                    Debug.WriteLine("CredentialContainer: Clear completed successfully");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialContainer: Exception in Clear: " + ex.Message);
                }
            }
        }

        /// <summary>
        /// Get the age of the credentials in seconds
        /// </summary>
        /// <returns>Age in seconds</returns>
        public double GetAgeInSeconds()
        {
            lock (_lockObject)
            {
                double age = (DateTime.UtcNow - _creationTime).TotalSeconds;
                Debug.WriteLine("CredentialContainer: Credential age = " + age + " seconds");
                return age;
            }
        }

        /// <summary>
        /// Dispose pattern implementation
        /// </summary>
        public void Dispose()
        {
            Debug.WriteLine("CredentialContainer: Dispose called");
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected dispose implementation
        /// </summary>
        /// <param name="disposing">True if disposing managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            lock (_lockObject)
            {
                if (!_disposed)
                {
                    Debug.WriteLine("CredentialContainer: Dispose(" + disposing + ") - disposing");
                    if (disposing)
                    {
                        // Clear and dispose all secure strings
                        try
                        {
                            if (_username != null)
                            {
                                _username.Clear();
                                _username.Dispose();
                                _username = null;
                            }

                            if (_password != null)
                            {
                                _password.Clear();
                                _password.Dispose();
                                _password = null;
                            }

                            if (_domain != null)
                            {
                                _domain.Clear();
                                _domain.Dispose();
                                _domain = null;
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine("CredentialContainer: Exception during dispose cleanup: " + ex.Message);
                        }
                    }

                    _disposed = true;
                    Debug.WriteLine("CredentialContainer: Dispose completed");
                }
            }
        }

        /// <summary>
        /// Finalizer to ensure credentials are cleared
        /// </summary>
        ~CredentialContainer()
        {
            Debug.WriteLine("CredentialContainer: Finalizer called");
            Dispose(false);
        }

        /// <summary>
        /// Check if the container has been disposed
        /// </summary>
        public bool IsDisposed
        {
            get
            {
                lock (_lockObject)
                {
                    return _disposed;
                }
            }
        }
    }
}