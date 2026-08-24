using System;
using System.Threading;
using System.Diagnostics;

namespace Rust9xWindowsAuth
{
    /// <summary>
    /// Thread-safe singleton manager for temporary credential storage between forms
    /// Provides production-grade security and lifecycle management for credentials
    /// Compatible with .NET Framework 2.0
    /// </summary>
    public class CredentialManager
    {
        private static CredentialManager _instance;
        private static readonly object _instanceLock = new object();
        private static readonly object _credentialsLock = new object();

        private CredentialContainer _currentCredentials;
        private DateTime _credentialsStoredTime;
        private Timer _clearCredentialsTimer;
        private const int AutoClearMilliseconds = 60000; // Auto-clear after 1 minute

        /// <summary>
        /// Private constructor for singleton pattern
        /// </summary>
        private CredentialManager()
        {
            try
            {
                _currentCredentials = null;
                _credentialsStoredTime = DateTime.MinValue;
                Debug.WriteLine("CredentialManager: Instance created");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialManager: Exception in constructor: " + ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Get the singleton instance of CredentialManager
        /// </summary>
        public static CredentialManager Instance
        {
            get
            {
                try
                {
                    if (_instance == null)
                    {
                        lock (_instanceLock)
                        {
                            if (_instance == null)
                            {
                                _instance = new CredentialManager();
                            }
                        }
                    }
                    return _instance;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in Instance getter: " + ex.Message);
                    throw;
                }
            }
        }

        /// <summary>
        /// Store credentials securely with default auto-clear time
        /// </summary>
        /// <param name="credentials">CredentialContainer to store</param>
        public void StoreCredentials(CredentialContainer credentials)
        {
            StoreCredentials(credentials, AutoClearMilliseconds);
        }

        /// <summary>
        /// Store credentials securely
        /// </summary>
        /// <param name="credentials">CredentialContainer to store</param>
        /// <param name="autoClearAfterMs">Auto-clear time in milliseconds</param>
        public void StoreCredentials(CredentialContainer credentials, int autoClearAfterMs)
        {
            try
            {
                if (credentials == null)
                {
                    Debug.WriteLine("CredentialManager: StoreCredentials - credentials is null");
                    throw new ArgumentNullException("credentials");
                }

                if (!credentials.HasCredentials())
                {
                    Debug.WriteLine("CredentialManager: StoreCredentials - credentials are empty or invalid");
                    throw new ArgumentException("Credentials container is empty or invalid", "credentials");
                }

                lock (_credentialsLock)
                {
                    Debug.WriteLine("CredentialManager: Storing credentials with auto-clear after " + autoClearAfterMs + "ms");
                    
                    // Clear any existing credentials first
                    ClearCredentialsInternal();

                    _currentCredentials = credentials;
                    _credentialsStoredTime = DateTime.UtcNow;

                    // Set up auto-clear timer
                    SetupAutoClearTimer(autoClearAfterMs);
                    
                    Debug.WriteLine("CredentialManager: Credentials stored successfully");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialManager: Exception in StoreCredentials: " + ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Retrieve and clear credentials (one-time use pattern)
        /// </summary>
        /// <returns>CredentialContainer or null if no credentials available</returns>
        public CredentialContainer RetrieveAndClearCredentials()
        {
            lock (_credentialsLock)
            {
                try
                {
                    if (_currentCredentials == null || !_currentCredentials.IsValid)
                    {
                        Debug.WriteLine("CredentialManager: RetrieveAndClearCredentials - no valid credentials available");
                        return null;
                    }

                    CredentialContainer credentials = _currentCredentials;
                    _currentCredentials = null;
                    _credentialsStoredTime = DateTime.MinValue;

                    // Cancel any pending auto-clear timer
                    ClearAutoClearTimer();

                    Debug.WriteLine("CredentialManager: Credentials retrieved and cleared successfully");
                    return credentials;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in RetrieveAndClearCredentials: " + ex.Message);
                    return null;
                }
            }
        }

        /// <summary>
        /// Check if credentials are available
        /// </summary>
        /// <returns>True if valid credentials are stored</returns>
        public bool HasCredentials
        {
            get
            {
                lock (_credentialsLock)
                {
                    try
                    {
                        bool hasCreds = _currentCredentials != null && _currentCredentials.IsValid;
                        Debug.WriteLine("CredentialManager: HasCredentials = " + hasCreds);
                        return hasCreds;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("CredentialManager: Exception in HasCredentials: " + ex.Message);
                        return false;
                    }
                }
            }
        }

        /// <summary>
        /// Get credentials without clearing (use with caution)
        /// </summary>
        /// <returns>CredentialContainer or null if no credentials available</returns>
        public CredentialContainer PeekCredentials()
        {
            lock (_credentialsLock)
            {
                try
                {
                    if (_currentCredentials == null || !_currentCredentials.IsValid)
                    {
                        Debug.WriteLine("CredentialManager: PeekCredentials - no valid credentials available");
                        return null;
                    }

                    Debug.WriteLine("CredentialManager: PeekCredentials - credentials peeked successfully");
                    return _currentCredentials;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in PeekCredentials: " + ex.Message);
                    return null;
                }
            }
        }

        /// <summary>
        /// Clear stored credentials immediately
        /// </summary>
        public void ClearCredentials()
        {
            lock (_credentialsLock)
            {
                try
                {
                    Debug.WriteLine("CredentialManager: ClearCredentials called");
                    ClearCredentialsInternal();
                    ClearAutoClearTimer();
                    Debug.WriteLine("CredentialManager: ClearCredentials completed");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in ClearCredentials: " + ex.Message);
                }
            }
        }

        /// <summary>
        /// Internal method to clear credentials (must be called within lock)
        /// </summary>
        private void ClearCredentialsInternal()
        {
            if (_currentCredentials != null)
            {
                try
                {
                    Debug.WriteLine("CredentialManager: Clearing credentials internally");
                    _currentCredentials.Clear();
                    _currentCredentials.Dispose();
                }
                catch (Exception ex)
                {
                    // Log but don't throw - we want to ensure cleanup happens
                    Debug.WriteLine("CredentialManager: Error clearing credentials: " + ex.Message);
                }
                finally
                {
                    _currentCredentials = null;
                }
            }

            _credentialsStoredTime = DateTime.MinValue;
        }

        /// <summary>
        /// Setup auto-clear timer
        /// </summary>
        private void SetupAutoClearTimer(int delayMs)
        {
            try
            {
                ClearAutoClearTimer();

                if (delayMs > 0)
                {
                    _clearCredentialsTimer = new Timer(
                        new TimerCallback(AutoClearCallback),
                        null,
                        delayMs,
                        Timeout.Infinite);
                    Debug.WriteLine("CredentialManager: Auto-clear timer set for " + delayMs + "ms");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialManager: Exception in SetupAutoClearTimer: " + ex.Message);
            }
        }

        /// <summary>
        /// Clear auto-clear timer
        /// </summary>
        private void ClearAutoClearTimer()
        {
            try
            {
                if (_clearCredentialsTimer != null)
                {
                    _clearCredentialsTimer.Dispose();
                    _clearCredentialsTimer = null;
                    Debug.WriteLine("CredentialManager: Auto-clear timer cleared");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialManager: Exception in ClearAutoClearTimer: " + ex.Message);
            }
        }

        /// <summary>
        /// Timer callback for auto-clearing credentials
        /// </summary>
        private void AutoClearCallback(object state)
        {
            try
            {
                lock (_credentialsLock)
                {
                    if (_currentCredentials != null)
                    {
                        Debug.WriteLine("CredentialManager: Auto-clearing credentials after timeout");
                        ClearCredentialsInternal();
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("CredentialManager: Error in auto-clear callback: " + ex.Message);
            }
            finally
            {
                ClearAutoClearTimer();
            }
        }

        /// <summary>
        /// Get the age of stored credentials in seconds
        /// </summary>
        /// <returns>Age in seconds, or -1 if no credentials stored</returns>
        public double GetCredentialsAgeInSeconds()
        {
            lock (_credentialsLock)
            {
                try
                {
                    if (_currentCredentials == null || _credentialsStoredTime == DateTime.MinValue)
                    {
                        return -1;
                    }

                    double age = (DateTime.UtcNow - _credentialsStoredTime).TotalSeconds;
                    Debug.WriteLine("CredentialManager: Credential age = " + age + " seconds");
                    return age;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in GetCredentialsAgeInSeconds: " + ex.Message);
                    return -1;
                }
            }
        }

        /// <summary>
        /// Validate stored credentials are still valid
        /// </summary>
        /// <returns>True if credentials are valid and not expired</returns>
        public bool ValidateCredentials()
        {
            lock (_credentialsLock)
            {
                try
                {
                    bool valid = _currentCredentials != null && _currentCredentials.IsValid;
                    Debug.WriteLine("CredentialManager: ValidateCredentials = " + valid);
                    return valid;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in ValidateCredentials: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>
        /// Cleanup method to be called during application shutdown
        /// </summary>
        public void Shutdown()
        {
            lock (_credentialsLock)
            {
                try
                {
                    Debug.WriteLine("CredentialManager: Shutdown called");
                    ClearCredentialsInternal();
                    ClearAutoClearTimer();
                    Debug.WriteLine("CredentialManager: Shutdown completed");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("CredentialManager: Exception in Shutdown: " + ex.Message);
                }
            }
        }
    }
}