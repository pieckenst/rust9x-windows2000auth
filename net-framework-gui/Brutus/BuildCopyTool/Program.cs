using System;
using System.Collections.Generic;
using System.IO;

namespace BuildCopyTool
{
    internal static class Program
    {
        private const string DllName = "rust9x_windows_auth.dll";
        private const int MaxSearchDepth = 6;
        private const int MaxUpwardWalkLevels = 10;

        private static int Main(string[] args)
        {
            try
            {
                Console.WriteLine("=== BuildCopyTool (Enhanced) ===");
                Console.WriteLine();

                PrintEnvironmentInfo(args);
                Console.WriteLine();

                string projectDir = null;
                string targetDir = null;
                string configuration = null;

                // Handle trailing backslash escaping issue from MSBuild
                // When $(TargetDir) has a trailing backslash, it escapes the closing quote
                // causing arguments to be merged: "path1\" "path2" becomes single arg: path1" path2"
                // This results in: args[0] = path1" path2", args[1] = "Debug"
                // Example: E:\code\HandlerGui" E:\code\HandlerGui\bin\Debug"
                
                // Check if first argument contains an embedded quote pattern (indicating merged paths)
                if (args.Length >= 1 && args[0].Contains("\"") && args[0].IndexOf("\"") != args[0].LastIndexOf("\""))
                {
                    Console.WriteLine("Detected MSBuild escaping issue - splitting merged argument");
                    string firstArg = args[0];
                    
                    // Find the pattern: path + quote + space + path + quote
                    int firstQuoteIndex = firstArg.IndexOf("\"");
                    int secondQuoteIndex = firstArg.LastIndexOf("\"");
                    
                    if (firstQuoteIndex >= 0 && secondQuoteIndex > firstQuoteIndex)
                    {
                        // Extract project directory (everything before the first quote)
                        projectDir = NormalizePath(firstArg.Substring(0, firstQuoteIndex));
                        
                        // Extract target directory (between the quotes, but skip the space after first quote)
                        string middlePart = firstArg.Substring(firstQuoteIndex + 1, secondQuoteIndex - firstQuoteIndex - 1);
                        // Remove leading space if present
                        middlePart = middlePart.TrimStart();
                        targetDir = NormalizePath(middlePart);
                        
                        // Configuration is in the next argument
                        if (args.Length >= 2)
                        {
                            configuration = args[1];
                        }
                    }
                }
                else
                {
                    // Normal parsing when no escaping issue
                    if (args.Length >= 3)
                    {
                        projectDir = NormalizePath(args[0]);
                        targetDir = NormalizePath(args[1]);
                        configuration = args[2];
                    }
                    else if (args.Length == 2)
                    {
                        projectDir = NormalizePath(args[0]);
                        targetDir = NormalizePath(args[1]);
                    }
                    else if (args.Length == 1)
                    {
                        projectDir = NormalizePath(args[0]);
                    }
                    else
                    {
                        projectDir = NormalizePath(Environment.CurrentDirectory);
                    }
                }

                Console.WriteLine("=== Path Resolution ===");

                projectDir = ValidateAndResolvePath(projectDir, "ProjectDir");
                string projectDirDisplay = projectDir;
                if (projectDirDisplay == null) projectDirDisplay = "(not provided)";
                Console.WriteLine("Project directory : " + projectDirDisplay);

                targetDir = ValidateAndResolvePath(targetDir, "TargetDir");
                string targetDirDisplay = targetDir;
                if (targetDirDisplay == null) targetDirDisplay = "(not provided)";
                Console.WriteLine("Target directory  : " + targetDirDisplay);

                Console.WriteLine("Configuration     : " + (configuration ?? "(auto-detect)"));
                
                // Auto-detect MSBuild configuration if not provided
                if (string.IsNullOrEmpty(configuration))
                {
                    string msbuildConfig = DetectMsBuildConfiguration(projectDir);
                    if (!string.IsNullOrEmpty(msbuildConfig))
                    {
                        Console.WriteLine("Auto-detected MSBuild config: " + msbuildConfig);
                        configuration = msbuildConfig;
                    }
                }
                Console.WriteLine();

                string rustSrcDir = LocateRustSrcDirectory(projectDir);
                if (rustSrcDir == null)
                {
                    Console.WriteLine("ERROR: Could not locate rust-src directory");
                    return 3;
                }

                Console.WriteLine("Located rust-src    : " + rustSrcDir);
                Console.WriteLine();

                string targetBaseDir = Path.Combine(rustSrcDir, "target");
                if (!Directory.Exists(targetBaseDir))
                {
                    Console.WriteLine("ERROR: target directory not found: " + targetBaseDir);
                    return 4;
                }

                string dllPath = LocateNewestDll(targetBaseDir, configuration);
                if (dllPath == null)
                {
                    Console.WriteLine("ERROR: Could not locate " + DllName);
                    return 5;
                }

                Console.WriteLine("=== DLL Selection ===");
                Console.WriteLine("Selected DLL        : " + dllPath);
                Console.WriteLine("Last modified       : " + File.GetLastWriteTime(dllPath));
                FileInfo dllFileInfo = new FileInfo(dllPath);
                Console.WriteLine("Size                : " + dllFileInfo.Length + " bytes");
                Console.WriteLine();

                string dllConfig = DetectConfiguration(dllPath);
                Console.WriteLine("Detected DLL configuration: " + dllConfig);
                
                // Use provided configuration if available, otherwise use detected
                string finalConfig = configuration ?? dllConfig;
                Console.WriteLine("Using configuration  : " + finalConfig);
                
                // Verify configuration match if one was provided
                if (!string.IsNullOrEmpty(configuration) && 
                    configuration.ToLowerInvariant() != dllConfig.ToLowerInvariant())
                {
                    Console.WriteLine("Warning: Provided configuration '" + configuration + 
                                     "' differs from DLL detected '" + dllConfig + "'");
                    Console.WriteLine("Using provided configuration for output directory: " + configuration);
                    finalConfig = configuration;
                }
                Console.WriteLine();

                string runtimeDir = Path.GetDirectoryName(dllPath);
                Console.WriteLine("Runtime directory   : " + runtimeDir);
                Console.WriteLine();

                string destinationDir = targetDir;
                if (string.IsNullOrEmpty(destinationDir))
                {
                    // Use the final configuration for output directory location
                    // If configuration was provided, use it; otherwise use detected config
                    string outputConfig = configuration ?? dllConfig;
                    destinationDir = LocateOutputDirectory(projectDir, outputConfig);
                    if (destinationDir == null)
                    {
                        Console.WriteLine("ERROR: Could not locate output directory");
                        return 6;
                    }
                }

                Console.WriteLine("Destination directory: " + destinationDir);
                Console.WriteLine();

                if (!Directory.Exists(destinationDir))
                {
                    Directory.CreateDirectory(destinationDir);
                    Console.WriteLine("Created destination directory.");
                    Console.WriteLine();
                }

                Console.WriteLine("=== Copying Files ===");
                string dllDest = Path.Combine(destinationDir, Path.GetFileName(dllPath));
                CopyFileWithVerification(dllPath, dllDest);

                CopyDirectoryRecursive(runtimeDir, destinationDir, true);

                Console.WriteLine();
                Console.WriteLine("=== BuildCopyTool completed successfully ===");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("=== FATAL ERROR ===");
                Console.WriteLine(ex.ToString());
                return 1;
            }
        }

        private static void PrintEnvironmentInfo(string[] args)
        {
            Console.WriteLine("Current directory   : " + Environment.CurrentDirectory);
            Console.WriteLine("Executable          : " + Environment.GetCommandLineArgs()[0]);
            Console.WriteLine("Arguments count     : " + args.Length);
            for (int i = 0; i < args.Length; i++)
            {
                Console.WriteLine("  Arg[" + i + "]: " + args[i]);
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  BuildCopyTool.exe [projectDir] [targetDir] [configuration]");
            Console.WriteLine();
            Console.WriteLine("Arguments:");
            Console.WriteLine("  projectDir    - Optional. Project directory containing .csproj. Defaults to current directory.");
            Console.WriteLine("  targetDir     - Optional. Output directory for DLL and runtime files. Auto-detected if not provided.");
            Console.WriteLine("  configuration - Optional. Build configuration (Debug/Release). Auto-detected from DLL path if not provided.");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  BuildCopyTool.exe");
            Console.WriteLine("  BuildCopyTool.exe \"E:\\code\\rust9x-windows2000auth\\net-framework-gui\\Brutus\\HandlerGui\"");
            Console.WriteLine("  BuildCopyTool.exe \"$(ProjectDir)\" \"$(TargetDir)\"");
            Console.WriteLine("  BuildCopyTool.exe \"$(ProjectDir)\" \"$(TargetDir)\" \"$(ConfigurationName)\"");
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return null;

            path = path.Trim().Trim('"');

            if (path.Length == 0)
                return null;

            try
            {
                return Path.GetFullPath(path);
            }
            catch
            {
                return path;
            }
        }

        private static string NormalizePathTrimmed(string path)
        {
            string normalized = NormalizePath(path);
            if (string.IsNullOrEmpty(normalized))
                return null;

            if (normalized.EndsWith("\\") || normalized.EndsWith("/"))
                normalized = normalized.Substring(0, normalized.Length - 1);

            if (normalized.EndsWith("\""))
                normalized = normalized.Substring(0, normalized.Length - 1);

            return normalized;
        }

        private static string ResolvePathByWalking(string basePath, string relativePath)
        {
            Console.WriteLine("=== Resolving path by walking ===");
            Console.WriteLine("Base path: " + basePath);
            Console.WriteLine("Relative path: " + relativePath);

            if (string.IsNullOrEmpty(relativePath))
                return basePath;

            if (Path.IsPathRooted(relativePath))
                return NormalizePathTrimmed(relativePath);

            string current = basePath;
            if (string.IsNullOrEmpty(current))
                current = Environment.CurrentDirectory;

            current = NormalizePathTrimmed(current);

            string[] segments = relativePath.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string segment in segments)
            {
                if (segment == ".")
                    continue;

                if (segment == "..")
                {
                    DirectoryInfo dirInfo = new DirectoryInfo(current);
                    if (dirInfo.Parent != null)
                    {
                        current = dirInfo.Parent.FullName;
                        Console.WriteLine("Walked up to: " + current);
                    }
                    continue;
                }

                current = Path.Combine(current, segment);
                Console.WriteLine("Walked into: " + current);
            }

            Console.WriteLine("Resolved path: " + current);
            return NormalizePathTrimmed(current);
        }

        private static string ValidateAndResolvePath(string path, string context)
        {
            Console.WriteLine("=== Validating path ===");
            Console.WriteLine("Context: " + context);
            Console.WriteLine("Path: " + path);

            if (string.IsNullOrEmpty(path))
            {
                Console.WriteLine("Path is null or empty");
                return null;
            }

            string resolved = NormalizePathTrimmed(path);
            Console.WriteLine("Normalized: " + resolved);

            if (string.IsNullOrEmpty(resolved))
            {
                Console.WriteLine("Normalized path is null or empty");
                return null;
            }

            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(resolved);
                Console.WriteLine("Directory exists: " + dirInfo.Exists);
                Console.WriteLine("Full path: " + dirInfo.FullName);
                return dirInfo.FullName;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error validating path: " + ex.Message);
                return null;
            }
        }

        private static string LocateRustSrcDirectory(string startPath)
        {
            Console.WriteLine("=== Locating rust-src ===");

            if (string.IsNullOrEmpty(startPath))
                startPath = Environment.CurrentDirectory;

            startPath = ValidateAndResolvePath(startPath, "LocateRustSrcDirectory start");
            if (string.IsNullOrEmpty(startPath))
            {
                Console.WriteLine("Invalid start path, using current directory");
                startPath = Environment.CurrentDirectory;
            }

            DirectoryInfo current = new DirectoryInfo(startPath);
            int levelsWalked = 0;

            Console.WriteLine("Starting search from: " + current.FullName);
            Console.WriteLine("Will walk up " + MaxUpwardWalkLevels + " levels maximum");

            while (current != null && levelsWalked < MaxUpwardWalkLevels)
            {
                Console.WriteLine("Level " + levelsWalked + ": Checking " + current.FullName);

                try
                {
                    // Check for rust-src in current directory
                    string rustSrcPath = Path.Combine(current.FullName, "rust-src");
                    if (Directory.Exists(rustSrcPath))
                    {
                        Console.WriteLine("Found rust-src at: " + rustSrcPath);
                        return ValidateAndResolvePath(rustSrcPath, "Found rust-src");
                    }

                    // Also check if we're already in a subdirectory that might have rust-src as a sibling
                    // This handles cases where we start in HandlerGui and need to go up to find rust-src
                    if (levelsWalked == 0)
                    {
                        Console.WriteLine("First level - checking for sibling rust-src directory");
                        // Check parent directory for rust-src as well
                        if (current.Parent != null)
                        {
                            string parentRustSrc = Path.Combine(current.Parent.FullName, "rust-src");
                            if (Directory.Exists(parentRustSrc))
                            {
                                Console.WriteLine("Found rust-src as sibling at: " + parentRustSrc);
                                return ValidateAndResolvePath(parentRustSrc, "Found sibling rust-src");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error checking directory: " + ex.Message);
                }

                current = current.Parent;
                levelsWalked++;

                if (current == null)
                {
                    Console.WriteLine("Reached filesystem root, stopping search");
                    break;
                }
            }

            Console.WriteLine("rust-src not found after walking " + levelsWalked + " levels");
            return null;
        }

        private static string LocateNewestDll(string searchRoot, string preferredConfiguration)
        {
            Console.WriteLine("=== Searching for " + DllName + " ===");
            Console.WriteLine("Search root: " + searchRoot);
            if (!string.IsNullOrEmpty(preferredConfiguration))
            {
                Console.WriteLine("Preferred configuration: " + preferredConfiguration);
            }

            searchRoot = ValidateAndResolvePath(searchRoot, "LocateNewestDll search root");
            if (string.IsNullOrEmpty(searchRoot))
            {
                Console.WriteLine("Invalid search root");
                return null;
            }

            List<string> candidates = new List<string>();

            try
            {
                Console.WriteLine("Starting recursive search...");
                SearchDirectoryRecursively(searchRoot, DllName, candidates, 0);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine("Warning: Access denied during search: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Error during search: " + ex.Message);
            }

            if (candidates.Count == 0)
            {
                Console.WriteLine("No DLL candidates found");
                return null;
            }

            Console.WriteLine("Found " + candidates.Count + " candidate(s):");

            // Filter by configuration if specified
            if (!string.IsNullOrEmpty(preferredConfiguration))
            {
                string preferredConfigLower = preferredConfiguration.ToLowerInvariant();
                List<string> filteredCandidates = new List<string>();
                
                foreach (string candidate in candidates)
                {
                    string candidateConfig = DetectConfiguration(candidate);
                    if (candidateConfig.ToLowerInvariant() == preferredConfigLower)
                    {
                        filteredCandidates.Add(candidate);
                    }
                }

                if (filteredCandidates.Count > 0)
                {
                    Console.WriteLine("Filtered to " + filteredCandidates.Count + " candidate(s) matching configuration '" + preferredConfiguration + "'");
                    candidates = filteredCandidates;
                }
                else
                {
                    Console.WriteLine("Warning: No candidates found matching configuration '" + preferredConfiguration + "', using all candidates");
                }
            }

            candidates.Sort(new DllFileComparer());

            int displayCount = 5;
            if (candidates.Count < displayCount)
                displayCount = candidates.Count;

            for (int i = 0; i < displayCount; i++)
            {
                FileInfo fi = new FileInfo(candidates[i]);
                string config = DetectConfiguration(candidates[i]);
                Console.WriteLine("  [" + (i + 1) + "] " + candidates[i]);
                Console.WriteLine("       Config: " + config + ", Date: " + fi.LastWriteTime + ", Size: " + fi.Length + " bytes");
            }

            if (candidates.Count > 5)
            {
                Console.WriteLine("  ... and " + (candidates.Count - 5) + " more");
            }

            Console.WriteLine("Using newest candidate: " + candidates[0]);
            return candidates[0];
        }

        private static void SearchDirectoryRecursively(string currentDir, string searchPattern, List<string> results, int currentDepth)
        {
            if (currentDepth > MaxSearchDepth)
            {
                Console.WriteLine("Warning: Maximum search depth reached at: " + currentDir);
                return;
            }

            try
            {
                Console.WriteLine("Searching directory (depth " + currentDepth + "): " + currentDir);

                string[] files = Directory.GetFiles(currentDir, searchPattern, SearchOption.TopDirectoryOnly);
                foreach (string file in files)
                {
                    Console.WriteLine("  Found: " + file);
                    results.Add(file);
                }

                string[] subDirs = Directory.GetDirectories(currentDir);
                foreach (string subDir in subDirs)
                {
                    try
                    {
                        SearchDirectoryRecursively(subDir, searchPattern, results, currentDepth + 1);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("  Skipping (access denied): " + subDir);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("  Skipping (error): " + subDir + " - " + ex.Message);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Access denied to directory: " + currentDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error searching directory: " + currentDir + " - " + ex.Message);
            }
        }

        private class DllFileComparer : IComparer<string>
        {
            public int Compare(string a, string b)
            {
                DateTime timeA = File.GetLastWriteTime(a);
                DateTime timeB = File.GetLastWriteTime(b);
                return timeB.CompareTo(timeA);
            }
        }

        private static string DetectConfiguration(string dllPath)
        {
            string lowerPath = dllPath.ToLowerInvariant();

            if (lowerPath.Contains("\\dll-debug\\") || lowerPath.Contains("/dll-debug/"))
                return "Debug";

            if (lowerPath.Contains("\\dll-release\\") || lowerPath.Contains("/dll-release/"))
                return "Release";

            if (lowerPath.Contains("\\debug\\") || lowerPath.Contains("/debug/"))
                return "Debug";

            if (lowerPath.Contains("\\release\\") || lowerPath.Contains("/release/"))
                return "Release";

            return "Unknown";
        }

        private static string DetectMsBuildConfiguration(string projectDir)
        {
            Console.WriteLine("=== Detecting MSBuild Configuration ===");
            
            if (string.IsNullOrEmpty(projectDir))
            {
                Console.WriteLine("Project directory is null, cannot detect MSBuild config");
                return null;
            }

            DirectoryInfo dirInfo = new DirectoryInfo(projectDir);
            if (!dirInfo.Exists)
            {
                Console.WriteLine("Project directory does not exist: " + projectDir);
                return null;
            }

            // Method 1: Check for bin/Debug or bin/Release directories in the project
            string binPath = Path.Combine(projectDir, "bin");
            if (Directory.Exists(binPath))
            {
                string debugPath = Path.Combine(binPath, "Debug");
                string releasePath = Path.Combine(binPath, "Release");

                // Check which directory has more recent files
                if (Directory.Exists(debugPath) && Directory.Exists(releasePath))
                {
                    DateTime debugTime = GetLatestFileTime(debugPath);
                    DateTime releaseTime = GetLatestFileTime(releasePath);

                    if (debugTime > releaseTime)
                    {
                        Console.WriteLine("Detected Debug configuration (more recent activity in bin/Debug)");
                        return "Debug";
                    }
                    else
                    {
                        Console.WriteLine("Detected Release configuration (more recent activity in bin/Release)");
                        return "Release";
                    }
                }
                else if (Directory.Exists(debugPath))
                {
                    Console.WriteLine("Detected Debug configuration (bin/Debug exists)");
                    return "Debug";
                }
                else if (Directory.Exists(releasePath))
                {
                    Console.WriteLine("Detected Release configuration (bin/Release exists)");
                    return "Release";
                }
            }

            // Method 2: Check for obj/Debug or obj/Release directories
            string objPath = Path.Combine(projectDir, "obj");
            if (Directory.Exists(objPath))
            {
                string debugPath = Path.Combine(objPath, "Debug");
                string releasePath = Path.Combine(objPath, "Release");

                if (Directory.Exists(debugPath) && Directory.Exists(releasePath))
                {
                    DateTime debugTime = GetLatestFileTime(debugPath);
                    DateTime releaseTime = GetLatestFileTime(releasePath);

                    if (debugTime > releaseTime)
                    {
                        Console.WriteLine("Detected Debug configuration (more recent activity in obj/Debug)");
                        return "Debug";
                    }
                    else
                    {
                        Console.WriteLine("Detected Release configuration (more recent activity in obj/Release)");
                        return "Release";
                    }
                }
                else if (Directory.Exists(debugPath))
                {
                    Console.WriteLine("Detected Debug configuration (obj/Debug exists)");
                    return "Debug";
                }
                else if (Directory.Exists(releasePath))
                {
                    Console.WriteLine("Detected Release configuration (obj/Release exists)");
                    return "Release";
                }
            }

            // Method 3: Check for .csproj file and examine Configuration property
            string[] csprojFiles = Directory.GetFiles(projectDir, "*.csproj");
            if (csprojFiles.Length > 0)
            {
                string csprojFile = csprojFiles[0];
                Console.WriteLine("Examining .csproj file: " + csprojFile);
                
                try
                {
                    string csprojContent = File.ReadAllText(csprojFile);
                    
                    // Look for default Configuration in PropertyGroup
                    if (csprojContent.ToLowerInvariant().Contains("<configuration>debug</configuration>"))
                    {
                        Console.WriteLine("Detected Debug configuration from .csproj");
                        return "Debug";
                    }
                    else if (csprojContent.ToLowerInvariant().Contains("<configuration>release</configuration>"))
                    {
                        Console.WriteLine("Detected Release configuration from .csproj");
                        return "Release";
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error reading .csproj file: " + ex.Message);
                }
            }

            // Method 4: Check environment variables
            string configEnv = Environment.GetEnvironmentVariable("Configuration");
            if (!string.IsNullOrEmpty(configEnv))
            {
                Console.WriteLine("Found Configuration environment variable: " + configEnv);
                return configEnv;
            }

            string buildConfigEnv = Environment.GetEnvironmentVariable("BuildConfiguration");
            if (!string.IsNullOrEmpty(buildConfigEnv))
            {
                Console.WriteLine("Found BuildConfiguration environment variable: " + buildConfigEnv);
                return buildConfigEnv;
            }

            Console.WriteLine("Could not auto-detect MSBuild configuration");
            return null;
        }

        private static DateTime GetLatestFileTime(string directory)
        {
            DateTime latestTime = DateTime.MinValue;
            
            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(directory);
                foreach (FileInfo file in dirInfo.GetFiles("*.*", SearchOption.AllDirectories))
                {
                    if (file.LastWriteTime > latestTime)
                    {
                        latestTime = file.LastWriteTime;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error getting latest file time for " + directory + ": " + ex.Message);
            }
            
            return latestTime;
        }

        private static string LocateOutputDirectory(string projectDir, string configuration)
        {
            Console.WriteLine("=== Locating output directory ===");
            Console.WriteLine("Target configuration: " + (configuration ?? "(not specified)"));

            if (string.IsNullOrEmpty(projectDir))
                projectDir = Environment.CurrentDirectory;

            projectDir = ValidateAndResolvePath(projectDir, "LocateOutputDirectory start");
            if (string.IsNullOrEmpty(projectDir))
            {
                Console.WriteLine("Invalid project directory, using current directory");
                projectDir = Environment.CurrentDirectory;
            }

            DirectoryInfo current = new DirectoryInfo(projectDir);
            int levelsWalked = 0;

            Console.WriteLine("Starting search from: " + current.FullName);
            Console.WriteLine("Will walk up " + MaxUpwardWalkLevels + " levels maximum");

            while (current != null && levelsWalked < MaxUpwardWalkLevels)
            {
                Console.WriteLine("Level " + levelsWalked + ": Checking " + current.FullName);

                try
                {
                    string[] searchPatterns = { "HandlerGui", "Rust9xWindowsAuth" };

                    foreach (string pattern in searchPatterns)
                    {
                        string projectPath = Path.Combine(current.FullName, pattern);
                        if (Directory.Exists(projectPath))
                        {
                            Console.WriteLine("Found project: " + projectPath);

                            string binPath = Path.Combine(projectPath, "bin");
                            if (Directory.Exists(binPath))
                            {
                                // Priority 1: Use specified configuration if provided
                                if (!string.IsNullOrEmpty(configuration))
                                {
                                    string configPath = Path.Combine(binPath, configuration);
                                    if (Directory.Exists(configPath))
                                    {
                                        Console.WriteLine("Found output directory matching configuration: " + configPath);
                                        return ValidateAndResolvePath(configPath, "Found config output");
                                    }
                                    else
                                    {
                                        Console.WriteLine("Configuration-specific directory not found: " + configPath);
                                    }
                                }

                                // Priority 2: Try to auto-detect based on most recent activity
                                string debugPath = Path.Combine(binPath, "Debug");
                                string releasePath = Path.Combine(binPath, "Release");

                                if (Directory.Exists(debugPath) && Directory.Exists(releasePath))
                                {
                                    DateTime debugTime = GetLatestFileTime(debugPath);
                                    DateTime releaseTime = GetLatestFileTime(releasePath);

                                    if (debugTime > releaseTime)
                                    {
                                        Console.WriteLine("Auto-detected Debug configuration (more recent activity)");
                                        return ValidateAndResolvePath(debugPath, "Auto-detected Debug output");
                                    }
                                    else
                                    {
                                        Console.WriteLine("Auto-detected Release configuration (more recent activity)");
                                        return ValidateAndResolvePath(releasePath, "Auto-detected Release output");
                                    }
                                }

                                // Priority 3: Fall back to available directories
                                if (Directory.Exists(debugPath))
                                {
                                    Console.WriteLine("Using Debug output (fallback): " + debugPath);
                                    return ValidateAndResolvePath(debugPath, "Found Debug output");
                                }

                                if (Directory.Exists(releasePath))
                                {
                                    Console.WriteLine("Using Release output (fallback): " + releasePath);
                                    return ValidateAndResolvePath(releasePath, "Found Release output");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error checking directory: " + ex.Message);
                }

                current = current.Parent;
                levelsWalked++;

                if (current == null)
                {
                    Console.WriteLine("Reached filesystem root, stopping search");
                    break;
                }
            }

            Console.WriteLine("Output directory not found after walking " + levelsWalked + " levels");
            return null;
        }

        private static void CopyDirectoryRecursive(string sourceDir, string destDir, bool ignorePdb)
        {
            Console.WriteLine("=== Copying directory recursively ===");
            Console.WriteLine("Source: " + sourceDir);
            Console.WriteLine("Destination: " + destDir);
            Console.WriteLine();

            if (!Directory.Exists(sourceDir))
            {
                Console.WriteLine("Source directory does not exist: " + sourceDir);
                return;
            }

            if (!Directory.Exists(destDir))
            {
                Directory.CreateDirectory(destDir);
            }

            CopyDirectoryRecursiveInternal(sourceDir, destDir, ignorePdb, 0);

            Console.WriteLine("Recursive copy complete.");
        }

        private static void CopyDirectoryRecursiveInternal(string sourceDir, string destDir, bool ignorePdb, int currentDepth)
        {
            if (currentDepth > MaxSearchDepth)
            {
                Console.WriteLine("Warning: Maximum search depth reached at: " + sourceDir);
                return;
            }

            string[] files = Directory.GetFiles(sourceDir);
            foreach (string file in files)
            {
                string fileName = Path.GetFileName(file);
                string lowerFileName = fileName.ToLowerInvariant();

                if (ignorePdb && lowerFileName.EndsWith(".pdb"))
                {
                    Console.WriteLine("Skipping PDB: " + fileName);
                    continue;
                }

                string destFile = Path.Combine(destDir, fileName);
                CopyFileWithVerification(file, destFile);
            }

            string[] subDirs = Directory.GetDirectories(sourceDir);
            foreach (string subDir in subDirs)
            {
                string subDirName = Path.GetFileName(subDir);
                string destSubDir = Path.Combine(destDir, subDirName);

                if (!Directory.Exists(destSubDir))
                {
                    Directory.CreateDirectory(destSubDir);
                }

                CopyDirectoryRecursiveInternal(subDir, destSubDir, ignorePdb, currentDepth + 1);
            }
        }

        private static void CopyFileWithVerification(string source, string destination)
        {
            string destDir = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
            {
                Directory.CreateDirectory(destDir);
            }

            Console.WriteLine("Copy: " + source);
            Console.WriteLine("  -> " + destination);

            File.Copy(source, destination, true);

            if (!File.Exists(destination))
            {
                throw new IOException("Copy verification failed: destination file does not exist");
            }

            FileInfo sourceInfo = new FileInfo(source);
            FileInfo destInfo = new FileInfo(destination);

            if (sourceInfo.Length != destInfo.Length)
            {
                throw new IOException("Copy verification failed: size mismatch (source: " + sourceInfo.Length + ", dest: " + destInfo.Length + ")");
            }

            TimeSpan timeDiff = sourceInfo.LastWriteTime - destInfo.LastWriteTime;
            if (timeDiff.TotalSeconds < 0)
                timeDiff = TimeSpan.FromMilliseconds(-timeDiff.TotalMilliseconds);

            if (timeDiff.TotalSeconds > 2)
            {
                Console.WriteLine("Warning: Timestamp difference: " + timeDiff.TotalSeconds + " seconds");
            }

            Console.WriteLine("  Verified: " + destInfo.Length + " bytes");
        }
    }
}