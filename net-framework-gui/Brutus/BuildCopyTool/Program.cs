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

                if (args.Length >= 2)
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

                Console.WriteLine("=== Path Resolution ===");

                projectDir = ValidateAndResolvePath(projectDir, "ProjectDir");
                string projectDirDisplay = projectDir;
                if (projectDirDisplay == null) projectDirDisplay = "(not provided)";
                Console.WriteLine("Project directory : " + projectDirDisplay);

                targetDir = ValidateAndResolvePath(targetDir, "TargetDir");
                string targetDirDisplay = targetDir;
                if (targetDirDisplay == null) targetDirDisplay = "(not provided)";
                Console.WriteLine("Target directory  : " + targetDirDisplay);
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

                string dllPath = LocateNewestDll(targetBaseDir);
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

                string configuration = DetectConfiguration(dllPath);
                Console.WriteLine("Detected configuration: " + configuration);
                Console.WriteLine();

                string runtimeDir = Path.GetDirectoryName(dllPath);
                Console.WriteLine("Runtime directory   : " + runtimeDir);
                Console.WriteLine();

                string destinationDir = targetDir;
                if (string.IsNullOrEmpty(destinationDir))
                {
                    destinationDir = LocateOutputDirectory(projectDir, configuration);
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
            Console.WriteLine("  BuildCopyTool.exe [projectDir] [targetDir]");
            Console.WriteLine();
            Console.WriteLine("Arguments:");
            Console.WriteLine("  projectDir - Optional. Project directory containing .csproj. Defaults to current directory.");
            Console.WriteLine("  targetDir  - Optional. Output directory for DLL and runtime files. Auto-detected if not provided.");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  BuildCopyTool.exe");
            Console.WriteLine("  BuildCopyTool.exe \"E:\\code\\rust9x-windows2000auth\\net-framework-gui\\Brutus\\HandlerGui\"");
            Console.WriteLine("  BuildCopyTool.exe \"$(ProjectDir)\" \"$(TargetDir)\"");
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

            while (current != null && levelsWalked < MaxUpwardWalkLevels)
            {
                Console.WriteLine("Checking: " + current.FullName);

                try
                {
                    string rustSrcPath = Path.Combine(current.FullName, "rust-src");
                    if (Directory.Exists(rustSrcPath))
                    {
                        Console.WriteLine("Found rust-src at: " + rustSrcPath);
                        return ValidateAndResolvePath(rustSrcPath, "Found rust-src");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error checking directory: " + ex.Message);
                }

                current = current.Parent;
                levelsWalked++;
            }

            Console.WriteLine("rust-src not found after walking " + levelsWalked + " levels");
            return null;
        }

        private static string LocateNewestDll(string searchRoot)
        {
            Console.WriteLine("=== Searching for " + DllName + " ===");
            Console.WriteLine("Search root: " + searchRoot);

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

            candidates.Sort(new DllFileComparer());

            int displayCount = 5;
            if (candidates.Count < displayCount)
                displayCount = candidates.Count;

            for (int i = 0; i < displayCount; i++)
            {
                FileInfo fi = new FileInfo(candidates[i]);
                Console.WriteLine("  [" + (i + 1) + "] " + candidates[i]);
                Console.WriteLine("       Date: " + fi.LastWriteTime + ", Size: " + fi.Length + " bytes");
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

        private static string LocateOutputDirectory(string projectDir, string configuration)
        {
            Console.WriteLine("=== Locating output directory ===");

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

            while (current != null && levelsWalked < MaxUpwardWalkLevels)
            {
                Console.WriteLine("Checking: " + current.FullName);

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
                                string configPath = Path.Combine(binPath, configuration);
                                if (Directory.Exists(configPath))
                                {
                                    Console.WriteLine("Found output directory: " + configPath);
                                    return ValidateAndResolvePath(configPath, "Found config output");
                                }

                                string debugPath = Path.Combine(binPath, "Debug");
                                string releasePath = Path.Combine(binPath, "Release");

                                if (Directory.Exists(debugPath))
                                {
                                    Console.WriteLine("Using Debug output: " + debugPath);
                                    return ValidateAndResolvePath(debugPath, "Found Debug output");
                                }

                                if (Directory.Exists(releasePath))
                                {
                                    Console.WriteLine("Using Release output: " + releasePath);
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