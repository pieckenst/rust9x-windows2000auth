use std::{
    collections::VecDeque,
    env,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
struct Vc80Identity {
    name: String,
    version: String,
    processor_architecture: String,
    public_key_token: String,
}

#[derive(Debug, Clone)]
struct Vc80Assembly {
    dir: PathBuf,
    identity: Vc80Identity,
    has_source_manifest: bool,
}

fn main() {
    if let Err(err) = run() {
        println!("cargo:warning=[Auth-Build] {err}");
        if is_windows_msvc() {
            panic!("{err}");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUST9X_VC80_SOURCE_DIR");
    println!("cargo:rerun-if-env-changed=RUST9X_COPY_FLAT_CRT");
}

fn run() -> Result<(), String> {
    if !is_windows_msvc() {
        return Ok(());
    }

    let assembly = locate_vc80_assembly()?;

    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|e| format!("OUT_DIR missing: {e}"))?);
    let target_dir = cargo_target_dir()?;
    let exe_name = env::var("CARGO_BIN_NAME").unwrap_or_else(|_| "rust9x_auth_test".to_string());
    let exe_manifest_name = format!("{exe_name}.exe.manifest");
    let exe_manifest_path = target_dir.join(&exe_manifest_name);

    let mut res = winres::WindowsResource::new();

    let version = (0u64 << 48) | (1u64 << 32) | (0u64 << 16) | 0u64;
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, version);
    res.set_version_info(winres::VersionInfo::FILEVERSION, version);
    res.set(
        "FileDescription",
        "Rust9x Linkage Library for Windows Authentication and Services for legacy systems",
    );
    res.set("ProductName", "Rust9x Windows Auth");
    res.set("OriginalFilename", "rust9x_windows_auth.dll");
    res.set("CompanyName", "Pieckenst");
    res.set("LegalCopyright", "Work of Pieckenst (c) 2026");

    if is_exe_build() {
        let app_manifest = render_app_manifest(&assembly.identity);
        fs::write(&exe_manifest_path, app_manifest)
            .map_err(|e| format!("failed to write {}: {e}", exe_manifest_path.display()))?;
        res.set_manifest_file(exe_manifest_path.to_string_lossy().as_ref());
        println!("cargo:warning=[Auth-Build] wrote app manifest {}", exe_manifest_path.display());
    }

    res.compile()
        .map_err(|e| format!("failed to compile Windows resources: {e}"))?;

    deploy_vc80_assembly(&assembly, &target_dir)?;

    // Also keep the generated app manifest as a build artifact for inspection
    let _ = fs::write(out_dir.join("app.manifest"), render_app_manifest(&assembly.identity));

    Ok(())
}

fn is_windows_msvc() -> bool {
    env::var("CARGO_CFG_WINDOWS").is_ok()
        && env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc"
}

fn is_exe_build() -> bool {
    env::var("CARGO_FEATURE_EXE_BUILD").is_ok()
        || env::var("CARGO_FEATURE_EXE_STATIC_BUILD").is_ok()
        || env::var("CARGO_BIN_NAME").is_ok()
}

fn locate_vc80_assembly() -> Result<Vc80Assembly, String> {
    let mut roots = Vec::<PathBuf>::new();

    if let Ok(dir) = env::var("RUST9X_VC80_SOURCE_DIR") {
        roots.push(PathBuf::from(dir));
    }

    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        roots.push(root.join("deps"));
        roots.push(root.join("third_party"));
    }

    roots.push(PathBuf::from(r"C:\Windows\WinSxS"));
    roots.push(PathBuf::from(r"C:\Windows\SysWOW64"));
    roots.push(PathBuf::from(r"C:\Windows\System32"));

    for root in roots {
        match find_vc80_in_tree(&root) {
            Ok(Some(found)) => return Ok(found),
            Ok(None) => continue,
            Err(err) => {
                println!("cargo:warning=[Auth-Build] {err}");
                continue;
            }
        }
    }

    Err("could not locate a VC80 assembly (need at least msvcr80.dll, and preferably Microsoft.VC80.CRT.manifest or a parseable WinSxS folder name)".to_string())
}

fn find_vc80_in_tree(root: &Path) -> Result<Option<Vc80Assembly>, String> {
    if !root.exists() {
        return Ok(None);
    }

    let mut stack = VecDeque::new();
    stack.push_back(root.to_path_buf());

    while let Some(dir) = stack.pop_back() {
        if !dir.is_dir() {
            continue;
        }

        if let Some(found) = inspect_vc80_dir(&dir)? {
            return Ok(Some(found));
        }

        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                if is_permission_error(&e.to_string()) {
                    println!("cargo:warning=[Auth-Build] skipped unreadable directory {}", dir.display());
                    continue;
                }
                return Err(format!("failed to read {}: {e}", dir.display()));
            }
        };

        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    if is_permission_error(&e.to_string()) {
                        println!("cargo:warning=[Auth-Build] skipped unreadable directory entry under {}", dir.display());
                        continue;
                    }
                    return Err(format!("failed to read entry in {}: {e}", dir.display()));
                }
            };

            let path = entry.path();
            if path.is_dir() {
                stack.push_back(path);
            }
        }
    }

    Ok(None)
}

fn inspect_vc80_dir(dir: &Path) -> Result<Option<Vc80Assembly>, String> {
    let dll = dir.join("msvcr80.dll");
    if !dll.exists() {
        return Ok(None);
    }

    let source_manifest = dir.join("Microsoft.VC80.CRT.manifest");
    let has_source_manifest = source_manifest.exists();

    if has_source_manifest {
        let identity = parse_vc80_identity(&source_manifest)?;
        return Ok(Some(Vc80Assembly {
            dir: dir.to_path_buf(),
            identity,
            has_source_manifest: true,
        }));
    }

    if let Some(identity) = parse_vc80_identity_from_folder_name(dir) {
        return Ok(Some(Vc80Assembly {
            dir: dir.to_path_buf(),
            identity,
            has_source_manifest: false,
        }));
    }

    Ok(None)
}

fn parse_vc80_identity(manifest_path: &Path) -> Result<Vc80Identity, String> {
    let text = fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed to read {}: {e}", manifest_path.display()))?;

    let assembly_identity = extract_tag(&text, "assemblyIdentity")
        .ok_or_else(|| format!("missing <assemblyIdentity ... /> in {}", manifest_path.display()))?;

    let name = extract_attr(&assembly_identity, "name")
        .ok_or_else(|| format!("missing name= in {}", manifest_path.display()))?;
    let version = extract_attr(&assembly_identity, "version")
        .ok_or_else(|| format!("missing version= in {}", manifest_path.display()))?;
    let processor_architecture = extract_attr(&assembly_identity, "processorArchitecture")
        .ok_or_else(|| format!("missing processorArchitecture= in {}", manifest_path.display()))?;
    let public_key_token = extract_attr(&assembly_identity, "publicKeyToken")
        .ok_or_else(|| format!("missing publicKeyToken= in {}", manifest_path.display()))?;

    Ok(Vc80Identity {
        name,
        version,
        processor_architecture,
        public_key_token,
    })
}

fn parse_vc80_identity_from_folder_name(dir: &Path) -> Option<Vc80Identity> {
    let folder = dir.file_name()?.to_string_lossy();
    let lower = folder.to_ascii_lowercase();

    if !lower.contains("microsoft.vc80.crt") {
        return None;
    }

    let parts: Vec<&str> = lower.split('_').collect();
    if parts.len() < 4 {
        return None;
    }

    let arch = normalize_arch(parts[0])?;
    let token = parts[2].to_string();
    let version = parts[3].to_string();

    if !looks_like_token(&token) || !looks_like_version(&version) {
        return None;
    }

    Some(Vc80Identity {
        name: "Microsoft.VC80.CRT".to_string(),
        version,
        processor_architecture: arch,
        public_key_token: token,
    })
}

fn normalize_arch(s: &str) -> Option<String> {
    match s {
        "x86" => Some("x86".to_string()),
        "amd64" => Some("amd64".to_string()),
        "ia64" => Some("ia64".to_string()),
        _ => None,
    }
}

fn looks_like_token(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_version(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_digit() || c == '.')
        && s.split('.').count() >= 4
}

fn render_app_manifest(identity: &Vc80Identity) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="{name}"
        version="{version}"
        processorArchitecture="{arch}"
        publicKeyToken="{token}" />
    </dependentAssembly>
  </dependency>
</assembly>
"#,
        name = identity.name,
        version = identity.version,
        arch = identity.processor_architecture,
        token = identity.public_key_token,
    )
}

fn deploy_vc80_assembly(assembly: &Vc80Assembly, target_dir: &Path) -> Result<(), String> {
    let assembly_dir = target_dir.join("Microsoft.VC80.CRT");
    fs::create_dir_all(&assembly_dir)
        .map_err(|e| format!("failed to create {}: {e}", assembly_dir.display()))?;

    let dlls = ["msvcr80.dll", "msvcp80.dll", "msvcm80.dll"];

    let mut copied_any = false;

    for file in dlls {
        let src = assembly.dir.join(file);
        if src.exists() {
            let dst = assembly_dir.join(file);
            fs::copy(&src, &dst)
                .map_err(|e| format!("failed to copy {} -> {}: {e}", src.display(), dst.display()))?;
            copied_any = true;
            println!("cargo:warning=[Auth-Build] copied {} -> {}", src.display(), dst.display());
        }
    }

    if assembly.has_source_manifest {
        let src_manifest = assembly.dir.join("Microsoft.VC80.CRT.manifest");
        let dst_manifest = assembly_dir.join("Microsoft.VC80.CRT.manifest");
        fs::copy(&src_manifest, &dst_manifest)
            .map_err(|e| format!("failed to copy {} -> {}: {e}", src_manifest.display(), dst_manifest.display()))?;
        println!("cargo:warning=[Auth-Build] copied manifest {} -> {}", src_manifest.display(), dst_manifest.display());
    } else {
        let dst_manifest = assembly_dir.join("Microsoft.VC80.CRT.manifest");
        let manifest = render_vc80_assembly_manifest(&assembly.identity, &["msvcr80.dll", "msvcp80.dll", "msvcm80.dll"]);
        fs::write(&dst_manifest, manifest)
            .map_err(|e| format!("failed to write generated manifest {}: {e}", dst_manifest.display()))?;
        println!(
            "cargo:warning=[Auth-Build] generated VC80 manifest from folder name at {}",
            dst_manifest.display()
        );
    }

    if !copied_any {
        return Err(format!(
            "found VC80 source at {}, but no runtime DLLs were copied",
            assembly.dir.display()
        ));
    }

    if should_copy_flat_fallback() {
        for file in dlls {
            let src = assembly.dir.join(file);
            if src.exists() {
                let dst = target_dir.join(file);
                fs::copy(&src, &dst)
                    .map_err(|e| format!("failed to copy flat fallback {} -> {}: {e}", src.display(), dst.display()))?;
                println!("cargo:warning=[Auth-Build] flat fallback {} -> {}", src.display(), dst.display());
            }
        }
    }

    Ok(())
}

fn render_vc80_assembly_manifest(identity: &Vc80Identity, files: &[&str]) -> String {
    let mut file_tags = String::new();
    for file in files {
        file_tags.push_str(&format!("  <file name=\"{}\" />\n", file));
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="{name}"
    version="{version}"
    processorArchitecture="{arch}"
    publicKeyToken="{token}" />
{file_tags}</assembly>
"#,
        name = identity.name,
        version = identity.version,
        arch = identity.processor_architecture,
        token = identity.public_key_token,
        file_tags = file_tags
    )
}

fn should_copy_flat_fallback() -> bool {
    match env::var("RUST9X_COPY_FLAT_CRT") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
        _ => true,
    }
}

fn cargo_target_dir() -> Result<PathBuf, String> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|e| format!("OUT_DIR missing: {e}"))?);
    let mut p = out_dir;

    for _ in 0..3 {
        if !p.pop() {
            return Err("failed to locate Cargo target directory from OUT_DIR".to_string());
        }
    }

    Ok(p)
}

fn is_permission_error(msg: &str) -> bool {
    msg.contains("Access is denied")
        || msg.contains("Отказано в доступе")
        || msg.contains("permission denied")
}

fn extract_tag(text: &str, tag: &str) -> Option<String> {
    let start_pat = format!("<{tag}");
    let start = text.find(&start_pat)?;
    let rest = &text[start..];
    let end = rest.find("/>")? + 2;
    Some(rest[..end].to_string())
}

fn extract_attr(tag_text: &str, attr: &str) -> Option<String> {
    let pat = format!(r#"{attr}=""#);
    let start = tag_text.find(&pat)? + pat.len();
    let rest = &tag_text[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}