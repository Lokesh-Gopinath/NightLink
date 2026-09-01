use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate the Windows SDK resource compiler (rc.exe): prefer the pinned
/// SDK 10.0.28000.0, then the newest other installed Windows 10/11 SDK.
fn find_rc_exe() -> Option<PathBuf> {
    let pinned = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\rc.exe");
    if pinned.is_file() {
        return Some(pinned.to_path_buf());
    }
    let kits = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(kits)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with("10."))
                .unwrap_or(false)
                && p.join("x64").join("rc.exe").is_file()
        })
        .collect();
    candidates.sort();
    candidates.pop().map(|v| v.join("x64").join("rc.exe"))
}

fn main() {
    if cfg!(target_os = "windows") {
        // Re-run whenever the icon, the resource script or this script change.
        println!("cargo:rerun-if-changed=assets/logo/NL.ico");
        println!("cargo:rerun-if-changed=assets/logo/nite.rc");
        println!("cargo:rerun-if-changed=build.rs");

        let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let rc_dir = manifest.join("assets").join("logo");
        let rc_file = rc_dir.join("nite.rc");
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let target = std::env::var("TARGET").unwrap_or_default();
        let is_msvc = target.ends_with("-msvc");

        // Compile assets/logo/nite.rc (IDI_ICON1 ICON "NL.ico") and pass the
        // result DIRECTLY to the linker. Linking it directly (instead of via
        // a static library) is essential: archive members that define no
        // symbols are never pulled into the link, which silently dropped the
        // icon in previous releases.
        let compiled: Option<PathBuf> = if is_msvc {
            // MSVC: rc.exe -> .res, consumed natively by link.exe.
            find_rc_exe().and_then(|rc_exe| {
                let out_res = out_dir.join("nite.res");
                let ok = Command::new(&rc_exe)
                    .args(["/nologo", "/fo"])
                    .arg(&out_res)
                    .arg(&rc_file)
                    // CWD = the .rc folder so `ICON "NL.ico"` always resolves.
                    .current_dir(&rc_dir)
                    .status()
                    .map(|s| s.success() && out_res.is_file())
                    .unwrap_or(false);
                if ok {
                    Some(out_res)
                } else {
                    None
                }
            })
        } else {
            // GNU: the linker cannot consume rc.exe's .res format, so use
            // mingw windres to produce a COFF object instead.
            let out_obj = out_dir.join("nite_res.o");
            let ok = Command::new("windres")
                .arg(format!("-I{}", manifest.display()))
                .arg(&rc_file)
                .args(["-O", "coff", "-o"])
                .arg(&out_obj)
                .current_dir(&rc_dir)
                .status()
                .map(|s| s.success() && out_obj.is_file())
                .unwrap_or(false);
            if ok {
                Some(out_obj)
            } else {
                None
            }
        };

        if let Some(res) = compiled {
            let via = if is_msvc { "rc.exe" } else { "windres" };
            println!("cargo:rustc-link-arg={}", res.display());
            println!("cargo:warning=icon embedded via {} ({})", via, res.display());
            return;
        }
        println!(
            "cargo:warning=no resource compiler found; falling back to winres for icon embedding"
        );

        // Last-resort fallback: winres.
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/logo/NL.ico");
        if let Err(e) = res.compile() {
            panic!("failed to embed application icon: {}", e);
        }
    }
}