use std::path::Path;

fn main() {
    if cfg!(target_os = "windows") {
        // Resolve an absolute path from the package root so rc.exe always
        // finds the icon, regardless of the working directory cargo uses.
        let icon_path = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("assets")
            .join("logo")
            .join("NL.ico")
            .canonicalize()
            .expect("Failed to find NL.ico at assets/logo/NL.ico");

        // canonicalize() yields a \\?\-prefixed path on Windows; strip that
        // prefix because rc.exe's preprocessor cannot handle it.
        let icon_path = icon_path.to_string_lossy();
        let icon_path = icon_path.strip_prefix(r"\\?\").unwrap_or(&icon_path);

        // Re-embed the icon whenever it (or this script) changes.
        println!("cargo:rerun-if-changed=assets/logo/NL.ico");
        println!("cargo:rerun-if-changed=build.rs");

        let mut res = winres::WindowsResource::new();
        res.set_icon(icon_path);
        if let Err(e) = res.compile() {
            panic!("failed to embed application icon: {}", e);
        }
    }
}