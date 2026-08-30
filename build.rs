fn main() {
    if cfg!(target_os = "windows") {
        // Embed assets/logo/NL.ico as the application icon so the executable
        // shows it in Explorer, the taskbar, Alt+Tab and file properties.
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/logo/NL.ico");
        if let Err(e) = res.compile() {
            panic!("failed to embed application icon: {}", e);
        }
    }
}