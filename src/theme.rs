use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Theme {
    Default,
    Matrix,
    Nord,
    Dracula,
}

impl Default for Theme {
    fn default() -> Self {
        Self::Default
    }
}

impl Theme {
    pub fn apply(&self) {
        match self {
            Theme::Default => {
                // Reset to default
                print!("\x1B[0m");
            }
            Theme::Matrix => {
                // Green on black (Matrix style)
                print!("\x1B[32m\x1B[40m");
            }
            Theme::Nord => {
                // Nord color scheme
                print!("\x1B[38;2;116;135;156m");
            }
            Theme::Dracula => {
                // Dracula color scheme
                print!("\x1B[38;2;248;248;242m\x1B[48;2;40;42;54m");
            }
        }
    }

    pub fn prompt(&self) -> String {
        match self {
            Theme::Default => "\x1B[36m[nite~]# \x1B[0m".to_string(), // Cyan
            Theme::Matrix => "\x1B[32m[nite~]# \x1B[0m".to_string(), // Green
            Theme::Nord => "\x1B[38;2;136;192;208m[nite~]# \x1B[0m".to_string(), // Nord4
            Theme::Dracula => "\x1B[38;2;248;248;242m[nite~]# \x1B[0m".to_string(), // Dracula fg
        }
    }

    pub fn log(&self, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[34m[nite] {}\x1B[0m", msg), // Blue
            Theme::Matrix => format!("\x1B[32m[nite] {}\x1B[0m", msg), // Green
            Theme::Nord => format!("\x1B[38;2;136;192;208m[nite] {}\x1B[0m", msg), // Nord4
            Theme::Dracula => format!("\x1B[38;2;189;147;249m[nite] {}\x1B[0m", msg), // Purple
        }
    }

    pub fn error(&self, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[31m[nite] Error: {}\x1B[0m", msg), // Red
            Theme::Matrix => format!("\x1B[31m[nite] Error: {}\x1B[0m", msg), // Red
            Theme::Nord => format!("\x1B[38;2;191;97;106m[nite] Error: {}\x1B[0m", msg), // Nord11
            Theme::Dracula => format!("\x1B[38;2;255;85;85m[nite] Error: {}\x1B[0m", msg), // Red
        }
    }

    pub fn user_msg(&self, alias: &str, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[33m[{}]: \x1B[0m{}", alias, msg), // Yellow alias
            Theme::Matrix => format!("\x1B[32m[{}]: \x1B[0m{}", alias, msg), // Green
            Theme::Nord => format!("\x1B[38;2;129;161;193m[{}]: \x1B[0m{}", alias, msg), // Nord9
            Theme::Dracula => format!("\x1B[38;2;255;121;198m[{}]: \x1B[0m{}", alias, msg), // Pink
        }
    }

    pub fn ascii_art(&self) -> String {
        let art = r#"
 ________   ___  ________  ___  ___  _________  ___       ___  ________   ___  __
|\   ___  \|\  \|\   ____\|\  \|\  \|\___   ___\\  \     |\  \|\   ___  \|\  \|\  \
 \ \  \\ \  \ \  \ \  \___|\ \  \\\  \|___ \  \_\ \  \    \ \  \ \  \\ \  \ \  \/  /|_
  \ \  \\ \  \ \  \ \  \  __\ \   __  \   \ \  \ \ \  \    \ \  \ \  \\ \  \ \   ___  \
   \ \  \\ \  \ \  \ \  \|\  \ \  \ \  \   \ \  \ \ \  \____\ \  \ \  \\ \  \ \  \\ \  \
    \ \__\\ \__\ \__\ \_______\ \__\ \__\   \ \__\ \ \_______\ \__\ \__\\ \__\ \__\\ \__\
     \|__| \|__|\|__|\|_______|\|__|\|__|    \|__|  \|_______|\|__|\|__| \|__|\|__| \|__|
"#;
        match self {
            Theme::Default => art.to_string(),
            Theme::Matrix => format!("\x1B[32m{}\x1B[0m", art), // Green
            Theme::Nord => format!("\x1B[38;2;136;192;208m{}\x1B[0m", art), // Nord4
            Theme::Dracula => format!("\x1B[38;2;189;147;249m{}\x1B[0m", art), // Purple
        }
    }
}
