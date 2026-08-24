use serde::{Serialize, Deserialize};

/// The NightLink logo shown on the startup screen (and anywhere else the
/// banner is displayed).
pub const LOGO: &str = r#"__/\\\\\_____/\\\__/\\\\\\\\\\\_____/\\\\\\\\\\\\__/\\\________/\\\__/\\\\\\\\\\\\\\\____________/\\\______________/\\\\\\\\\\\__/\\\\\_____/\\\__/\\\________/\\\__
 _\/\\\\\\___\/\\\_\/////\\\///____/\\\//////////__\/\\\_______\/\\\_\///////\\\/////____________\/\\\_____________\/////\\\///__\/\\\\\\___\/\\\_\/\\\_____/\\\//__
  _\/\\\/\\\__\/\\\_____\/\\\______/\\\_____________\/\\\_______\/\\\_______\/\\\_________________\/\\\_________________\/\\\_____\/\\\/\\\__\/\\\_\/\\\__/\\\//_____
   _\/\\\//\\\_\/\\\_____\/\\\_____\/\\\____/\\\\\\\_\/\\\\\\\\\\\\\\\_______\/\\\_________________\/\\\_________________\/\\\_____\/\\\//\\\_\/\\\_\/\\\\\\//\\\_____
    _\/\\\\//\\\\/\\\_____\/\\\_____\/\\\___\/////\\\_\/\\\/////////\\\_______\/\\\_________________\/\\\_________________\/\\\_____\/\\\\//\\\\/\\\_\/\\\//_\//\\\____
     _\/\\\_\//\\\/\\\_____\/\\\_____\/\\\_______\/\\\_\/\\\_______\/\\\_______\/\\\_________________\/\\\_________________\/\\\_____\/\\\_\//\\\/\\\_\/\\\____\//\\\___
      _\/\\\__\//\\\\\\_____\/\\\_____\/\\\_______\/\\\_\/\\\_______\/\\\_______\/\\\_________________\/\\\_________________\/\\\_____\/\\\__\//\\\\\\_\/\\\_____\//\\\__
       _\/\\\___\//\\\\\__/\\\\\\\\\\\_\//\\\\\\\\\\\\/__\/\\\_______\/\\\_______\/\\\_________________\/\\\\\\\\\\\\\\\__/\\\\\\\\\\\_\/\\\___\//\\\\\_\/\\\______\//\\\_
        _\///_____\/////__\///////////___\////////////____\///________\///________\///__________________\///////////////__\///////////__\///_____\/////__\///________\///__"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Theme {
    Default,
    Matrix,
    Nord,
    Dracula,
    Mist,
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
            Theme::Mist => {
                // Blue haze: light text on dark blue-gray background
                print!("\x1B[38;2;224;224;255m\x1B[48;2;10;22;40m");
            }
        }
    }

    pub fn prompt(&self) -> String {
        match self {
            Theme::Default => "\x1B[36m[nite~]# \x1B[0m".to_string(), // Cyan
            Theme::Matrix => "\x1B[32m[nite~]# \x1B[0m".to_string(), // Green
            Theme::Nord => "\x1B[38;2;136;192;208m[nite~]# \x1B[0m".to_string(), // Nord4
            Theme::Dracula => "\x1B[38;2;248;248;242m[nite~]# \x1B[0m".to_string(), // Dracula fg
            Theme::Mist => "\x1B[38;2;107;142;255m[nite~]# \x1B[0m".to_string(), // Soft blue #6B8EFF
        }
    }

    pub fn log(&self, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[34m[nite] {}\x1B[0m", msg), // Blue
            Theme::Matrix => format!("\x1B[32m[nite] {}\x1B[0m", msg), // Green
            Theme::Nord => format!("\x1B[38;2;136;192;208m[nite] {}\x1B[0m", msg), // Nord4
            Theme::Dracula => format!("\x1B[38;2;189;147;249m[nite] {}\x1B[0m", msg), // Purple
            Theme::Mist => format!("\x1B[38;2;77;121;255m[nite] {}\x1B[0m", msg), // Accent blue #4D79FF
        }
    }

    pub fn error(&self, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[31m[nite] Error: {}\x1B[0m", msg), // Red
            Theme::Matrix => format!("\x1B[31m[nite] Error: {}\x1B[0m", msg), // Red
            Theme::Nord => format!("\x1B[38;2;191;97;106m[nite] Error: {}\x1B[0m", msg), // Nord11
            Theme::Dracula => format!("\x1B[38;2;255;85;85m[nite] Error: {}\x1B[0m", msg), // Red
            Theme::Mist => format!("\x1B[38;2;255;107;142m[nite] Error: {}\x1B[0m", msg), // Warm rose #FF6B8E
        }
    }

    pub fn user_msg(&self, alias: &str, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[33m[{}]: \x1B[0m{}", alias, msg), // Yellow alias
            Theme::Matrix => format!("\x1B[32m[{}]: \x1B[0m{}", alias, msg), // Green
            Theme::Nord => format!("\x1B[38;2;129;161;193m[{}]: \x1B[0m{}", alias, msg), // Nord9
            Theme::Dracula => format!("\x1B[38;2;255;121;198m[{}]: \x1B[0m{}", alias, msg), // Pink
            Theme::Mist => format!("\x1B[38;2;224;224;255m[{}]: \x1B[0m{}", alias, msg), // Light #E0E0FF
        }
    }

    pub fn ascii_art(&self) -> String {
        let art = LOGO;
        match self {
            Theme::Default => art.to_string(),
            Theme::Matrix => format!("\x1B[32m{}\x1B[0m", art), // Green
            Theme::Nord => format!("\x1B[38;2;136;192;208m{}\x1B[0m", art), // Nord4
            Theme::Dracula => format!("\x1B[38;2;189;147;249m{}\x1B[0m", art), // Purple
            Theme::Mist => format!("\x1B[38;2;107;142;255m{}\x1B[0m", art), // Soft blue #6B8EFF
        }
    }
}