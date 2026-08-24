use serde::{Serialize, Deserialize};

/// The NightLink logo shown on the startup screen (and anywhere else the
/// banner is displayed).
pub const LOGO: &str = r#" __   __     __     ______     __  __     ______      __         __     __   __     __  __    
/\ "-.\ \   /\ \   /\  ___\   /\ \_\ \   /\__  _\    /\ \       /\ \   /\ "-.\ \   /\ \/ /    
\ \ \-.  \  \ \ \  \ \ \__ \  \ \  __ \  \/_/\ \/    \ \ \____  \ \ \  \ \ \-.  \  \ \  _"-.  
 \ \_\\"\_\  \ \_\  \ \_____\  \ \_\ \_\    \ \_\     \ \_____\  \ \_\  \ \_\\"\_\  \ \_\ \_\ 
  \/_/ \/_/   \/_/   \/_____/   \/_/\/_/     \/_/      \/_____/   \/_/   \/_/ \/_/   \/_/\/_/"#;

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
                // Blue haze: very light blue text on dark navy background
                print!("\x1B[38;2;224;242;254m\x1B[48;2;15;23;42m");
            }
        }
    }

    pub fn prompt(&self) -> String {
        match self {
            Theme::Default => "\x1B[36m[nite~]# \x1B[0m".to_string(), // Cyan
            Theme::Matrix => "\x1B[32m[nite~]# \x1B[0m".to_string(), // Green
            Theme::Nord => "\x1B[38;2;136;192;208m[nite~]# \x1B[0m".to_string(), // Nord4
            Theme::Dracula => "\x1B[38;2;248;248;242m[nite~]# \x1B[0m".to_string(), // Dracula fg
            Theme::Mist => "\x1B[38;2;175;222;227m[nite~]# \x1B[0m".to_string(), // Primary #AFDEE3
        }
    }

    pub fn log(&self, msg: &str) -> String {
        match self {
            Theme::Default => format!("\x1B[34m[nite] {}\x1B[0m", msg), // Blue
            Theme::Matrix => format!("\x1B[32m[nite] {}\x1B[0m", msg), // Green
            Theme::Nord => format!("\x1B[38;2;136;192;208m[nite] {}\x1B[0m", msg), // Nord4
            Theme::Dracula => format!("\x1B[38;2;189;147;249m[nite] {}\x1B[0m", msg), // Purple
            Theme::Mist => format!("\x1B[38;2;103;232;249m[nite] {}\x1B[0m", msg), // Accent cyan #67E8F9
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
            Theme::Mist => format!("\x1B[38;2;224;242;254m[{}]: \x1B[0m{}", alias, msg), // Text #E0F2FE
        }
    }

    pub fn ascii_art(&self) -> String {
        let art = LOGO;
        match self {
            Theme::Default => art.to_string(),
            Theme::Matrix => format!("\x1B[32m{}\x1B[0m", art), // Green
            Theme::Nord => format!("\x1B[38;2;136;192;208m{}\x1B[0m", art), // Nord4
            Theme::Dracula => format!("\x1B[38;2;189;147;249m{}\x1B[0m", art), // Purple
            Theme::Mist => format!("\x1B[38;2;175;222;227m{}\x1B[0m", art), // Primary #AFDEE3
        }
    }
}
