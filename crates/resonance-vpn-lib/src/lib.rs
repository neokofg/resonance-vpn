pub mod config;
pub mod deploy;
pub mod routing;
pub mod tls;
pub mod tunnel;

pub fn dirs_home() -> String {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string())
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
    }
}
