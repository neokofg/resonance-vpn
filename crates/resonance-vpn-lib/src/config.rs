use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub server: String,
    pub psk: String,
    pub dns: Option<Vec<String>>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
