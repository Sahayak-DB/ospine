use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileConfig {
    pub target: Option<String>,
    pub ports: Option<String>,
    pub popular: Option<bool>,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub banner_bytes: Option<u32>,
    pub passive: Option<bool>,
    pub json: Option<bool>,
    pub open_only: Option<bool>,
    pub raw_banner: Option<bool>,
    pub save_file: Option<String>,
    pub max_connections: Option<usize>,
    pub rate: Option<u64>,
}

pub fn default_config_path() -> Option<PathBuf> {
    if let Some(proj) = directories::ProjectDirs::from("org", "ospine", "ospine") {
        let mut p = proj.config_dir().to_path_buf();
        p.push("config.toml");
        Some(p)
    } else {
        None
    }
}

pub fn load_config(path: Option<&Path>) -> io::Result<Option<FileConfig>> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => match default_config_path() {
            Some(p) => p,
            None => return Ok(None),
        },
    };
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let cfg: FileConfig = toml::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TOML parse error: {e}")))?;
    Ok(Some(cfg))
}

pub fn save_config(cfg: &FileConfig, path: Option<&Path>) -> io::Result<PathBuf> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_config_path().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no default config dir"))?,
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let toml_str = toml::to_string_pretty(cfg)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TOML serialize error: {e}")))?;
    fs::write(&path, toml_str)?;
    Ok(path)
}
