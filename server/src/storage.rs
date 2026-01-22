use rusqlite::Connection;
use std::sync::{Mutex, OnceLock};

const DB_PATH: &str = "db.sqlite";

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();

// TODO: Revisar esquema
pub fn init(passphrase: &str) {
    let conn = Connection::open(DB_PATH).expect("Failed to open connection");

    // Convert passphrase to hex to avoid issues with special characters
    let hex_key = passphrase
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    conn.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";
         CREATE TABLE IF NOT EXISTS storage (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        hex_key
    ))
    .expect("Failed to initialize database");

    DB.set(Mutex::new(conn)).unwrap();
}

pub fn get_entry(key: &str) -> Option<String> {
    let db = DB.get().expect("Database not initialized");
    let conn = db.lock().unwrap();

    conn.query_row("SELECT value FROM storage WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .ok()
}

pub fn add_entry(key: &str, value: &str) -> bool {
    let db = DB.get().expect("Database not initialized");
    let conn = db.lock().unwrap();

    match conn.execute(
        "INSERT INTO storage (key, value) VALUES (?1, ?2)",
        (key, value),
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn update_entry(key: &str, value: &str) -> bool {
    let db = DB.get().expect("Database not initialized");
    let conn = db.lock().unwrap();

    match conn.execute("UPDATE storage SET value = ?1 WHERE key = ?2", (value, key)) {
        Ok(rows) => rows > 0,
        Err(_) => false,
    }
}

pub fn remove_entry(key: &str) -> bool {
    let db = DB.get().expect("Database not initialized");
    let conn = db.lock().unwrap();

    match conn.execute("DELETE FROM storage WHERE key = ?1", [key]) {
        Ok(rows) => rows > 0,
        Err(_) => false,
    }
}

pub fn get_all_entries() -> Vec<(String, String)> {
    let db = DB.get().expect("Database not initialized");
    let conn = db.lock().unwrap();

    let mut stmt = match conn.prepare("SELECT key, value FROM storage") {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };

    let entries = match stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    entries.filter_map(|e| e.ok()).collect()
}
