use rusqlite::{Connection, Result};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    pub id: i64,
    pub name: String,
    pub target_addr: String,
    pub is_hibernating: bool,
    pub status: String, // Derived field for frontend: 'active' or 'hibernated'
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        // Enable WAL mode
        conn.pragma_update(None, "journal_mode", "WAL")?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS backend_servers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                target_addr TEXT NOT NULL,
                is_hibernating BOOLEAN NOT NULL DEFAULT 1
            )",
            [],
        )?;

        // Insert dummy if empty
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM backend_servers", [], |row| row.get(0))?;
        if count == 0 {
            conn.execute(
                "INSERT INTO backend_servers (name, target_addr, is_hibernating) VALUES (?1, ?2, ?3)",
                ["Survival Server", "127.0.0.1:25566", "1"],
            )?;
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn get_servers(&self) -> std::result::Result<Vec<BackendServer>, String> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> std::result::Result<Vec<BackendServer>, String> {
            let conn = conn.lock().map_err(|e| e.to_string())?;
            let mut stmt = conn.prepare("SELECT id, name, target_addr, is_hibernating FROM backend_servers")
                .map_err(|e| e.to_string())?;
            let server_iter = stmt.query_map([], |row| {
                let is_hibernating: bool = row.get(3)?;
                Ok(BackendServer {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    target_addr: row.get(2)?,
                    is_hibernating,
                    status: if is_hibernating { "hibernated".to_string() } else { "active".to_string() },
                })
            }).map_err(|e| e.to_string())?;

            let mut servers = Vec::new();
            for server in server_iter {
                servers.push(server.map_err(|e| e.to_string())?);
            }
            Ok(servers)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn wake_server(&self, id: i64) -> std::result::Result<(), String> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
            let conn = conn.lock().map_err(|e| e.to_string())?;
            conn.execute(
                "UPDATE backend_servers SET is_hibernating = 0 WHERE id = ?1",
                [id],
            ).map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn add_server(&self, name: String, target_addr: String) -> std::result::Result<i64, String> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> std::result::Result<i64, String> {
            let conn = conn.lock().map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT INTO backend_servers (name, target_addr, is_hibernating) VALUES (?1, ?2, 1)",
                [&name, &target_addr],
            ).map_err(|e| e.to_string())?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn update_server(&self, id: i64, name: String, target_addr: String) -> std::result::Result<(), String> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
            let conn = conn.lock().map_err(|e| e.to_string())?;
            conn.execute(
                "UPDATE backend_servers SET name = ?1, target_addr = ?2 WHERE id = ?3",
                rusqlite::params![name, target_addr, id],
            ).map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn delete_server(&self, id: i64) -> std::result::Result<(), String> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
            let conn = conn.lock().map_err(|e| e.to_string())?;
            conn.execute(
                "DELETE FROM backend_servers WHERE id = ?1",
                [id],
            ).map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_initialization_and_queries() {
        let db = Database::new(":memory:").expect("Failed to initialize in-memory DB");
        let servers = db.get_servers().await.expect("Failed to query servers");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "Survival Server");
        assert_eq!(servers[0].status, "hibernated");
        assert!(servers[0].is_hibernating);

        // Wake server
        db.wake_server(servers[0].id).await.expect("Failed to wake server");
        let updated = db.get_servers().await.expect("Failed to query updated servers");
        assert_eq!(updated[0].status, "active");
        assert!(!updated[0].is_hibernating);
    }
}
