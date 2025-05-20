use std::vec::Vec;

use rusqlite::Connection;
use webauthn_rs::prelude::Passkey;

use crate::{lock::Mutex, sync::Arc};

#[derive(Debug)]
pub(crate) struct User {
    pub(crate) user_id: Vec<u8>,
    pub(crate) passkey: Passkey

}

#[derive(Debug, Clone)]
pub(crate) struct FidoDB {
    pub(crate) conn: Arc<Mutex<Connection>>
}

impl FidoDB {
    pub(crate) fn new(db_path: &str) -> Self {
        let conn = Connection::open(db_path).unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                user_id BLOB PRIMARY KEY,
                passkey BLOB NOT NULL UNIQUE
            );",
        ()
        ).unwrap();

        let conn = Arc::new(Mutex::new(conn));
        Self { conn }
    }

    pub(crate) fn add_user(&self, user: User) -> Result<(), rusqlite::Error> {
        let db = self.conn.lock().unwrap();
        let user_exists = db.query_row(
            "SELECT user_id FROM users WHERE user_id = ?",
            (user.user_id.clone(), ), 
            |_| Ok(())
        ).is_ok();

        if user_exists {
            return Err(rusqlite::Error::ExecuteReturnedResults);
        }

        let passkey_blob = serde_cbor::to_vec(&user.passkey).unwrap();

        db.execute(
            "INSERT INTO users (user_id, passkey) VALUES (?1, ?2)",
            (user.user_id.clone(), passkey_blob)
        )?;

        Ok(())
    }

    pub(crate) fn get_passkey(&self, user_id: Vec<u8>) -> Result<Passkey, rusqlite::Error> {
        let db = self.conn.lock().unwrap();

        let passkey_blob: Vec<u8> = db.query_row(
            "SELECT passkey FROM users WHERE user_id = ?",
            (user_id,),
            |row| row.get(0)
        )?;

        serde_cbor::from_slice(&passkey_blob).map_err(|_| rusqlite::Error::InvalidQuery)
    }
}