use std::{borrow::ToOwned, string::String, vec::Vec};

use rusqlite::Connection;

#[derive(Debug)]
pub(crate) struct User {
    pub(crate) user_id: Vec<u8>,
    pub(crate) user_name: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Transport {
    USB = 0x01,
    NFC = 0x02,
    BLE = 0x04,
    INTERNAL = 0x08,
}

impl Transport {
    pub(crate) fn from_bits(bits: usize) -> Vec<Self> {
        let mut result = Vec::new();
        for &(flag, transport) in &[
            (0x01, Transport::USB),
            (0x02, Transport::NFC),
            (0x04, Transport::BLE),
            (0x08, Transport::INTERNAL),
        ] {
            if bits & flag != 0 {
                result.push(transport);
            }
        }
        result
    }
}

#[derive(Debug)]
pub(crate) struct Credentials {
    pub(crate) cred_id: Vec<u8>,
    pub(crate) cred_type: String,
    pub(crate) transports: Vec<Transport>,
    pub(crate) rp_id: String,
    pub(crate) pubkey_cose: Vec<u8>,
    pub(crate) sign_count: usize,
    pub(crate) user_id: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct FidoDB {
    pub(crate) conn: Connection
}

impl FidoDB {
    pub(crate) fn new(db: String) -> Self {
        let conn = Connection::open("./fido.db3").unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                user_id BLOB PRIMARY KEY,
                user_name TEXT NOT NULL UNIQUE
            );",
        ()
        ).unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS credentials (
                cred_id BLOB PRIMARY KEY,
                type TEXT NOT NULL,
                transports INTEGER NOT NULL,
                rp_id TEXT NOT NULL,
                pubkey_cose BLOB NOT NULL,
                sign_count INTEGER NOT NULL,
                user_id BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );",
        ()
        ).unwrap();

        Self { conn }
    }

    pub(crate) fn get_user_id(self, user_name: String) -> Result<usize, rusqlite::Error> {
        self.conn.query_row(
            "SELECT user_id FROM users WHERE user_name = ?1", 
            (user_name,), 
            |row| row.get(0)
        )
    }

    pub(crate) fn get_credential(self, user_id: Vec<u8>, cred_id: Vec<u8>) -> Result<Credentials, rusqlite::Error> {
        self.conn.query_row(
            "SELECT type, transports, pubkey_cose, sign_count, rp_id FROM credentials WHERE user_id = ?1 AND cred_id = ?2",
            (user_id.clone(), cred_id.clone()), 
            |row| Ok(Credentials{
                cred_id,
                cred_type: row.get(0)?,
                transports: Transport::from_bits(row.get(1)?),
                rp_id: row.get(4)?,
                pubkey_cose: row.get(2)?,
                sign_count: row.get(3)?,
                user_id
            })
        )
    }

    pub(crate) fn update_sign_count(self, sign_count: usize, cred_id: Vec<u8>) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "UPDATE credentials SET sign_count = ?1 WHERE cred_id = ?2",
            (sign_count, cred_id)
        ).map(|_| ())
    }

    pub(crate) fn get_excluded_credentials(self, user_id: Vec<u8>) -> Result<Vec<Credentials>, rusqlite::Error> {
        let mut stmt = self.conn.prepare("SELECT cred_id, type, transports FROM credentials WHERE user_id == ?")?;
        let credentials_iter = stmt.query_map((user_id,), |row| {
            Ok(Credentials {
                cred_id: row.get(0)?,
                cred_type: row.get(1)?,
                transports: Transport::from_bits(row.get(2)?),
                rp_id: "".to_owned(),
                pubkey_cose: Vec::new(),
                sign_count: 0,
                user_id: Vec::new()
            })
        })?;

        credentials_iter.collect()
    }

    pub(crate) fn add_credentials(self, user: User, credential: Credentials) -> Result<(), rusqlite::Error> {
        let user_exists = self.conn.query_row(
            "SELECT user_id FROM users WHERE user_id = ?",
            (user.user_id.clone(), ), 
            |_| Ok(())
        ).is_ok();
        if !user_exists {
            self.conn.execute(
                "INSERT INTO users (user_id, user_name) VALUES (?1, ?2)",
                (user.user_id.clone(), user.user_name)
            )?;
        }

        self.conn.execute(
            "INSERT INTO credentials (user_id, rp_id, type, cred_id, pubkey_cose, sign_count, transports) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (user.user_id.clone(), credential.rp_id, credential.cred_type, credential.cred_id, credential.pubkey_cose, credential.sign_count, 0)
        )?;

        Ok(())
    }
}