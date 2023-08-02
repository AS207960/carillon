#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde;

pub mod log;
mod models;
mod schema;
mod openssl_c;

use chrono::prelude::*;

#[derive(Deserialize)]
pub struct Config {
    pub expiry_range_start: DateTime<Utc>,
    pub expiry_range_end: DateTime<Utc>,
    pub certs_dir: std::path::PathBuf,
    pub storage_dir: std::path::PathBuf,
    pub log_private_key: std::path::PathBuf,
    pub log_public_key: std::path::PathBuf,
    pub database_url: String
}