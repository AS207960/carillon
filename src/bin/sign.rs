#[rocket::main]
async fn main() {
    let rocket = rocket::build();

    let config = rocket.figment().extract::<carillon::Config>().unwrap();

    let log_private_key_bytes = std::fs::read(config.log_private_key).expect("Unable to read log private key");
    let log_public_key_bytes = std::fs::read(config.log_public_key).expect("Unable to read log public key");

    let log_private_key = openssl::pkey::PKey::private_key_from_pem(&log_private_key_bytes).expect("Unable to parse log private key");
    let log_public_key = openssl::pkey::PKey::public_key_from_pem(&log_public_key_bytes).expect("Unable to parse log private key");

    let pool_config = diesel_async::pooled_connection::AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(
        config.database_url,
    );
    let log = carillon::log::Log {
        db_conn: diesel_async::pooled_connection::mobc::Pool::new(pool_config),
        storage: config.storage_dir,
        log_private_key,
        log_public_key
    };

    log.sign().await.expect("Unable to sign log");
}