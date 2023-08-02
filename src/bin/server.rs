#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde;

use rocket::serde::Deserialize;
use base64::Engine;

struct Error {
    status: rocket::http::Status,
    message: String
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        rocket::Response::build_from(self.message.respond_to(request).unwrap())
            .status(self.status)
            .ok()
    }
}

#[derive(Debug, Deserialize)]
struct AddChainInputs {
    chain: Vec<String>
}

#[derive(Debug, Serialize)]
struct AddChainOutputs {
    sct_version: u64,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String
}

impl AddChainInputs {
    fn to_certs(&self) -> Result<ChainCerts, Error> {
        let mut certs = Vec::new();
        for cert in &self.chain {
            let cert_bytes = match base64::engine::general_purpose::STANDARD.decode(cert) {
                Ok(bytes) => bytes,
                Err(e) => return Err(Error {
                    status: rocket::http::Status::BadRequest,
                    message: format!("Invalid base64: {}", e)
                })
            };
            let cert = openssl::x509::X509::from_der(&cert_bytes).map_err(|e| Error {
                status: rocket::http::Status::BadRequest,
                message: format!("Invalid certificate: {}", e)
            })?;
            certs.push(cert);
        }
        Ok(ChainCerts(certs))
    }
}

#[derive(Debug)]
struct ChainCerts(Vec<openssl::x509::X509>);

impl ChainCerts {
    fn check_acceptance(&mut self, config: &AppConfig) -> Result<(), Error> {
        let mut last_cert = None;
        for cert in &self.0 {
            if let Some(last_cert) = last_cert {
                if cert.issued(last_cert) != openssl::x509::X509VerifyResult::OK {
                    return Err(Error {
                        status: rocket::http::Status::BadRequest,
                        message: format!("Certificate not issued by previous certificate")
                    });
                }
            }
            last_cert = Some(cert);
        }
        if last_cert.is_none() {
            return Err(Error {
                status: rocket::http::Status::BadRequest,
                message: format!("No certificates provided")
            });
        }
        let last_cert = last_cert.unwrap();
        let first_cert = &self.0[0];

        if first_cert.not_before() < config.expiry_range_start ||
            first_cert.not_after() >= config.expiry_range_end {
            return Err(Error {
                status: rocket::http::Status::BadRequest,
                message: format!("Certificate outside of expiry range")
            });
        }

        let ca = last_cert.issuer_name();
        let possible_ca_certs = config.get_certs_for_issuer(ca);
        for possible_ca in possible_ca_certs {
            if possible_ca.issued(last_cert) == openssl::x509::X509VerifyResult::OK {
                if last_cert != possible_ca {
                    self.0.push(possible_ca.clone());
                }
                return Ok(());
            }
        }

        return Err(Error {
            status: rocket::http::Status::BadRequest,
            message: format!("Certificate not issued by an accepted root")
        });
    }
}

#[post("/ct/v1/add-chain", data = "<inputs>")]
async fn add_chain(
    inputs: rocket::serde::json::Json<AddChainInputs>,
    config: &rocket::State<AppConfig>,
    log: &rocket::State<carillon::log::Log>,
) -> Result<rocket::serde::json::Json<AddChainOutputs>, Error> {
    let mut certs = inputs.to_certs()?;
    certs.check_acceptance(config)?;

    let add_chain = carillon::log::AddChain {
        cert: carillon::log::AddChainCert::Cert(certs.0.remove(0)),
        issuer: certs.0[0].clone(),
        extra: certs.0
    };
    let add_chain_result = log.add_chain(add_chain).await.map_err(|e| {
        error!("Error adding chain: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error adding chain: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(AddChainOutputs {
        sct_version: 0,
        id: base64::engine::general_purpose::STANDARD.encode(add_chain_result.log_id),
        timestamp: add_chain_result.timestamp,
        extensions: "".to_string(),
        signature: base64::engine::general_purpose::STANDARD.encode(add_chain_result.signature)
    }))
}

#[post("/ct/v1/add-pre-chain", data = "<inputs>")]
async fn add_pre_chain(
    inputs: rocket::serde::json::Json<AddChainInputs>,
    config: &rocket::State<AppConfig>,
    log: &rocket::State<carillon::log::Log>,
) -> Result<rocket::serde::json::Json<AddChainOutputs>, Error> {
    let mut certs = inputs.to_certs()?;
    certs.check_acceptance(config)?;

    let add_chain = carillon::log::AddChain {
        cert: carillon::log::AddChainCert::PreCert(certs.0.remove(0)),
        issuer: certs.0[0].clone(),
        extra: certs.0
    };
    let add_chain_result = log.add_chain(add_chain).await.map_err(|e| {
        error!("Error adding chain: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error adding chain: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(AddChainOutputs {
        sct_version: 0,
        id: base64::engine::general_purpose::STANDARD.encode(add_chain_result.log_id),
        timestamp: add_chain_result.timestamp,
        extensions: "".to_string(),
        signature: base64::engine::general_purpose::STANDARD.encode(add_chain_result.signature)
    }))
}

#[derive(Debug, Serialize)]
struct GetSTHOutputs {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

#[get("/ct/v1/get-sth")]
async fn get_sth(
    log: &rocket::State<carillon::log::Log>,
) -> Result<rocket::serde::json::Json<GetSTHOutputs>, Error> {
    let sth = log.get_sth().await.map_err(|e| {
        error!("Error getting STH: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error getting STH: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(GetSTHOutputs {
        tree_size: sth.tree_size,
        timestamp: sth.timestamp,
        sha256_root_hash: base64::engine::general_purpose::STANDARD.encode(sth.sha256_root_hash),
        tree_head_signature: base64::engine::general_purpose::STANDARD.encode(sth.tree_head_signature)
    }))
}

#[derive(Debug, Serialize)]
struct GetSTHConsistencyOutputs {
    consistency: Vec<String>
}

#[get("/ct/v1/get-sth-consistency?<first>&<second>")]
async fn get_sth_consistency(
    first: u64, second: u64,
    log: &rocket::State<carillon::log::Log>
) -> Result<rocket::serde::json::Json<GetSTHConsistencyOutputs>, Error> {
    let entries = log.get_consistency_proof(first, second).await.map_err(|e| {
        error!("Error getting entries: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error getting entries: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(GetSTHConsistencyOutputs {
        consistency: entries.into_iter().map(|e| base64::engine::general_purpose::STANDARD.encode(e)).collect()
    }))
}

#[derive(Debug, Serialize)]
struct GetProofByHashOutputs {
    leaf_index: u64,
    audit_path: Vec<String>,
}

#[get("/ct/v1/get-proof-by-hash?<hash>&<tree_size>")]
async fn get_proof_by_hash(
    hash: &str, tree_size: u64,
    log: &rocket::State<carillon::log::Log>
) -> Result<rocket::serde::json::Json<GetProofByHashOutputs>, Error> {
    let hash = base64::engine::general_purpose::STANDARD.decode(hash).map_err(|e| {
        Error {
            status: rocket::http::Status::BadRequest,
            message: format!("Invalid base64: {}", e)
        }
    })?;

    let entry = log.get_proof_by_hash(hash, tree_size).await.map_err(|e| {
        error!("Error getting proof by hash: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error getting proof by hash: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(GetProofByHashOutputs {
        leaf_index: entry.leaf_index,
        audit_path: entry.audit_path.into_iter().map(|e| base64::engine::general_purpose::STANDARD.encode(e)).collect()
    }))
}

#[derive(Debug, Serialize)]
struct GetEntriesOutputs {
    entries: Vec<Entry>
}

#[derive(Debug, Serialize)]
struct Entry {
    leaf_input: String,
    extra_data: String,
}

#[get("/ct/v1/get-entries?<start>&<end>")]
async fn get_entries(
    start: u64, end: u64,
    log: &rocket::State<carillon::log::Log>
) -> Result<rocket::serde::json::Json<GetEntriesOutputs>, Error> {
    let entries = log.get_entries(start, end).await.map_err(|e| {
        error!("Error getting entries: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error getting entries: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(GetEntriesOutputs {
        entries: entries.into_iter().map(|e| Entry {
            leaf_input: base64::engine::general_purpose::STANDARD.encode(e.leaf_input),
            extra_data: base64::engine::general_purpose::STANDARD.encode(e.extra_data)
        }).collect()
    }))
}

#[derive(Debug, Serialize)]
struct GetRootsOutputs {
    roots: Vec<String>
}

#[get("/ct/v1/get-roots")]
fn get_roots(config: &rocket::State<AppConfig>) -> Result<rocket::serde::json::Json<GetRootsOutputs>, Error> {
    config.certs.values().into_iter().flatten().map(|cert| {
        let der = cert.to_der().map_err(|e| Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Failed to convert certificate to DER: {}", e)
        })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(der))
    }).collect::<Result<Vec<_>, Error>>().map(|roots| {
        rocket::serde::json::Json(GetRootsOutputs {
            roots
        })
    })
}

#[derive(Debug, Serialize)]
struct GetEntryAndProofOutputs {
    leaf_input: String,
    extra_data: String,
    audit_path: Vec<String>,
}

#[get("/ct/v1/get-entry-and-proof?<leaf_index>&<tree_size>")]
async fn get_entry_and_proof(
    leaf_index: u64, tree_size: u64,
    log: &rocket::State<carillon::log::Log>
) -> Result<rocket::serde::json::Json<GetEntryAndProofOutputs>, Error> {
    let entry = log.get_entry_and_proof(leaf_index, tree_size).await.map_err(|e| {
        error!("Error getting entry and proof: {}", e);
        Error {
            status: rocket::http::Status::InternalServerError,
            message: format!("Error getting entry and proof: {}", e)
        }
    })?;

    Ok(rocket::serde::json::Json(GetEntryAndProofOutputs {
        leaf_input: base64::engine::general_purpose::STANDARD.encode(entry.entry.leaf_input),
        extra_data: base64::engine::general_purpose::STANDARD.encode(entry.entry.extra_data),
        audit_path: entry.audit_path.into_iter().map(|e| base64::engine::general_purpose::STANDARD.encode(e)).collect()
    }))
}



struct AppConfig {
    expiry_range_start: openssl::asn1::Asn1Time,
    expiry_range_end: openssl::asn1::Asn1Time,
    certs: std::collections::HashMap<Vec<u8>, Vec<openssl::x509::X509>>,
}

impl AppConfig {
    fn get_certs_for_issuer(&self, issuer: &openssl::x509::X509NameRef) -> &[openssl::x509::X509] {
        let issuer = match issuer.to_der() {
            Ok(issuer) => issuer,
            Err(_) => return &[]
        };
        self.certs.get(issuer.as_slice()).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

#[launch]
fn rocket() -> _ {
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

    let cert_paths = std::fs::read_dir(config.certs_dir).expect("Unable to enumerate accepted roots");
    let mut certs = std::collections::HashMap::<Vec<u8>, Vec<openssl::x509::X509>>::new();

    for entry in cert_paths {
        let entry = entry.expect("Unable to read accepted root");
        let path = entry.path();
        if path.is_file() {
            let cert = openssl::x509::X509::from_pem(
                &std::fs::read(path).expect("Unable to read accepted root")
            ).expect("Unable to parse accepted root");
            let key = cert.subject_name().to_der().unwrap();
            certs.entry(key).or_default().push(cert);
        }
    }

    let app_config = AppConfig {
        expiry_range_start: openssl::asn1::Asn1Time::from_unix(config.expiry_range_start.timestamp()).unwrap(),
        expiry_range_end: openssl::asn1::Asn1Time::from_unix(config.expiry_range_end.timestamp()).unwrap(),
        certs,
    };

    rocket
        .manage(app_config)
        .manage(log)
        .mount("/", routes![
        add_chain,
        add_pre_chain,
        get_sth,
        get_sth_consistency,
        get_proof_by_hash,
        get_entries,
        get_roots,
        get_entry_and_proof
    ])
}