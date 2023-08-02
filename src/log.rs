use chrono::prelude::*;
use diesel::prelude::*;
use diesel_async::AsyncConnection;
use diesel_async::RunQueryDsl;
use foreign_types_shared::ForeignType;

lazy_static::lazy_static! {
    static ref POISON_OID: openssl::asn1::Asn1Object = {
        openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.11129.2.4.3").unwrap()
    };
}

pub struct Log {
    pub db_conn: diesel_async::pooled_connection::mobc::Pool<diesel_async::AsyncPgConnection>,
    pub log_public_key: openssl::pkey::PKey<openssl::pkey::Public>,
    pub log_private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    pub storage: std::path::PathBuf,
}

pub struct AddChain {
    pub cert: AddChainCert,
    pub issuer: openssl::x509::X509,
    pub extra: Vec<openssl::x509::X509>
}

pub enum AddChainCert {
    Cert(openssl::x509::X509),
    PreCert(openssl::x509::X509)
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum Version {
    V1 = 0,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum SignatureType {
    CertificateTimestamp = 0,
    TreeHash = 1,
}

#[repr(u16)]
#[derive(Copy, Clone)]
enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

struct SignedCertificateTimestampTBS {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    entry: LogEntry
}

enum LogEntry {
    ASN1Cert(Vec<u8>),
    PreCert {
        issuer_key_hash: [u8; 32],
        tbs_certificate: Vec<u8>
    }
}

impl SignedCertificateTimestampTBS {
    fn encode(&self) -> Vec<u8> {
        let log_entry_type = match &self.entry {
            LogEntry::ASN1Cert(_) => LogEntryType::X509Entry,
            LogEntry::PreCert { .. } => LogEntryType::PrecertEntry
        };

        let mut buf = Vec::new();
        buf.push(self.version as u8);
        buf.push(self.signature_type as u8);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&(log_entry_type as u16).to_be_bytes());
        buf.extend_from_slice(&self.entry.encode());
        buf.extend_from_slice(&[0u8, 0u8]);

        buf
    }
}

impl LogEntry {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match &self {
            LogEntry::ASN1Cert(cert) => {
                let len = cert.len() as u32;
                buf.extend_from_slice(&len.to_be_bytes()[1..4]);
                buf.extend_from_slice(&cert);
            }
            LogEntry::PreCert { issuer_key_hash, tbs_certificate } => {
                buf.extend_from_slice(issuer_key_hash.as_slice());
                let len = tbs_certificate.len() as u32;
                buf.extend_from_slice(&len.to_be_bytes()[1..4]);
                buf.extend_from_slice(&tbs_certificate);
            }
        }

        buf
    }
}

struct CertificateChain(Vec<Vec<u8>>);

impl CertificateChain {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8, 0u8, 0u8]);
        for cert in &self.0 {
            let len = cert.len() as u32;
            buf.extend_from_slice(&len.to_be_bytes()[1..4]);
            buf.extend_from_slice(cert);
        }

        let len = (buf.len() as u32 - 3).to_be_bytes();
        buf[0] = len[1];
        buf[1] = len[2];
        buf[2] = len[3];

        buf
    }
}

struct PreCertChainEntry {
    pre_certificate: Vec<u8>,
    pre_certificate_chain: CertificateChain
}

impl PreCertChainEntry {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let len = self.pre_certificate.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes()[1..4]);
        buf.extend_from_slice(&self.pre_certificate);
        buf.extend_from_slice(&self.pre_certificate_chain.encode());

        buf
    }
}

#[repr(u8)]
#[derive(Copy, Clone)]
#[allow(dead_code)]
enum HashAlgorithm {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
}

#[repr(u8)]
#[derive(Copy, Clone)]
#[allow(dead_code)]
enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
}

struct DigitallySigned {
    hash_alg: HashAlgorithm,
    signature_alg: SignatureAlgorithm,
    signature: Vec<u8>
}

impl DigitallySigned {
    fn sign(key: &openssl::pkey::PKeyRef<openssl::pkey::Private>, data: &[u8]) -> Result<DigitallySigned, String> {
        let sig_alg = match key.id() {
            openssl::pkey::Id::RSA => SignatureAlgorithm::RSA,
            openssl::pkey::Id::DSA => SignatureAlgorithm::DSA,
            openssl::pkey::Id::EC => SignatureAlgorithm::ECDSA,
            _ => return Err("Unsupported key type".to_string())
        };
        let mut signer = openssl::sign::Signer::new(
            openssl::hash::MessageDigest::sha512(), key
        ).map_err(|e| format!("Failed to create signer: {}", e))?;
        let sig = signer.sign_oneshot_to_vec(data)
            .map_err(|e| format!("Failed to sign data: {}", e))?;
        Ok(DigitallySigned {
            hash_alg: HashAlgorithm::SHA512,
            signature_alg: sig_alg,
            signature: sig
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.hash_alg as u8);
        buf.push(self.signature_alg as u8);
        let len = self.signature.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }
}

#[repr(u8)]
enum MerkleLeafType {
    TimestampedEntry = 0,
}

struct MerkleTreeLeaf {
    version: Version,
    leaf: MerkleLeaf,
}

enum MerkleLeaf {
    TimestampedEntry(TimestampedEntry)
}

struct TimestampedEntry {
    timestamp: u64,
    entry_type: LogEntryType,
    log_entry: Vec<u8>,
}

impl MerkleTreeLeaf {
    fn encode(&self) -> Vec<u8> {
        let leaf_type = match &self.leaf {
            MerkleLeaf::TimestampedEntry(_) => MerkleLeafType::TimestampedEntry
        };

        let mut buf = Vec::new();
        buf.push(self.version as u8);
        buf.push(leaf_type as u8);
        match &self.leaf {
            MerkleLeaf::TimestampedEntry(entry) => {
                buf.extend_from_slice(&entry.timestamp.to_be_bytes());
                buf.extend_from_slice(&(entry.entry_type as u16).to_be_bytes());
                buf.extend_from_slice(&entry.log_entry);
            }
        }
        buf.extend_from_slice(&[0u8, 0u8]);

        buf
    }
}

struct TreeHeadSignature {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    tree_size: u64,
    sha256_root_hash: Vec<u8>,
}

impl TreeHeadSignature {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version as u8);
        buf.push(self.signature_type as u8);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.tree_size.to_be_bytes());
        buf.extend_from_slice(&self.sha256_root_hash[0..32]);
        buf
    }
}

pub struct AddChainResult {
    pub log_id: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>
}

pub struct SignedTreeHead {
    pub tree_size: u64,
    pub timestamp: u64,
    pub sha256_root_hash: Vec<u8>,
    pub tree_head_signature: Vec<u8>
}

pub struct Entry {
    pub leaf_input: Vec<u8>,
    pub extra_data: Vec<u8>,
}

pub struct ProofByHashResult {
    pub leaf_index: u64,
    pub audit_path: Vec<Vec<u8>>,
}

pub struct EntryAndProofResult {
    pub entry: Entry,
    pub audit_path: Vec<Vec<u8>>,
}

impl Log {
    fn log_id(&self) -> [u8; 32] {
        openssl::sha::sha256(&self.log_public_key.public_key_to_der().unwrap())
    }

    fn store_blob(&self, data: &[u8]) -> Result<String, String> {
        let id = uuid::Uuid::new_v4();
        let path = self.storage.join(id.to_string());
        std::fs::write(path, data).map_err(|e| format!("Failed to write blob: {}", e))?;
        Ok(id.to_string())
    }

    fn get_blob(&self, id: &str) -> Result<Vec<u8>, String> {
        let path = self.storage.join(id);
        std::fs::read(path).map_err(|e| format!("Failed to read blob: {}", e))
    }

    fn delete_blob(&self, id: &str) -> Result<(), String> {
        let path = self.storage.join(id);
        std::fs::remove_file(path).map_err(|e| format!("Failed to delete blob: {}", e))
    }

    pub async fn add_chain(&self, chain: AddChain) -> Result<AddChainResult, String> {
        let timestamp: u64 = Utc::now().timestamp_millis() as u64;

        let chain_encoded = chain.extra.iter().map(|c| c.to_der()
            .map_err(|e| format!("Invalid certificate: {}", e)))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        let (entry, extra) = match &chain.cert {
            AddChainCert::Cert(cert) => {
                unsafe {
                    let poison_ext_loc = openssl_sys::X509_get_ext_by_OBJ(cert.as_ptr(), POISON_OID.as_ptr(), -1);
                    if poison_ext_loc != -1 {
                        return Err("Cert has poison extension".to_string());
                    }
                }

                (
                    LogEntry::ASN1Cert(cert.to_der().map_err(|e| format!("Invalid certificate: {}", e))?),
                    CertificateChain(chain_encoded).encode()
                )
            },
            AddChainCert::PreCert(cert) => {
                let pre_certificate = cert.to_der().map_err(|e| format!("Invalid precert: {}", e))?;

                let tbs_certificate = unsafe {
                    let poison_ext_loc = openssl_sys::X509_get_ext_by_OBJ(cert.as_ptr(), POISON_OID.as_ptr(), -1);
                    if poison_ext_loc < 0 {
                        return Err("Precert does not contain poison extension".to_string());
                    }
                    openssl_sys::X509_delete_ext(cert.as_ptr(), poison_ext_loc);
                    let tbs_len = crate::openssl_c::i2d_re_X509_tbs(cert.as_ptr(), std::ptr::null_mut());
                    if tbs_len < 0 {
                        return Err("Invalid precert".to_string());
                    }
                    let mut tbs_buf = vec![0u8; tbs_len as usize];
                    crate::openssl_c::i2d_re_X509_tbs(cert.as_ptr(), &mut tbs_buf.as_mut_ptr());
                    tbs_buf
                };
                let issuer_key = chain.issuer.public_key().map_err(|e| format!("Invalid precert issuer: {}", e))?
                    .public_key_to_der().map_err(|e| format!("Invalid precert issuer: {}", e))?;
                let issuer_key_hash = openssl::sha::sha256(&issuer_key);

                (
                    LogEntry::PreCert {
                        issuer_key_hash,
                        tbs_certificate,
                    },
                    PreCertChainEntry {
                        pre_certificate,
                        pre_certificate_chain: CertificateChain(chain_encoded)
                    }.encode()
                )
            }
        };

        let entry_id = self.store_blob(&entry.encode())?;
        let extra_data_id = self.store_blob(&extra)?;

        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;
        if let Err(err) = diesel::insert_into(crate::schema::to_be_included::table)
            .values(crate::models::ToBeIncluded {
                id: uuid::Uuid::new_v4(),
                timestamp: timestamp as i64,
                log_entry_type: match &chain.cert {
                    AddChainCert::Cert(_) => crate::models::LogEntryType::Cert,
                    AddChainCert::PreCert(_) => crate::models::LogEntryType::PreCert
                },
                entry_id,
                extra_data_id,
            }).execute(&mut conn).await {
            return Err(format!("Failed to insert into DB: {}", err));
        }

        let tbs = SignedCertificateTimestampTBS {
            version: Version::V1,
            signature_type: SignatureType::CertificateTimestamp,
            timestamp,
            entry
        };
        let tbs_bytes = tbs.encode();
        let tbs_signed = DigitallySigned::sign(&self.log_private_key, &tbs_bytes)?;
        let tbs_signed_bytes = tbs_signed.encode();

        Ok(AddChainResult {
            log_id: self.log_id(),
            timestamp,
            signature: tbs_signed_bytes
        })
    }

    pub async fn get_sth(&self) -> Result<SignedTreeHead, String> {
        let timestamp: u64 = Utc::now().timestamp_millis() as u64;
        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;

        let root_node = match crate::schema::tree::table.filter(
            crate::schema::tree::dsl::is_root.eq(true)
        ).first::<crate::models::Node>(&mut conn).await.optional() {
            Ok(Some(t)) => t,
            Ok(None) => crate::models::Node {
                id: Default::default(),
                tree_size: 0,
                min_seq: 0,
                max_seq: 0,
                left_child_id: None,
                right_child_id: None,
                is_root: true,
                hash: compute_sha256_hash(&[])?.to_vec(),
                entry_id: None,
            },
            Err(err) => return Err(format!("Failed to query DB: {}", err))
        };

        let tree_head_signature = TreeHeadSignature {
            version: Version::V1,
            signature_type: SignatureType::TreeHash,
            timestamp,
            tree_size: root_node.tree_size as u64,
            sha256_root_hash: root_node.hash.clone(),
        };
        let tree_head_signature_tbs = tree_head_signature.encode();
        let tree_head_signed = DigitallySigned::sign(&self.log_private_key, &tree_head_signature_tbs)?;

        let sth = SignedTreeHead {
            tree_size: root_node.tree_size as u64,
            timestamp,
            sha256_root_hash: root_node.hash,
            tree_head_signature: tree_head_signed.encode(),
        };

        Ok(sth)
    }

    pub async fn get_entries(&self, start: u64, end: u64) -> Result<Vec<Entry>, String> {
        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;

        let entries: Vec<crate::models::Entry> = crate::schema::entry::table.filter(
            crate::schema::entry::dsl::seq.ge(start as i64)
                .and(crate::schema::entry::dsl::seq.le(end as i64))
        ).get_results(&mut conn).await
            .map_err(|e| format!("Failed to query DB: {}", e))?;

        Ok(entries.into_iter().map(|e| {
            let leaf_bytes = self.get_blob(e.entry_id.as_str())?;
            let extra_bytes = self.get_blob(e.extra_data_id.as_str())?;
            Ok(Entry {
                leaf_input: leaf_bytes,
                extra_data: extra_bytes,
            })
        }).collect::<Result<Vec<_>, String>>()?)
    }

    pub async fn get_proof_by_hash(&self, hash: Vec<u8>, tree_size: u64) -> Result<ProofByHashResult, String> {
        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;

        let node = match crate::schema::tree::table.filter(
            crate::schema::tree::dsl::hash.eq(hash)
        ).first::<crate::models::Node>(&mut conn).await.optional() {
            Ok(Some(t)) => t,
            Ok(None) => return Err("No such node".to_string()),
            Err(err) => return Err(format!("Failed to query DB: {}", err))
        };
        let entry: crate::models::Entry = match crate::schema::entry::table.filter(
            crate::schema::entry::dsl::id.eq(node.entry_id.unwrap())
        ).get_result(&mut conn).await {
            Ok(t) => t,
            Err(err) => return Err(format!("Failed to query DB: {}", err))
        };

        let audit_path = self.get_audit_proof(&mut conn, entry.seq as u64, 0, tree_size).await?;

        Ok(ProofByHashResult {
            leaf_index: entry.seq as u64,
            audit_path,
        })
    }

    pub async fn get_entry_and_proof(&self, leaf_index: u64, tree_size: u64) -> Result<EntryAndProofResult, String> {
        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;

        let entry: crate::models::Entry = crate::schema::entry::table.filter(
            crate::schema::entry::dsl::seq.eq(leaf_index as i64)
        ).get_result(&mut conn).await.map_err(|e| format!("Failed to query DB: {}", e))?;
        let node: crate::models::Node = crate::schema::tree::table.filter(
            crate::schema::tree::dsl::entry_id.eq(entry.id)
        ).get_result(&mut conn).await.map_err(|e| format!("Failed to query DB: {}", e))?;

        let audit_path = self.get_audit_proof(&mut conn, node.max_seq as u64, 0, tree_size).await?;
        let leaf_bytes = self.get_blob(entry.entry_id.as_str())?;
        let extra_bytes = self.get_blob(entry.extra_data_id.as_str())?;

        Ok(EntryAndProofResult {
            entry: Entry {
                leaf_input: leaf_bytes,
                extra_data: extra_bytes,
            },
            audit_path,
        })
    }

    #[async_recursion::async_recursion]
    pub async fn get_audit_proof(
        &self, mut conn: &mut mobc::Connection<diesel_async::pooled_connection::AsyncDieselConnectionManager<diesel_async::AsyncPgConnection>>,
        node_id: u64, tree_start: u64, tree_end: u64
    ) -> Result<Vec<Vec<u8>>, String> {
        let tree_size = tree_end - tree_start;
        if node_id > tree_size {
            return Err(format!("Node index ({}) is greater than tree size ({})", node_id, tree_size));
        }

        if node_id == 1 && tree_size == 1 {
            return Ok(vec![]);
        }

        let k = 2u64.pow((((tree_size - 1) as f64).log(2.0).floor()) as u32);

        if node_id < k {
            let mut sp = self.get_audit_proof(conn, node_id, tree_start, k).await?;
            let node = match crate::schema::tree::table.filter(
                crate::schema::tree::dsl::min_seq.eq(k as i64)
                    .and(crate::schema::tree::dsl::max_seq.eq((tree_end - 1) as i64))
            ).first::<crate::models::Node>(&mut conn).await {
                Ok(t) => t,
                Err(err) => return Err(format!("Failed to query DB: {}", err))
            };
            sp.push(node.hash);

            Ok(sp)
        } else {
            let mut sp = self.get_audit_proof(conn, node_id - k, k, tree_end).await?;
            let node = match crate::schema::tree::table.filter(
                crate::schema::tree::dsl::min_seq.eq(tree_start as i64)
                    .and(crate::schema::tree::dsl::max_seq.eq((k - 1) as i64))
            ).first::<crate::models::Node>(&mut conn).await {
                Ok(t) => t,
                Err(err) => return Err(format!("Failed to query DB: {}", err))
            };
            sp.push(node.hash);

            Ok(sp)
        }
    }

    pub async fn get_consistency_proof(&self, first: u64, second: u64) -> Result<Vec<Vec<u8>>, String> {
        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;

        if first > second {
            return Err(format!("First index ({}) is greater than second index ({})", first, second));
        }

        let root_node = match crate::schema::tree::table.filter(
            crate::schema::tree::dsl::is_root.eq(true)
        ).first::<crate::models::Node>(&mut conn).await.optional() {
            Ok(Some(t)) => t,
            Ok(None) => return Err("Tree is empty".to_string()),
            Err(err) => return Err(format!("Failed to query DB: {}", err))
        };

        if first > root_node.tree_size as u64 || second > root_node.tree_size as u64 {
            return Err(format!("First index ({}) or second index ({}) is greater than tree size ({})", first, second, root_node.tree_size));
        }

        self.get_consistency_subproof(&mut conn, first, 0, second, true).await
    }

    #[async_recursion::async_recursion]
    async fn get_consistency_subproof(
        &self, mut conn: &mut mobc::Connection<diesel_async::pooled_connection::AsyncDieselConnectionManager<diesel_async::AsyncPgConnection>>,
        m: u64, d_start: u64, d_end: u64, b: bool
    ) -> Result<Vec<Vec<u8>>, String> {
        let n = d_end - d_start;
        println!("get_consistency_subproof(m={}, d_start={}, d_end={}, b={})", m, d_start, d_end, b);
        if m == d_end - d_start {
            return if b {
                Ok(vec![])
            } else {
                let x = d_start;
                let y = d_start + m - 1;
                println!("[{}:{}]", x, y);
                let node = match crate::schema::tree::table.filter(
                    crate::schema::tree::dsl::min_seq.eq(x as i64)
                        .and(crate::schema::tree::dsl::max_seq.eq(y as i64))
                ).first::<crate::models::Node>(&mut conn).await {
                    Ok(t) => t,
                    Err(err) => return Err(format!("Failed to query DB: {}", err))
                };
                Ok(vec![node.hash])
            }
        } else if m < n {
            let k = 2u64.pow((((n - 1) as f64).log(2.0).floor()) as u32);
            println!("k={}", k);

            if m <= k {
                let mut sp = self.get_consistency_subproof(conn, m, d_start, k + d_start, b).await?;
                println!("sp={:?}", sp);

                let x = k + d_start;
                let y = d_end - 1;
                println!("[{}:{}]", x, y);
                let node = match crate::schema::tree::table.filter(
                    crate::schema::tree::dsl::min_seq.eq(x as i64)
                        .and(crate::schema::tree::dsl::max_seq.eq(y as i64))
                ).first::<crate::models::Node>(&mut conn).await {
                    Ok(t) => t,
                    Err(err) => return Err(format!("Failed to query DB: {}", err))
                };

                sp.push(node.hash);

                Ok(sp)
            } else {
                let mut sp = self.get_consistency_subproof(conn, m - k + d_start, k + d_start, d_end, false).await?;

                let x = d_start;
                let y = k + d_start - 1;
                println!("[{}:{}]", x, y);
                let node = match crate::schema::tree::table.filter(
                    crate::schema::tree::dsl::min_seq.eq(x as i64)
                        .and(crate::schema::tree::dsl::max_seq.eq(y as i64))
                ).first::<crate::models::Node>(&mut conn).await {
                    Ok(t) => t,
                    Err(err) => return Err(format!("Failed to query DB: {}", err))
                };

                sp.push(node.hash);

                Ok(sp)
            }
        } else {
            Ok(vec![])
        }
    }

    pub async fn sign(&self) -> Result<(), String> {
        let mut conn = self.db_conn.get().await
            .map_err(|e| format!("Failed to get DB connection: {}", e))?;

        let to_be_included: crate::models::ToBeIncluded = match crate::schema::to_be_included::table.limit(1)
            .get_result(&mut conn).await.optional() {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(()),
            Err(err) => return Err(format!("Failed to query DB: {}", err))
        };

        let entry_id = to_be_included.entry_id.clone();
        let entry = self.get_blob(entry_id.as_str())?;
        let leaf = MerkleTreeLeaf {
            version: Version::V1,
            leaf: MerkleLeaf::TimestampedEntry(TimestampedEntry {
                timestamp: to_be_included.timestamp as u64,
                entry_type: match to_be_included.log_entry_type {
                    crate::models::LogEntryType::Cert => LogEntryType::X509Entry,
                    crate::models::LogEntryType::PreCert => LogEntryType::PrecertEntry,
                },
                log_entry: entry,
            })
        };
        let leaf_encoded = leaf.encode();
        let leaf_blob_id = self.store_blob(&leaf_encoded)?;
        let leaf_hash = computer_merkle_node_hash_one(&leaf_encoded)?;

        let mut entry = crate::models::Entry {
            id: uuid::Uuid::new_v4(),
            seq: 0,
            entry_id: leaf_blob_id,
            extra_data_id: to_be_included.extra_data_id.clone(),
        };

        match conn.transaction::<_, diesel::result::Error, _>(|conn| Box::pin(async move {
            let root_node = crate::schema::tree::table.filter(
                crate::schema::tree::dsl::is_root.eq(true)
            ).first::<crate::models::Node>(conn).await.optional()?;

            if root_node.is_none() {
                diesel::insert_into(crate::schema::entry::table).values(&entry).execute(conn).await?;
                diesel::insert_into(crate::schema::tree::table)
                    .values(crate::models::Node {
                        id: uuid::Uuid::new_v4(),
                        tree_size: 1,
                        min_seq: 0,
                        max_seq: 0,
                        left_child_id: None,
                        right_child_id: None,
                        is_root: true,
                        hash: leaf_hash.to_vec(),
                        entry_id: Some(entry.id),
                    }).execute(conn).await?;
                diesel::delete(&to_be_included).execute(conn).await?;
                return Ok(());
            }

            let root_node = root_node.unwrap();
            let tree_size = root_node.tree_size;

            entry.seq = tree_size;
            diesel::insert_into(crate::schema::entry::table).values(&entry).execute(conn).await?;

            let new_leaf_id = uuid::Uuid::new_v4();
            diesel::insert_into(crate::schema::tree::table)
                .values(crate::models::Node {
                    id: new_leaf_id,
                    tree_size: 1,
                    min_seq: entry.seq,
                    max_seq: entry.seq,
                    left_child_id: None,
                    right_child_id: None,
                    is_root: false,
                    hash: leaf_hash.to_vec(),
                    entry_id: Some(entry.id),
                }).execute(conn).await?;

            if (tree_size & (tree_size - 1)) == 0 {
                let new_root_hash = computer_merkle_node_hash(&root_node.hash, &leaf_hash).unwrap();

                diesel::insert_into(crate::schema::tree::table)
                    .values(crate::models::Node {
                        id: uuid::Uuid::new_v4(),
                        tree_size: tree_size + 1,
                        min_seq: root_node.min_seq,
                        max_seq: entry.seq,
                        left_child_id: Some(root_node.id),
                        right_child_id: Some(new_leaf_id),
                        is_root: true,
                        hash: new_root_hash.to_vec(),
                        entry_id: None,
                    }).execute(conn).await?;

                diesel::update(&root_node)
                    .set(crate::schema::tree::dsl::is_root.eq(false)).execute(conn).await?;
            } else {
                let mut tbr = vec![root_node.clone()];
                let mut next_node = root_node;
                loop {
                    next_node = crate::schema::tree::table.filter(
                        crate::schema::tree::dsl::id.eq(next_node.right_child_id.unwrap())
                    ).first::<crate::models::Node>(conn).await?;
                    if (next_node.tree_size & (next_node.tree_size - 1)) == 0 {
                        break
                    } else {
                        tbr.push(next_node.clone());
                    }
                }

                let new_hash = computer_merkle_node_hash(&next_node.hash, &leaf_hash).unwrap();
                let new_id = uuid::Uuid::new_v4();
                diesel::insert_into(crate::schema::tree::table)
                    .values(crate::models::Node {
                        id: new_id,
                        tree_size: next_node.tree_size + 1,
                        min_seq: next_node.min_seq,
                        max_seq: entry.seq,
                        left_child_id: Some(next_node.id),
                        right_child_id: Some(new_leaf_id),
                        is_root: false,
                        hash: new_hash.to_vec(),
                        entry_id: None,
                    }).execute(conn).await?;
                diesel::update(&tbr.last().unwrap())
                    .set(crate::schema::tree::dsl::right_child_id.eq(new_id))
                    .execute(conn).await?;

                for node in tbr.iter().rev() {
                    let left_node = crate::schema::tree::table.filter(
                        crate::schema::tree::dsl::id.eq(node.left_child_id.unwrap())
                    ).first::<crate::models::Node>(conn).await?;
                    let new_node_hash = computer_merkle_node_hash(&left_node.hash, &new_hash).unwrap();
                    diesel::update(node)
                        .set((
                                 crate::schema::tree::dsl::hash.eq(new_node_hash.to_vec()),
                                 crate::schema::tree::dsl::max_seq.eq(entry.seq),
                                 crate::schema::tree::dsl::tree_size.eq(node.tree_size + 1),
                        ))
                        .execute(conn).await?;
                }
            }

            diesel::delete(&to_be_included).execute(conn).await?;

            Ok(())
        })).await {
            Ok(_) => (),
            Err(err) => return Err(format!("Failed to update DB: {}", err))
        }

        self.delete_blob(entry_id.as_str())?;

        Ok(())
    }
}

fn compute_sha256_hash(data: &[u8]) -> Result<[u8; 32], String> {
    let digest = match openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &data) {
        Ok(v) => v.to_vec(),
        Err(_) => return Err("Failed to make digest".to_string())
    };
    Ok(<[u8; 32]>::try_from(digest).unwrap())
}

fn computer_merkle_node_hash(left: &[u8], right: &[u8]) -> Result<[u8; 32], String> {
    let mut out = vec![0x01];
    out.extend_from_slice(left);
    out.extend_from_slice(right);
    compute_sha256_hash(&out)
}

fn computer_merkle_node_hash_one(entry: &[u8]) -> Result<[u8; 32], String> {
    let mut out = vec![0x00];
    out.extend_from_slice(entry);
    compute_sha256_hash(&out)
}
