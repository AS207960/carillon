use crate::schema::*;

#[derive(diesel_derive_enum::DbEnum)]
#[derive(Debug, Clone)]
#[ExistingTypePath = "crate::schema::sql_types::LogEntryType"]
pub enum LogEntryType {
    Cert,
    PreCert,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = to_be_included)]
pub struct ToBeIncluded {
    pub id: uuid::Uuid,
    pub timestamp: i64,
    pub log_entry_type: LogEntryType,
    pub entry_id: String,
    pub extra_data_id: String,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = entry)]
pub struct Entry {
    pub id: uuid::Uuid,
    pub seq: i64,
    pub entry_id: String,
    pub extra_data_id: String,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = tree)]
pub struct Node {
    pub id: uuid::Uuid,
    pub tree_size: i64,
    pub min_seq: i64,
    pub max_seq: i64,
    pub left_child_id: Option<uuid::Uuid>,
    pub right_child_id: Option<uuid::Uuid>,
    pub is_root: bool,
    pub hash: Vec<u8>,
    pub entry_id: Option<uuid::Uuid>,
}