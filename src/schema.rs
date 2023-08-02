// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "log_entry_type"))]
    pub struct LogEntryType;
}

diesel::table! {
    entry (id) {
        id -> Uuid,
        seq -> Int8,
        entry_id -> Varchar,
        extra_data_id -> Varchar,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::LogEntryType;

    to_be_included (id) {
        id -> Uuid,
        timestamp -> Int8,
        log_entry_type -> LogEntryType,
        entry_id -> Varchar,
        extra_data_id -> Varchar,
    }
}

diesel::table! {
    tree (id) {
        id -> Uuid,
        tree_size -> Int8,
        min_seq -> Int8,
        max_seq -> Int8,
        left_child_id -> Nullable<Uuid>,
        right_child_id -> Nullable<Uuid>,
        is_root -> Bool,
        hash -> Bytea,
        entry_id -> Nullable<Uuid>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    entry,
    to_be_included,
    tree,
);
