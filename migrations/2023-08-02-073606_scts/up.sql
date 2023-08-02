create type log_entry_type as enum ('cert', 'pre_cert');

create table to_be_included (
    id uuid primary key not null,
    timestamp bigint not null,
    log_entry_type log_entry_type not null,
    entry_id varchar(255) not null,
    extra_data_id varchar(255) not null
);