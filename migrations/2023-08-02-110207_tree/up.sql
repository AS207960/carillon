create table entry (
    id uuid primary key not null,
    seq bigint not null,
    entry_id varchar(255) not null,
    extra_data_id varchar(255) not null
);

create table tree (
    id uuid primary key not null,
    tree_size bigint not null,
    min_seq bigint not null,
    max_seq bigint not null,
    left_child_id uuid null,
    right_child_id uuid null,
    is_root boolean not null,
    hash bytea not null,
    entry_id uuid null
);