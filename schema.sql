create table users (
    id integer primary key,
    name varchar(32) unique,
    password blob(256)
);

create table keys (
    id integer primary key,
    filepath varchar(256) unique,
    server_id integer,
    foreign key (server_id) references servers on delete cascade
);

create table servers (
    id integer primary key,
    name varchar(32) unique
);

create table permissions (
    user_id integer,
    key_id integer,
    primary key (user_id, key_id),
    foreign key (user_id) references users on delete cascade,
    foreign key (key_id) references keys on delete cascade
);

insert into users(name, password) values ('simon', '1234'), ('werner', '1234');
insert into servers(name) values ('minecraft');
insert into keys(filepath, server_id) values ('private', 1);
insert into permissions values (1, 1);
