create table users (
    id integer primary key,
    name varchar(32) unique not null,
    password blob(256) not null
);

create table keys (
    id integer primary key,
    filepath varchar(256) unique,
    server_id integer not null,
    foreign key (server_id) references servers on delete cascade
);

create table servers (
    id integer primary key,
    name varchar(32) unique not null
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
insert into servers(name) values ('ark');
insert into keys(filepath, server_id) values ('private', 1);
insert into keys(filepath, server_id) values ('another', 1);
insert into keys(filepath, server_id) values ('ark_priv', 2);
insert into permissions values (1, 1);
insert into permissions values (1, 2);
insert into permissions values (1, 3);
