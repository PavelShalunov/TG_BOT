CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'replicator_password' LOGIN;

CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS numbers (
    id SERIAL PRIMARY KEY,
    number VARCHAR(20) NOT NULL
);

select setting from pg_settings where name like '%hba%';
CREATE TABLE hba ( lines text );
COPY hba FROM '/var/lib/postgresql/data/pg_hba.conf';
select * from hba where lines !~ '^#' and lines !~ '^$';
INSERT INTO hba (lines) VALUES ('host replication all 0.0.0.0/0 md5');
select * from hba where lines !~ '^#' and lines !~ '^$';
COPY hba TO '/var/lib/postgresql/data/pg_hba.conf';
SELECT pg_reload_conf();

SELECT * FROM pg_create_physical_replication_slot('replication_slot');
