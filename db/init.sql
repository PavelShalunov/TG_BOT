CREATE USER ${DB_REPL_USER} WITH REPLICATION ENCRYPTED PASSWORD '${DB_REPL_PASSWORD}';
SELECT pg_create_physical_replication_slot('replication_slot');

\c ${DB_DATABASE};

CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS numbers (
    id SERIAL PRIMARY KEY,
    phone_number VARCHAR(20) NOT NULL
);

INSERT INTO emails (email) VALUES
    ('userone@mail.ru'),
    ('employee@gmail.com');

INSERT INTO numbers (phone_number) VALUES
    ('89876543210'),
    ('87777777777');
