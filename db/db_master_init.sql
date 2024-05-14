CREATE TABLE IF NOT EXISTS numbers (
    id SERIAL PRIMARY KEY,
    numbers VARCHAR(64) NOT NULL
);

INSERT INTO numbers (number) VALUES
('89001234567'),
('82344445544');

CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    email VARCHAR(300) NOT NULL
);

INSERT INTO emails (email) VALUES
('first@email.com'),
('second@email.com');
