FROM postgres:15

COPY init.sql /init.sql

ARG DB_REPL_USER
ARG DB_REPL_PASSWORD
ARG DB_DATABASE

RUN apt-get update && apt-get install -y gettext-base && \
    envsubst '${DB_REPL_USER} ${DB_REPL_PASSWORD} ${DB_DATABASE}' < /init.sql > /docker-entrypoint-initdb.d/init.sql
