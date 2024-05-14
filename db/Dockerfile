FROM postgres:latest
COPY ./db_master_init.sh /docker-entrypoint-initdb.d/init.sh
COPY ./db_master_init.sql /init.sql
RUN chmod +x /docker-entrypoint-initdb.d/init.sh
