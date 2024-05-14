#!/bin/bash
sleep 30
DB_BIN_PATH=`pg_config --bindir`
DB_DATA_PATH=`psql -U postgres --no-align --quiet --tuples-only --command='SHOW data_directory'`
/$DB_BIN_PATH/pg_ctl stop -D $DB_DATA_PATH
rm -rf /var/lib/postgresql/data/*
pg_basebackup -R -h db -U $DB_REPL_USER -D /var/lib/postgresql/data -P
/$DB_BIN_PATH/pg_ctl start -D $DB_DATA_PATH
