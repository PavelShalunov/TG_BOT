#!/bin/bash

#Получить путь к испоняемым файлам
DB_BIN_PATH=`pg_config --bindir`

#Получить путь к кофигурационным файлам
DB_CONF_PATH=`psql -U postgres --no-align --quiet --tuples-only --command='SHOW config_file'`
DB_HBA_PATH=`psql -U postgres --no-align --quiet --tuples-only --command='SHOW hba_file'`
DB_DATA_PATH=`psql -U postgres --no-align --quiet --tuples-only --command='SHOW data_directory'`


#Настроить БД
sed -i "s/^#*\(log_replication_commands *= *\).*/\1on/" $DB_CONF_PATH
sed -i "s/^#*\(archive_mode *= *\).*/\1on/" $DB_CONF_PATH
sed -i "s|^#*\(archive_command *= *\).*|\1'cp %p /tmp/archive/%f'|" $DB_CONF_PATH
sed -i "s/^#*\(max_wal_senders *= *\).*/\110/" $DB_CONF_PATH
sed -i "s/^#*\(wal_level *= *\).*/\1replica/" $DB_CONF_PATH
sed -i "s/^#*\(wal_log_hints *= *\).*/\1on/" $DB_CONF_PATH
sed -i "s/^#*\(logging_collector *= *\).*/\1on/" $DB_CONF_PATH
sed -i -e"s/^#log_filename = 'postgresql-\%Y-\%m-\%d_\%H\%M\%S.log'.*$/log_filename = 'postgresql.log'/" $DB_CONF_PATH
sed -i "s/#log_line_prefix = '%m \[%p\] '/log_line_prefix = '%m [%p] %q%u@%d '/g" $DB_CONF_PATH

#Создать каталог архивирования
mkdir -p /tmp/archive

psql -c "CREATE USER $DB_REPL_USER WITH REPLICATION LOGIN PASSWORD '$DB_REPL_PASSWORD';" #Создать пользователя репликатора
psql -c "CREATE DATABASE $DB_DATABASE;" #Создать пользователя репликатора
psql -d $DB_DATABASE -a -f /init.sql #Создать таблицы с данными в БД
psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" #Создать пользователя БД
psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_DATABASE TO $DB_USER;" #Дать пользователю права на БД
psql -d $DB_DATABASE -c "ALTER TABLE emails OWNER TO $DB_USER;" #Назначить пользователя владельцем
psql -d $DB_DATABASE -c "ALTER TABLE numbers OWNER TO $DB_USER;" #Назначить пользователя владельцем
psql -d $DB_DATABASE -c "GRANT EXECUTE ON FUNCTION pg_current_logfile() TO $DB_USER;" #Разрешить пользователю получать имя файла логов
psql -d $DB_DATABASE -c "GRANT EXECUTE ON FUNCTION pg_read_file(text) TO $DB_USER;" #Разрешить пользователю читать файлы

#Добавить правила доступа к БД
echo "host replication $DB_REPL_USER 0.0.0.0/0 trust" >> $DB_HBA_PATH #Разрешить подключение репликатора
echo "host all $DB_USER bot trust" >> $DB_HBA_PATH #Разрешить подключение бота

#Перезапустить БД
/$DB_BIN_PATH/pg_ctl restart -D $DB_DATA_PATH
