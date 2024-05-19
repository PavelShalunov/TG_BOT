import os
import re
import logging
import traceback
import json

import asyncpg
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes
import asyncssh

logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

TOKEN = os.getenv('TOKEN')
HOST = os.getenv('RM_HOST')
PORT = int(os.getenv('RM_PORT'))
USERNAME = os.getenv('RM_USER')
PASSWORD = os.getenv('RM_PASSWORD')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_PORT = int(os.getenv('DB_PORT'))
DB_DATABASE = os.getenv('DB_DATABASE')

HELP_TEXT = """
Доступные команды:
* /help - вызов справки

* /find_emails - поиск email-адресов
* /find_phone_numbers - поиск телефонных номеров
* /verify_password - проверка пароля

Мониторинг Linux-системы:
* /get_release - о релизе
* /get_uname - об архитектуры процессора, имени хоста системы и версии ядра
* /get_uptime - о времени работы

* /get_df - cбор информации о состоянии файловой системы
* /get_free - cбор информации о состоянии оперативной памяти
* /get_mpstat - cбор информации о производительности системы
* /get_w - cбор информации о работающих в данной системе пользователях

* /get_auths - последние 10 входов в систему
* /get_critical - последние 5 критических события

* /get_ps - сбор информации о запущенных процессах
* /get_ss - сбор информации о используемых портах
* /get_apt_list - сбор информации о установленных пакетах
* /get_services - сбор информации о запущенных сервисах

Работа с бд:
* /get_repl_logs - вывод логов о репликации с бд
* /get_emails - вывод данных из таблицы emails
* /get_phone_numbers - вывод данных из таблицы numbers
"""


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logging.error("Exception while handling an update:", exc_info=context.error)

    tb_list = traceback.format_exception(None, context.error, context.error.__traceback__)
    tb_string = "".join(tb_list)

    update_str = update.to_dict() if isinstance(update, Update) else str(update)
    message = (
        "An exception was raised while handling an update\n"
        f"update = {json.dumps(update_str, indent=2, ensure_ascii=False)}"
        "\n\n"
        f"{tb_string}"
    )

    await update.message.reply_text(message)


def split_text(text, max_length=4000):
    chunks = []
    while len(text) > max_length:
        index = max_length
        while index > 0 and text[index] not in (' ', '\n'):
            index -= 1
        if index == 0:  # нет пробелов или новых строк в первых max_length символах
            index = max_length
        chunk, text = text[:index], text[index:]
        chunks.append(chunk)
    chunks.append(text)  # добавляем оставшийся текст
    return chunks


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info(f'{update.effective_user.username} call /help command')  # !!! ПРОСТАВИТЬ ТАКОЙ ЛОГ ВЕЗДЕ
    await context.bot.send_message(chat_id=update.effective_chat.id, text=HELP_TEXT)


async def find_emails_cmd(update: Update, context):
    await update.message.reply_text('Введите текст для поиска email-адресов: ')
    return 'find_emails'


async def verify_password_cmd(update: Update, context):
    await update.message.reply_text('Введите пароль: ')
    return 'verify_password'


async def find_phone_numbers_cmd(update: Update, context):
    await update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    return 'find_phone_numbers'


async def find_emails(update: Update, context):
    user_input = update.message.text  # Получаем текст, содержащий(или нет) номера телефонов

    email_re = re.compile(
        "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])")

    emails = email_re.findall(user_input)  # Ищем номера телефонов

    if not emails:  # Обрабатываем случай, когда номеров телефонов нет
        await update.message.reply_text('Email-адреса не найдены')
        return ConversationHandler.END

    emails_msg = ''  # Создаем строку, в которую будем записывать номера телефонов
    for i in range(len(emails)):
        emails_msg += f'{i + 1}. {emails[i]}\n'  # Записываем очередной номер

    await update.message.reply_text('Найдены следующие email адреса:')  # Отправляем сообщение пользователю
    await update.message.reply_text(emails_msg)  # Отправляем сообщение пользователю
    await update.message.reply_text('Сохранить их (Введите 1, если да)?')  # Отправляем сообщение пользователю
    context.user_data['emails'] = emails
    return "save_emails"


async def save_emails(update: Update, context):
    user_input = update.message.text.strip()
    if user_input != '1':
        return ConversationHandler.END  # Завершаем работу обработчика диалога
    conn = await asyncpg.connect(user=DB_USER, password=DB_PASSWORD,
                                 database=DB_DATABASE, host=DB_HOST, port=DB_PORT)
    emails = context.user_data['emails']
    try:
        for email in emails:
            await conn.execute(
                'INSERT INTO emails(email) VALUES ($1)', email
            )
        await conn.close()
    except Exception:
        await update.message.reply_text('Сохранить данные не удалось')  # Отправляем сообщение пользователю
    else:
        await update.message.reply_text('Данные сохранены успешно')  # Отправляем сообщение пользователю
    return ConversationHandler.END  # Завершаем работу обработчика диалога


async def find_phone_numbers(update: Update, context):
    user_input = update.message.text  # Получаем текст, содержащий(или нет) номера телефонов

    phone_num_re = re.compile(r"(\+7|8)([-\s]?)(\()?(\d{3})(?(3)\))([- \s]?)(\d{3})([- \s]?)(\d{2})([- \s]?)(\d{2})")

    phone_numbers = phone_num_re.findall(user_input)  # Ищем номера телефонов
    if not phone_numbers:  # Обрабатываем случай, когда номеров телефонов нет
        await update.message.reply_text('Телефонные номера не найдены')
        return ConversationHandler.END


    phone_numbers_msg = ''  # Создаем строку, в которую будем записывать номера телефонов
    for i in range(len(phone_numbers)):
        phone_number = ''.join(phone_numbers[i])
        phone_numbers_msg += f'{i + 1}. {phone_number}\n'  # Записываем очередной номер

    await update.message.reply_text('Найдены следующие номера:')  # Отправляем сообщение пользователю
    await update.message.reply_text(phone_numbers_msg)  # Отправляем сообщение пользователю
    await update.message.reply_text('Сохранить их (Введите 1, если да)?')  # Отправляем сообщение пользователю
    context.user_data['numbers'] = phone_numbers
    return "save_numbers"


async def save_numbers(update: Update, context):
    user_input = update.message.text.strip()
    if user_input != '1':
        return ConversationHandler.END  # Завершаем работу обработчика диалога
    conn = await asyncpg.connect(user=DB_USER, password=DB_PASSWORD,
                                 database=DB_DATABASE, host=DB_HOST, port=DB_PORT)
    numbers = context.user_data['numbers']
    try:
        for number in numbers:
            await conn.execute(
                'INSERT INTO numbers(phone_number) VALUES ($1)', ''.join(number)
            )
        await conn.close()
    except Exception:
        logging.exception('')
        await update.message.reply_text('Сохранить данные не удалось')  # Отправляем сообщение пользователю
    else:
        await update.message.reply_text('Данные сохранены успешно')  # Отправляем сообщение пользователю
    return ConversationHandler.END  # Завершаем работу обработчика диалога


async def verify_password(update: Update, context):
    user_input = update.message.text  # Получаем текст, содержащий(или нет) номера телефонов

    pwd_re = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()]).{8,}$'

    if re.fullmatch(pwd_re, user_input):
        await update.message.reply_text('Пароль сложный')
    else:
        await update.message.reply_text('Пароль простой')
    return ConversationHandler.END  # Завершаем работу обработчика диалога


async def get_release(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info(f'{update.effective_user.username} call /get_release command')
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('cat /etc/os-release', check=True)
        await update.message.reply_text(result.stdout)


async def get_uname(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('uname -a', check=True)
        logging.info(f'stdout from uname -a: {result.stdout}')
        await update.message.reply_text(result.stdout)


async def get_uptime(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('uptime', check=True)
        await update.message.reply_text(result.stdout)


async def get_df(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('df -h', check=True)
        await update.message.reply_text(result.stdout)


async def get_free(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('free -h', check=True)
        await update.message.reply_text(result.stdout)


async def get_mpstat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('mpstat', check=True)
        await update.message.reply_text(result.stdout)


async def get_w(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('w', check=True)
        await update.message.reply_text(result.stdout)


async def get_auths(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('last -n 10', check=True)
        await update.message.reply_text(result.stdout)


async def get_critical(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('journalctl -p crit -n 5', check=True)
        await update.message.reply_text(result.stdout)


async def get_ps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('ps aux', check=True)
        for chunk in split_text(result.stdout):
            await update.message.reply_text(chunk)


async def get_ss(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('netstat -tulnp', check=True)
        await update.message.reply_text(result.stdout)


async def get_apt_list_cmd(update: Update, context):
    await update.message.reply_text('Введите имя интересующего пакета (введите 1, если хотите увидеть информацию о всех пакетах): ')
    return 'get_apt_list'


async def get_apt_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text.strip()
    cmd = 'apt --installed list'
    if user_input != '1':
        cmd += f' | grep {user_input}'

    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run(cmd, check=True)
        for chunk in split_text(result.stdout):
            await update.message.reply_text(chunk)


async def get_services(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with asyncssh.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, options=asyncssh.SSHClientConnectionOptions(known_hosts=None)) as conn:
        result = await conn.run('systemctl --type=service --state=running', check=True)
        await update.message.reply_text(result.stdout)


async def get_repl_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn = await asyncpg.connect(user=DB_USER, password=DB_PASSWORD,
                                 database=DB_DATABASE, host=DB_HOST, port=DB_PORT)
    values = await conn.fetch(
        'SELECT pg_read_file(pg_current_logfile());'
    )
    await conn.close()
    result = []
    for line in values[0]['pg_read_file'].split('\n'):
        if 'checkpoint' in line.lower() or 'repl' in line.lower():
            result.append(line)
    for chunk in split_text('\n'.join(result)):
        logging.warning(chunk)
        await update.message.reply_text(chunk)


async def get_emails(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn = await asyncpg.connect(user=DB_USER, password=DB_PASSWORD,
                                 database=DB_DATABASE, host=DB_HOST, port=DB_PORT)
    values = await conn.fetch(
        'SELECT * FROM emails'
    )
    await conn.close()
    res = ''
    for val in values:
        res += f'{val["id"]}: {val["email"]}'
        res += '\n'
    await update.message.reply_text(res)


async def get_phone_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn = await asyncpg.connect(user=DB_USER, password=DB_PASSWORD,
                                 database=DB_DATABASE, host=DB_HOST, port=DB_PORT)
    values = await conn.fetch(
        'SELECT * FROM numbers'
    )
    await conn.close()
    res = ''
    for val in values:
        res += f'{val["id"]}: {val["phone_number"]}'
        res += '\n'
    await update.message.reply_text(res)


if __name__ == '__main__':
    application = ApplicationBuilder().token(TOKEN).build()

    conv_handler_find_emails = ConversationHandler(
        entry_points=[CommandHandler('find_emails', find_emails_cmd)],
        states={
            'find_emails': [MessageHandler(filters.TEXT & ~filters.COMMAND, find_emails)],
            'save_emails': [MessageHandler(filters.TEXT & ~filters.COMMAND, save_emails)],
        },
        fallbacks=[]
    )

    conv_handler_find_phone_numbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_numbers', find_phone_numbers_cmd)],
        states={
            'find_phone_numbers': [MessageHandler(filters.TEXT & ~filters.COMMAND, find_phone_numbers)],
            'save_numbers': [MessageHandler(filters.TEXT & ~filters.COMMAND, save_numbers)],

        },
        fallbacks=[]
    )

    conv_handler_verify_password = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verify_password_cmd)],
        states={
            'verify_password': [MessageHandler(filters.TEXT & ~filters.COMMAND, verify_password)],
        },
        fallbacks=[]
    )

    conv_handler_get_apt_list = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_cmd)],
        states={
            'get_apt_list': [MessageHandler(filters.TEXT & ~filters.COMMAND, get_apt_list)],
        },
        fallbacks=[]
    )

    application.add_handler(CommandHandler("start", help_cmd))
    application.add_handler(CommandHandler("help", help_cmd))

    application.add_handler(conv_handler_find_emails)
    application.add_handler(conv_handler_find_phone_numbers)
    application.add_handler(conv_handler_verify_password)

    application.add_handler(CommandHandler('get_release', get_release))
    application.add_handler(CommandHandler('get_uname', get_uname))
    application.add_handler(CommandHandler('get_uptime', get_uptime))

    application.add_handler(CommandHandler('get_df', get_df))
    application.add_handler(CommandHandler('get_free', get_free))
    application.add_handler(CommandHandler('get_mpstat', get_mpstat))
    application.add_handler(CommandHandler('get_w', get_w))

    application.add_handler(CommandHandler('get_auths', get_auths))
    application.add_handler(CommandHandler('get_critical', get_critical))


    application.add_handler(CommandHandler('get_ps', get_ps))
    application.add_handler(CommandHandler('get_ss', get_ss))
    application.add_handler(conv_handler_get_apt_list)
    application.add_handler(CommandHandler('get_services', get_services))

    application.add_handler(CommandHandler('get_repl_logs', get_repl_logs))
    application.add_handler(CommandHandler('get_emails', get_emails))
    application.add_handler(CommandHandler('get_phone_numbers', get_phone_numbers))


    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, help_cmd))

    application.add_error_handler(error_handler)

    application.run_polling()
