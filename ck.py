import http.client
import json
import hashlib
import ssl
import os
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Загрузить переменные окружения из .env файла
load_dotenv()

# Получаем значения из .env
api_url = os.getenv("API_URL")
cert_sha256 = os.getenv("CERT_SHA256")
telegram_token = os.getenv("TELEGRAM_TOKEN")
authorized_username = os.getenv("AUTHORIZED_USERNAME")

# Проверка сертификата с использованием cert_sha256
def verify_cert_sha256(cert_der):
    sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
    return sha256_fingerprint == cert_sha256

# Функция для выполнения запросов к серверу Outline
def outline_request(method, endpoint, json_data=None):
    url_parts = api_url.split("://")[1].split("/")
    host = url_parts[0]
    path = "/" + "/".join(url_parts[1:] + [endpoint])

    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, context=context)

    try:
        conn.connect()
        der_cert = conn.sock.getpeercert(binary_form=True)
        if not verify_cert_sha256(der_cert):
            conn.close()
            return None

        headers = {"Content-Type": "application/json"}
        body = json.dumps(json_data) if json_data else None
        conn.request(method, path, body, headers)

        response = conn.getresponse()
        data = response.read().decode()
        # print("Response ", data)
        if response.status not in (200, 201):
            return None

        return json.loads(data) if data else None
    except Exception as e:
        print(f"Error sending request: {e}")
        return None
    finally:
        conn.close()

# Проверка доступа по username
def is_authorized(update: Update) -> bool:
    return update.message.from_user.username == authorized_username

# Получение всех ключей доступа и данных о трафике
def get_keys():
    keys = outline_request("GET", "access-keys")
    usage_data = outline_request("GET", "metrics/transfer")
    result = []
    
    if keys and usage_data:
        usage_dict = usage_data.get("bytesTransferredByUserId", {})

        for i, key in enumerate(keys.get("accessKeys", []), start=1):
            name = key.get("name", "No name")
            key_id = key["id"]
            
            # Лимит данных (если установлен)
            data_limit_bytes = key.get("dataLimit", {}).get("bytes")
            data_limit = f"{data_limit_bytes / (1024 * 1024):.2f} MB" if data_limit_bytes else "No limit"
            
            # Использование данных
            data_usage_bytes = usage_dict.get(key_id, 0)
            data_usage = f"{data_usage_bytes / (1024 * 1024):.2f} MB"

            # Форматируем вывод для каждого ключа с выравниванием по колонкам
            if data_limit_bytes:
                result.append(f"{i:<2}. Name: {name:<15} Data: {data_usage:<10} / {data_limit}")
            else:
                result.append(f"{i:<2}. Name: {name:<15} Data: {data_usage}")

    return result

# Создание или получение ключа по имени
def get_or_create_key(name):
    keys = outline_request("GET", "access-keys")
    for key in keys.get("accessKeys", []):
        if key.get("name") == name:
            return key["accessUrl"]

    new_key = outline_request("POST", "access-keys")
    if new_key:
        outline_request("PUT", f"access-keys/{new_key['id']}/name", {"name": name})
        return new_key["accessUrl"]
    return None

# Обработчик команды /keys
async def keys(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("You have no access to this bot.")
        return

    keys_list = get_keys()
    if keys_list:
        # Объединяем список ключей и форматируем в блок кода
        formatted_keys = "\n".join(keys_list)
        await update.message.reply_text(f"<pre>{formatted_keys}</pre>", parse_mode="HTML")
    else:
        await update.message.reply_text("Keys are not found.")

# Обработчик команды /key <name>
async def key(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("You have no access to this bot.")
        return

    if context.args:
        name = " ".join(context.args)
        access_url = get_or_create_key(name)
        if access_url:
            # Выделяем ключ (ss://...) в область кода
            await update.message.reply_text(
                f"Key '{name}' is available at this address:\n<pre>{access_url}</pre>", parse_mode="HTML"
            )
        else:
            await update.message.reply_text("Error getting a key.")
    else:
        await update.message.reply_text("Please specify a key name after the /key command to create a new key or retrieve an existing one.")

def main():
    # Настройка бота
    application = Application.builder().token(telegram_token).build()

    # Команды бота
    application.add_handler(CommandHandler("keys", keys))
    application.add_handler(CommandHandler("key", key))

    # Запуск бота
    application.run_polling()

if __name__ == "__main__":
    main()
