import os
import requests
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
from dotenv import load_dotenv

# Загрузить переменные из .env
load_dotenv()

# Переменные для основного сервера
API_URL = os.getenv("API_URL")
CERT_SHA256 = os.getenv("CERT_SHA256")

# Переменные для второго сервера
API_URL_RU = os.getenv("API_URL_RU")
CERT_SHA256_RU = os.getenv("CERT_SHA256_RU")

# Токен Telegram-бота
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


def get_keys(api_url, cert_sha256):
    """Получить список ключей доступа с сервера Outline."""
    url = f"{api_url}/access-keys"
    headers = {"X-Outline-Api-Key": cert_sha256}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("accessKeys", [])


def create_key(api_url, cert_sha256, name):
    """Создать новый ключ доступа на сервере Outline."""
    url = f"{api_url}/access-keys"
    headers = {"X-Outline-Api-Key": cert_sha256}
    data = {"name": name}
    response = requests.post(url, json=data, headers=headers)
    response.raise_for_status()
    return response.json()


def list_keys(update: Update, context: CallbackContext, api_url, cert_sha256):
    """Отправить список ключей в Telegram."""
    try:
        keys = get_keys(api_url, cert_sha256)
        if keys:
            response_text = "\n".join(
                [f"ID: {key['id']}, Name: {key['name']}, Data Limit: {key.get('dataLimit', 'No limit')}" for key in keys]
            )
        else:
            response_text = "Нет доступных ключей на этом сервере."
        update.message.reply_text(response_text)
    except requests.RequestException as e:
        update.message.reply_text(f"Ошибка при получении ключей: {e}")


def list_keys_main(update: Update, context: CallbackContext):
    list_keys(update, context, API_URL, CERT_SHA256)


def list_keys_ru(update: Update, context: CallbackContext):
    list_keys(update, context, API_URL_RU, CERT_SHA256_RU)


def add_key(update: Update, context: CallbackContext, api_url, cert_sha256, name):
    """Добавить ключ на сервер Outline."""
    try:
        new_key = create_key(api_url, cert_sha256, name)
        response_text = f"Создан новый ключ: ID: {new_key['id']}, Name: {new_key['name']}"
        update.message.reply_text(response_text)
    except requests.RequestException as e:
        update.message.reply_text(f"Ошибка при создании ключа: {e}")


def add_key_main(update: Update, context: CallbackContext):
    name = " ".join(context.args) if context.args else "default"
    add_key(update, context, API_URL, CERT_SHA256, name)


def add_key_ru(update: Update, context: CallbackContext):
    name = " ".join(context.args) if context.args else "default"
    add_key(update, context, API_URL_RU, CERT_SHA256_RU, name)


def main():
    updater = Updater(TELEGRAM_BOT_TOKEN)
    dispatcher = updater.dispatcher

    # Команды для основного сервера
    dispatcher.add_handler(CommandHandler("keys", list_keys_main))
    dispatcher.add_handler(CommandHandler("key", add_key_main))

    # Команды для второго сервера
    dispatcher.add_handler(CommandHandler("keysru", list_keys_ru))
    dispatcher.add_handler(CommandHandler("keyru", add_key_ru))

    updater.start_polling()
    updater.idle()


if __name__ == "__main__":
    main()
