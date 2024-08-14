import re
import logging
import os
from mitmproxy import http
from scapy.all import Ether, IP, TCP, Raw, wrpcap

# Настройка логирования
log_filename = os.path.join(os.path.dirname(__file__), 'incident_logs.txt') # Путь к файлу для логирования инцидентов
pcap_filename = os.path.join(os.path.dirname(__file__), 'matched_packets.pcap') # Путь к файлу для сохранения пакетов
patterns_filename = os.path.join(os.path.dirname(__file__), 'patterns.txt') # Путь к файлу с шаблонами

# Создаем логгер
logger = logging.getLogger('incident_logger') # Создаем логгер с именем 'incident_logger'
logger.setLevel(logging.INFO) # Устанавливаем уровень логирования на INFO

# Создаем обработчик для записи логов в файл
file_handler = logging.FileHandler(log_filename) # Обработчик для записи логов в файл
file_handler.setLevel(logging.INFO)  # Устанавливаем уровень логирования для обработчика

# Создаем обработчик для вывода логов в консоль
console_handler = logging.StreamHandler() # Обработчик для вывода логов в консоль
console_handler.setLevel(logging.INFO) # Устанавливаем уровень логирования для обработчика

# Создаем форматтер и добавляем его в обработчики
formatter = logging.Formatter('%(asctime)s %(message)s') # Форматтер для логов с временем и сообщением
file_handler.setFormatter(formatter) # Устанавливаем форматтер для файлового обработчика
console_handler.setFormatter(formatter) # Устанавливаем форматтер для консольного обработчика

# Добавляем обработчики в логгер
logger.addHandler(file_handler) # Добавляем файловый обработчик к логгеру
logger.addHandler(console_handler) # Добавляем консольный обработчик к логгеру

class WebhookDetector:
    def __init__(self):
        self.dns_responses = set() # Инициализируем множество для хранения DNS-ответов
        self.active_patterns = self.load_active_patterns() # Загружаем активные шаблоны

    def load_active_patterns(self):
        # Загружает активные шаблоны из файла
        active_patterns = []  # Список для хранения активных шаблонов
        if os.path.exists(patterns_filename):  # Проверяем, существует ли файл с шаблонами
            with open(patterns_filename, 'r') as f:
                for line in f:
                    line = line.strip() # Удаляем начальные и конечные пробелы
                    if not line:
                        continue  # Пропускаем пустые строки
                    try:
                        pattern, name, status = line.split('|') # Разбиваем строку на шаблон, имя и статус
                        if status.strip().lower() == 'active':  # Проверяем, активен ли шаблон
                            active_patterns.append((re.compile(pattern), name)) # Компилируем шаблон и добавляем в список
                    except ValueError:
                        logger.error(f"Invalid line in patterns file: {line}") # Логируем ошибку, если формат строки некорректен
                        continue  # Пропускаем некорректные строки
        logger.info(f"Loaded active patterns: {[name for _, name in active_patterns]}") # Логируем загруженные шаблоны
        return active_patterns # Возвращаем список активных шаблонов

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host  # Извлекаем хост из запроса
        url = flow.request.url # Извлекаем URL из запроса
        data = flow.request.content # Извлекаем содержимое запроса
        try:
            data = data.decode("utf-8") # Пытаемся декодировать данные как UTF-8
        except UnicodeDecodeError:
            data = data.decode("latin-1") # Если ошибка, декодируем как Latin-1

        webhook_pattern = re.compile(r"discord.com/api/webhook") # Компилируем регулярное выражение для поиска вебхуков Discord
        sensitive_data_patterns = self.active_patterns # Получаем активные шаблоны


        # if webhook_pattern.search(url):
        #     message = f"Webhook detected in URL: {url}"
        #     self.show_alert("Webhook detected!", message)
        #     logger.info(f"URL: {url}, Reason: Webhook detected")
        #     self.save_packet(flow)

        if flow.request.method == "POST": # Проверяем, является ли метод запроса POST
            if webhook_pattern.search(url):  # Проверяем, содержит ли URL вебхук
                for pattern, name in sensitive_data_patterns: # Перебираем активные шаблоны
                    match = pattern.search(data) # Ищем совпадение в данных запроса
                    if match:
                        message = f"Keyword '{name}' found in request data: '{match.group()}'. URL: {url}"
                        self.show_alert("Sensitive Data detected!", message) # Показать предупреждение
                        logger.info(f"URL: {url}, Reason: Keyword '{name}' found in request data: '{match.group()}'") # Логируем инцидент
                        self.save_packet(flow) # Сохраняем пакет

    def save_packet(self, flow):
        packet = Ether() / IP(dst=flow.request.host) / TCP(dport=flow.request.port) / Raw(load=flow.request.content) # Создаем пакет с помощью scapy
        wrpcap(pcap_filename, [packet], append=True) # Сохраняем пакет в файл .pcap

    def show_alert(self, title, message):
        logger.info(f"Notification: {title} - {message}") # Логируем уведомление

# Список дополнений для mitmproxy
addons = [
    WebhookDetector() # Добавляем WebhookDetector в список дополнений
]
