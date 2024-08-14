import os
import socket
import subprocess
import threading
import time
import queue
import logging
from scapy.all import sniff, DNS, IP, TCP

# Путь к скрипту mitmproxy
MITM_SCRIPT = os.path.join(os.path.dirname(__file__), 'webhook_detector.py')

# Настройка файлов
patterns_filename = os.path.join(os.path.dirname(__file__), 'patterns.txt')
dns_queue = queue.Queue()

# Создаем логгер для сервера
logger = logging.getLogger('server_logger')
logger.setLevel(logging.INFO)

# Создаем обработчик для записи логов в файл
server_log_filename = os.path.join(os.path.dirname(__file__), 'server_logs.txt')
file_handler = logging.FileHandler(server_log_filename)
file_handler.setLevel(logging.INFO)

# Создаем обработчик для вывода логов в консоль
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Создаем форматтер и добавляем его к обработчикам
formatter = logging.Formatter('%(asctime)s %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Добавляем обработчики к логгеру
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Создаем событие для остановки потоков и список для хранения ссылок на потоки
stop_event = threading.Event()
threads = []
mitmproxy_process = None

def load_patterns():
    """Загружает все шаблоны из файла."""
    patterns = []
    if os.path.exists(patterns_filename):
        with open(patterns_filename, 'r') as f:
            for line in f:
                line = line.strip()  # Удаляем начальные и конечные пробелы
                if not line:
                    continue  # Пропускаем пустые строки
                try:
                    pattern, name, status = line.split('|')
                    patterns.append((pattern, name, status)) # Добавляем шаблон, имя и статус как кортеж
                except ValueError:
                    logger.error(f"Invalid line in patterns file: {line}") # Логируем ошибку, если формат строки некорректен
                    continue  # Пропускаем некорректные строки
    return patterns

def load_active_patterns():
    """Загружает только активные шаблоны."""
    active_patterns = []
    patterns = load_patterns()
    for pattern, name, status in patterns:
        if status.strip().lower() == 'active':  # Проверяем, активен ли шаблон
            active_patterns.append((pattern, name)) # Добавляем активный шаблон и имя
    return active_patterns

def save_pattern(pattern, name, status='inactive'):
    """Сохраняет новый шаблон с заданным статусом."""
    with open(patterns_filename, 'a') as f:
        f.write(f"{pattern}|{name}|{status}\n") # Добавляем новый шаблон в файл

def dns_sniffer():
    """Функция сниффера для DNS пакетов."""
    def stop_filter(packet):
        return stop_event.is_set() # Останавливаем сниффинг, если установлено событие stop_event
    while not stop_event.is_set():
        sniff(prn=dns_sniffer_callback, filter="udp port 53", store=False, timeout=1, stop_filter=stop_filter)

def dns_sniffer_callback(packet):
    """Обработчик для обработки DNS пакетов."""
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        # Обрабатываем DNS ответы
        if dns_layer.qr == 1: # Проверяем, является ли это ответом DNS
            for i in range(dns_layer.ancount):  # Перебираем все ответы
                answer = dns_layer.an[i]
                if answer.type == 1:  # Проверяем, является ли это A-записью
                    response = answer.rdata # Получаем IP-адрес из ответа
                    dns_queue.put(response) # Добавляем IP-адрес ответа в очередь DNS

def capture_packets():
    """Функция сниффера для HTTPS пакетов."""
    def stop_filter(packet):
        return stop_event.is_set() # Останавливаем сниффинг, если установлено событие stop_event
    while not stop_event.is_set():
        sniff(prn=capture_packets_callback, filter="tcp port 443", store=False, timeout=1, stop_filter=stop_filter)

def capture_packets_callback(packet):
    """Обработчик для обработки HTTPS пакетов."""
    if packet.haslayer(TCP) and packet[TCP].dport == 443: # Проверяем, является ли пакет TCP и целевой порт 443
        ip = packet[IP].src # IP-адрес источника
        dst_ip = packet[IP].dst # IP-адрес назначения
        size = len(packet)  # Длина пакета


def notify_client(client_socket, title, message):
    """Отправляет уведомление клиенту."""
    notification = f"{title}: {message}"  # Форматируем сообщение уведомления
    client_socket.sendall(notification.encode('utf-8')) # Отправляем сообщение клиенту


def update_responses_periodically():
    """Периодическое обновление ответов."""
    while not stop_event.is_set():
        time.sleep(5)  # Задержка в 5 секунд


def update_pattern_status(selected_names, new_status='active'):
    """Обновляет статус шаблонов на основе выбранных имен без удаления неактивных."""
    patterns = load_patterns()
    updated_patterns = []
    # Обновляем статус только для выбранных шаблонов
    for pattern, name, status in patterns:
        if name in selected_names: # Проверяем, находится ли имя шаблона в списке выбранных
            updated_patterns.append((pattern, name, new_status)) # Обновляем статус
        else:
            updated_patterns.append((pattern, name, status)) # Сохраняем оригинальный статус

    # Сохраняем все шаблоны с обновленными статусами
    with open(patterns_filename, 'w') as f:
        for pattern, name, status in updated_patterns:
            f.write(f"{pattern}|{name}|{status}\n")  # Перезаписываем файл с обновленными шаблонами


def run_mitmproxy():
    """Запускает процесс mitmproxy."""
    global mitmproxy_process
    # Останавливаем любой существующий процесс mitmproxy
    stop_sniffing(mitmproxy_process)
    # Загружаем активные шаблоны из файла
    active_patterns = load_active_patterns()
    if not active_patterns:
        logger.info("No active patterns found, running mitmdump without filtering.") # Логируем, если активные шаблоны отсутствуют
    else:
        logger.info(f"Running mitmdump with active patterns: {active_patterns}")
    # Формируем аргумент активных шаблонов для mitmdump
    active_patterns_arg = ",".join(f"{pattern}" for pattern, _ in active_patterns)
    # Запускаем mitmdump с вашим скриптом, передавая активные шаблоны как аргумент командной строки
    proc = subprocess.Popen([
        'mitmdump',
        '-s', MITM_SCRIPT,
        '--set', f'active_patterns={active_patterns_arg}'
    ])
    time.sleep(5)  # Ожидание запуска mitmproxy
    mitmproxy_process = proc
    return proc

def deactivate_pattern_status(selected_names):
    """Деактивирует статус шаблонов на основе выбранных имен."""
    patterns = load_patterns()
    updated_patterns = []

    # Обновляем статус только для выбранных шаблонов
    for pattern, name, status in patterns:
        if name in selected_names:
            updated_patterns.append((pattern, name, 'inactive')) # Устанавливаем статус как неактивный
        else:
            updated_patterns.append((pattern, name, status))  # Сохраняем оригинальный статус

    # Сохраняем все шаблоны с обновленными статусами
    with open(patterns_filename, 'w') as f:
        for pattern, name, status in updated_patterns:
            f.write(f"{pattern}|{name}|{status}\n") # Перезаписываем файл с обновленными шаблонами


def handle_client(client_socket, address):
    """Обрабатывает связь с подключенным клиентом."""
    global mitmproxy_process
    logger.info(f"Client connected: {address}") # Логируем, когда клиент подключается
    notify_client(client_socket, "Server", "Connected to server successfully") # Уведомляем клиента об успешном подключении

    def relay_notifications():
        """Передает уведомления из журнала инцидентов клиенту."""
        log_file_path = os.path.join(os.path.dirname(__file__), 'incident_logs.txt') # Путь к файлу журнала инцидентов
        with open(log_file_path, 'r') as log_file:
            log_file.seek(0, os.SEEK_END) # Перемещаем курсор в конец файла
            while not stop_event.is_set():
                line = log_file.readline() # Читаем новые строки по мере их добавления
                if line:
                    if "Notification:" in line:
                        notification = line.strip().split("Notification: ", 1)[-1]
                        notify_client(client_socket, "Incident Logger", notification) # Отправляем уведомление клиенту
                else:
                    time.sleep(1) # Пауза, если новые строки не найдены

    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8') # Получаем данные от клиента
            if not data:
                break # Выходим из цикла, если данные не получены
            command, *args = data.split() # Разделяем команду и ее аргументы

            if command == "ADD_PATTERN":
                pattern, name = args
                save_pattern(pattern, name) # Сохраняем новый шаблон
                notify_client(client_socket, "Pattern Added", f"Added pattern '{name}'")
                logger.info(f"Pattern added: '{name}' with pattern '{pattern}'") # Логируем добавление шаблона

            elif command == "DELETE_PATTERN":
                patterns = load_patterns()
                patterns_to_keep = []
                for pattern, name, status in patterns:
                    if name not in args:
                        patterns_to_keep.append((pattern, name, status)) # Сохраняем шаблоны, не входящие в аргументы
                with open(patterns_filename, 'w') as f:
                    for pattern, name, status in patterns_to_keep:
                        f.write(f"{pattern}|{name}|{status}\n") # Перезаписываем файл без удаленных шаблонов
                notify_client(client_socket, "Pattern Deleted", f"Deleted patterns: {', '.join(args)}")
                logger.info(f"Patterns deleted: {', '.join(args)}") # Логируем удаление шаблонов

            elif command == "GET_PATTERNS":
                patterns = load_patterns()
                response = "|".join(
                    [f"{name} ({'ON' if status.lower() == 'active' else 'OFF'}): {pattern}" for pattern, name, status in
                     patterns]
                )
                client_socket.sendall(f"Patterns:{response}".encode('utf-8')) # Отправляем список шаблонов клиенту

            elif command == "SELECT_REGEX":
                update_pattern_status(args, 'active') # Активируем выбранные шаблоны
                notify_client(client_socket, "Selected Patterns", f"Activated patterns: {', '.join(args)}")
                logger.info(f"Activated patterns: {', '.join(args)}")  # Логируем активацию шаблонов

            # Новая команда для деактивации выбранных шаблонов
            elif command == "DEACTIVATE_REGEX":
                deactivate_pattern_status(args) # Деактивируем выбранные шаблоны
                notify_client(client_socket, "Deactivated Patterns", f"Deactivated patterns: {', '.join(args)}")
                logger.info(f"Deactivated patterns: {', '.join(args)}") # Логируем деактивацию шаблонов

            elif command == "START":
                stop_event.clear() # Сбрасываем событие остановки для запуска потоков

                # Перезапускаем потоки
                for thread in threads:
                    if thread.is_alive():
                        stop_event.set() # Устанавливаем событие остановки, чтобы остановить потоки
                        thread.join() # Ожидаем завершения потока

                threads.clear()  # Очищаем список потоков
                stop_event.clear()  # Сбрасываем событие остановки для перезапуска

                update_thread = threading.Thread(target=update_responses_periodically)
                update_thread.start() # Запускаем поток периодического обновления
                threads.append(update_thread) # Добавляем в список потоков

                dns_thread = threading.Thread(target=dns_sniffer)
                dns_thread.start()  # Запускаем поток сниффера DNS
                threads.append(dns_thread)  # Добавляем в список потоков

                https_thread = threading.Thread(target=capture_packets)
                https_thread.start() # Запускаем поток сниффера HTTPS
                threads.append(https_thread) # Добавляем в список потоков

                notification_thread = threading.Thread(target=relay_notifications)
                notification_thread.start()  # Запускаем поток передачи уведомлений
                threads.append(notification_thread) # Добавляем в список потоков

                run_mitmproxy()  # Запускаем процесс mitmproxy

                notify_client(client_socket, "Sniffing", "Started sniffing and analysis")
                logger.info("Sniffing started") # Логируем, что сниффинг начат

            elif command == "STOP":
                stop_event.set()  # Устанавливаем событие остановки для остановки всех потоков

                for thread in threads:
                    if thread.is_alive():
                        thread.join() # Ожидаем завершения каждого потока

                stop_sniffing(mitmproxy_process)  # Останавливаем процесс mitmproxy
                notify_client(client_socket, "Sniffing", "Stopped sniffing and analysis")
                logger.info("Sniffing stopped") # Логируем, что сниффинг остановлен

    finally:
        stop_event.set() # Устанавливаем stop_event при отключении клиента
        stop_sniffing(mitmproxy_process) # Останавливаем процесс mitmproxy
        client_socket.close() # Закрываем сокет клиента
        logger.info(f"Client disconnected: {address}") # Логируем, что клиент отключился
        print(f"Client disconnected: {address}")

def stop_sniffing(mitmproxy_process):
    """Проверка, что процесс mitmproxy завершен корректно."""
    if mitmproxy_process is not None:
        mitmproxy_process.terminate() # Завершаем процесс mitmproxy
        mitmproxy_process.wait()  # Ожидаем завершения процесса


def start_server(host='0.0.0.0', port=9999):
    """Запускает TCP сервер для обработки подключений клиентов."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Создаем сокет
    server_socket.bind((host, port))  # Привязываем сокет к хосту и порту
    server_socket.listen() # Ожидаем входящих подключений
    print(f"Server listening on {host}:{port}")

    try:
        while True:
            client_socket, address = server_socket.accept() # Принимаем подключение клиента
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address)) # Обрабатываем каждого клиента в отдельном потоке
            client_thread.start() # Запускаем поток клиента
    finally:
        server_socket.close() # Проверяем, что сокет сервера закрыт при остановке


if __name__ == "__main__":
    start_server() # Запускаем сервер, если скрипт выполняется напрямую
