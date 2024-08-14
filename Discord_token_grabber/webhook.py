import pyshark

# Функция для анализа пакетов и обнаружения веб-хуков
def analyze_packets(interface):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=10)  # Захватываем пакеты в течение 10 секунд (можете изменить время по своему усмотрению)

    # Проходим по каждому захваченному пакету
    for packet in capture:
        # Проверяем, является ли пакет HTTP-запросом
        if 'HTTP' in packet:
            # Если да, проверяем, содержит ли запрос информацию о веб-хуке (например, путь или заголовки)
            if '89b2-178-66-197-39.ngrok-free.app' in packet.http.request_uri.lower() or '89b2-178-66-197-39.ngrok-free.app"' in str(packet.http):
                # Если в запросе присутствует информация о веб-хуке, выводим соответствующее сообщение
                print("Detected webhook traffic:")
                print(packet)
                print("=" * 50)

# Вызов функции для анализа пакетов на определенном сетевом интерфейсе (например, 'eth0' на Linux)
analyze_packets('Ethernet0')  # Замените 'eth0' на имя вашего сетевого интерфейса
