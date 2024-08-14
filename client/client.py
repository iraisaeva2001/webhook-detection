import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
from plyer import notification

class IncidentLoggerClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Incident Logger Client") # Устанавливаем заголовок окна

        self.connected = False # Флаг подключения к серверу
        self.sock = None # Сокет для соединения с сервером

        self.setup_connection_tab() # Настройка вкладки соединения
        self.setup_patterns_tab()  # Настройка вкладки шаблонов

    def setup_connection_tab(self):
        self.connection_frame = tk.Frame(self.master) # Создаем фрейм для соединения
        self.connection_frame.pack() # Упаковываем фрейм

        tk.Label(self.connection_frame, text="Server IP:").grid(row=0, column=0) # Метка для IP сервера
        self.ip_entry = tk.Entry(self.connection_frame) # Поле для ввода IP
        self.ip_entry.grid(row=0, column=1)  # Размещаем поле ввода в сетке

        tk.Label(self.connection_frame, text="Port:").grid(row=1, column=0) # Метка для порта
        self.port_entry = tk.Entry(self.connection_frame) # Поле для ввода порта
        self.port_entry.grid(row=1, column=1) # Размещаем поле ввода в сетке

        self.connect_button = tk.Button(self.connection_frame, text="Connect", command=self.connect_to_server) # Кнопка подключения
        self.connect_button.grid(row=2, column=0, columnspan=2) # Размещаем кнопку в сетке

        self.messages = scrolledtext.ScrolledText(self.connection_frame, state='disabled', width=50, height=10) # Поле для вывода сообщений с прокруткой
        self.messages.grid(row=3, column=0, columnspan=2) # Размещаем поле в сетке

        # Добавляем метку состояния снифера
        self.status_label = tk.Label(self.connection_frame, text="Sniffer Status: Stopped", fg="red") # Метка состояния снифера
        self.status_label.grid(row=4, column=0, columnspan=2) # Размещаем метку в сетке

    def setup_patterns_tab(self):
        self.pattern_frame = tk.Frame(self.master)  # Создаем фрейм для шаблонов
        self.pattern_frame.pack() # Упаковываем фрейм

        tk.Label(self.pattern_frame, text="Pattern:").grid(row=0, column=0) # Метка для шаблона
        self.pattern_entry = tk.Entry(self.pattern_frame) # Поле для ввода шаблона
        self.pattern_entry.grid(row=0, column=1) # Размещаем поле ввода в сетке

        tk.Label(self.pattern_frame, text="Name:").grid(row=1, column=0) # Метка для имени шаблона
        self.name_entry = tk.Entry(self.pattern_frame) # Поле для ввода имени
        self.name_entry.grid(row=1, column=1) # Размещаем поле ввода в сетке

        self.add_button = tk.Button(self.pattern_frame, text="Add Pattern", command=self.add_pattern) # Кнопка добавления шаблона
        self.add_button.grid(row=2, column=0, columnspan=2)   # Размещаем кнопку в сетке

        self.refresh_button = tk.Button(self.pattern_frame, text="Refresh Patterns", command=self.refresh_patterns) # Кнопка обновления шаблонов
        self.refresh_button.grid(row=2, column=2)  # Размещаем кнопку в сетке

        self.pattern_list_frame = tk.Frame(self.pattern_frame) # Фрейм для списка шаблонов
        self.pattern_list_frame.grid(row=3, column=0, columnspan=3) # Размещаем фрейм в сетке

        self.select_all_var = tk.BooleanVar() # Переменная для состояния "Выбрать все"
        self.select_all_cb = tk.Checkbutton(self.pattern_frame, text="Select All", variable=self.select_all_var,
                                            command=self.select_all) # Чекбокс "Выбрать все"
        self.select_all_cb.grid(row=4, column=0) # Размещаем чекбокс в сетке

        self.delete_button = tk.Button(self.pattern_frame, text="Delete Selected",
                                       command=self.delete_selected_patterns)  # Кнопка удаления выбранных шаблонов
        self.delete_button.grid(row=4, column=1) # Размещаем кнопку в сетке

        self.select_regex_button = tk.Button(self.pattern_frame, text="Select Regex", command=self.select_regex) # Кнопка выбора шаблонов
        self.select_regex_button.grid(row=4, column=2) # Размещаем кнопку в сетке

        self.deactivate_regex_button = tk.Button(self.pattern_frame, text="Deactivate Regex", command=self.deactivate_regex)  # Кнопка деактивации шаблонов
        self.deactivate_regex_button.grid(row=5, column=0) # Размещаем кнопку в сетке

        self.start_button = tk.Button(self.pattern_frame, text="Start Sniffing", command=self.start_sniffing) # Кнопка запуска сниффинга
        self.start_button.grid(row=5, column=1)  # Размещаем кнопку в сетке

        self.stop_button = tk.Button(self.pattern_frame, text="Stop Sniffing", command=self.stop_sniffing) # Кнопка остановки сниффинга
        self.stop_button.grid(row=5, column=2) # Размещаем кнопку в сетке

        self.checkboxes = [] # Список чекбоксов для шаблонов

    def select_regex(self):
        selected_patterns = [] # Список для выбранных шаблонов
        for cb in self.checkboxes:
            if cb.var.get(): # Если чекбокс выбран
                name, _ = cb.cget("text").split(": ", 1) # Извлекаем имя шаблона
                name = name.strip().split(" ")[0]  # Извлекаем только имя шаблона
                selected_patterns.append(name) # Добавляем имя в список

        if self.connected:  # Если соединение установлено
            command = f"SELECT_REGEX {' '.join(selected_patterns)}"  # Формируем команду для выбора шаблонов
            self.sock.sendall(command.encode('utf-8')) # Отправляем команду на сервер
            self.refresh_patterns() # Обновляем список после выбора

    def deactivate_regex(self):
        selected_patterns = [] # Список для деактивации шаблонов
        for cb in self.checkboxes:
            if cb.var.get(): # Если чекбокс выбран
                name, _ = cb.cget("text").split(": ", 1) # Извлекаем имя шаблона
                name = name.strip().split(" ")[0]   # Извлекаем только имя шаблона
                selected_patterns.append(name) # Добавляем имя в список

        if self.connected: # Если соединение установлено
            command = f"DEACTIVATE_REGEX {' '.join(selected_patterns)}" # Формируем команду для деактивации шаблонов
            self.sock.sendall(command.encode('utf-8')) # Отправляем команду на сервер
            self.refresh_patterns() # Обновляем список после деактивации

    def connect_to_server(self):
        if self.connected: # Если уже подключены, отключаемся
            self.sock.close() # Закрываем сокет
            self.connected = False # Обновляем флаг подключения
            self.connect_button.config(text="Connect") # Изменяем текст кнопки
            return

        server_ip = self.ip_entry.get() # Получаем IP сервера из поля ввода
        server_port = int(self.port_entry.get()) # Получаем порт сервера из поля ввода

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Создаем сокет TCP
        try:
            self.sock.connect((server_ip, server_port)) # Подключаемся к серверу
            self.connected = True  # Обновляем флаг подключения
            self.connect_button.config(text="Disconnect")  # Изменяем текст кнопки

            self.listen_thread = threading.Thread(target=self.listen_to_server) # Создаем поток для прослушивания сервера
            self.listen_thread.start() # Запускаем поток

            self.messages.config(state='normal') # Делаем текстовое поле доступным для записи
            self.messages.insert(tk.END, "Connected to server\n") # Выводим сообщение о подключении
            self.messages.config(state='disabled')  # Делаем текстовое поле доступным только для чтения
        except Exception as e: # Обработка исключений при подключении
            self.messages.config(state='normal')
            self.messages.insert(tk.END, f"Failed to connect: {e}\n") # Выводим сообщение об ошибке
            self.messages.config(state='disabled')

    def listen_to_server(self):
        try:
            while self.connected: # Пока подключение активно
                data = self.sock.recv(4096).decode('utf-8') # Получаем данные от сервера
                if not data: # Если данных нет, выходим из цикла
                    break
                if data.startswith("Patterns:"):  # Если получены шаблоны
                    self.update_patterns_list(data[len("Patterns:"):]) # Обновляем список шаблонов
                else: # В противном случае выводим сообщение
                    self.messages.config(state='normal')
                    self.messages.insert(tk.END, f"{data}\n")
                    self.messages.config(state='disabled')
                    notification.notify( # Отправляем уведомление
                        title="Incident Logger",
                        message=data,
                        app_name='Incident Logger'
                    )
                    # Обновление состояния снифера на основе полученных данных
                    if "Sniffing: Started" in data: # Если сниффинг начат
                        self.update_status_label("Running", "green")  # Обновляем метку состояния
                    elif "Sniffing: Stopped" in data: # Если сниффинг остановлен
                        self.update_status_label("Stopped", "red")  # Обновляем метку состояния
        except Exception as e: # Обработка ошибок при прослушивании
            self.messages.config(state='normal')
            self.messages.insert(tk.END, f"Error: {e}\n")
            self.messages.config(state='disabled')

    def update_patterns_list(self, patterns_data):
        patterns = patterns_data.split("|") # Разбиваем строку с шаблонами на отдельные шаблоны
        for cb in self.checkboxes: # Удаляем существующие чекбоксы
            cb.destroy()
        self.checkboxes.clear() # Очищаем список чекбоксов

        for pattern_data in patterns: # Проходим по каждому шаблону
            if ":" in pattern_data:
                name_and_status, pattern = pattern_data.split(": ", 1) # Разделяем имя и статус от шаблона
                name, status = name_and_status.split(" (", 1) # Разделяем имя и статус
                status = status.strip(")")

                var = tk.BooleanVar() # Создаем переменную для состояния чекбокса
                cb = tk.Checkbutton(self.pattern_list_frame, text=f"{name} ({status}): {pattern}", variable=var) # Создаем чекбокс
                cb.var = var # Присваиваем переменной чекбокса
                cb.pack(anchor='w')  # Размещаем чекбокс в фрейме
                self.checkboxes.append(cb)  # Добавляем чекбокс в список

    def add_pattern(self):
        pattern = self.pattern_entry.get().strip()  # Получаем шаблон из поля ввода
        name = self.name_entry.get().strip() # Получаем имя из поля ввода
        if pattern and name and self.connected:  # Если шаблон, имя не пустые и подключение активно
            command = f"ADD_PATTERN {pattern} {name}"  # Формируем команду для добавления шаблона
            self.sock.sendall(command.encode('utf-8')) # Отправляем команду на сервер
            self.refresh_patterns()  # Обновляем список шаблонов
            self.pattern_entry.delete(0, tk.END) # Очищаем поле ввода шаблона
            self.name_entry.delete(0, tk.END) # Очищаем поле ввода имени

    def delete_selected_patterns(self):
        if not self.connected: # Если не подключены, выходим
            return
        selected_names = [] # Список для удаления шаблонов
        for cb in self.checkboxes:
            if cb.var.get(): # Если чекбокс выбран
                name_and_status, _ = cb.cget("text").split(": ", 1)  # Извлекаем имя шаблона
                name = name_and_status.split(" (")[0]
                selected_names.append(name) # Добавляем имя в список
                cb.destroy() # Удаляем чекбокс

        self.checkboxes = [cb for cb in self.checkboxes if cb.var.get() == False] # Обновляем список чекбоксов
        if selected_names: # Если есть шаблоны для удаления
            command = f"DELETE_PATTERN {' '.join(selected_names)}" # Формируем команду для удаления
            self.sock.sendall(command.encode('utf-8')) # Отправляем команду на сервер
            self.refresh_patterns() # Обновляем список после удаления

    def refresh_patterns(self):
        if self.connected:  # Если подключение активно
            self.sock.sendall(b"GET_PATTERNS") # Отправляем запрос на получение шаблонов

    def select_all(self):
        for cb in self.checkboxes: # Устанавливаем состояние всех чекбоксов в зависимости от "Выбрать все"
            cb.var.set(self.select_all_var.get())

    def start_sniffing(self):
        if self.connected: # Если подключение активно
            self.sock.sendall(b"START") # Отправляем команду на старт сниффинга

    def stop_sniffing(self):
        if self.connected: # Если подключение активно
            self.sock.sendall(b"STOP")  # Отправляем команду на остановку сниффинга

    def update_status_label(self, status, color):
        self.status_label.config(text=f"Sniffer Status: {status}", fg=color) # Обновляем текст и цвет метки состояния

if __name__ == "__main__":
    root = tk.Tk()  # Создаем главное окно
    client = IncidentLoggerClient(root) # Создаем экземпляр клиента
    root.mainloop() # Запускаем главный цикл обработки событий
