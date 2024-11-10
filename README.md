
# 📧 Secure Chat Application using Diffie-Hellman Algorithm

## Language

<details>

<summary>🇷🇺 Русский</summary>

# 📧 Приложение для Безопасного Чата с Использованием Алгоритма Диффи-Хеллмана

**Автор:** Бекзат Жаксыбаев  
**Курсовая работа для:** Студента первого курса магистратуры

## 📖 Описание Проекта
Данное приложение представляет собой безопасный чат, реализующий алгоритм обмена ключами Диффи-Хеллмана для обеспечения защищенной связи между пользователями.

### Основные возможности:
- 🔐 **Безопасный обмен ключами:** Использование алгоритма Диффи-Хеллмана для установления общего секретного ключа
- 🛡️ **Шифрование сообщений:** Симметричное шифрование (AES) для защиты передаваемых сообщений
- 💬 **Удобный интерфейс:** Простое и интуитивно понятное веб-приложение для общения

## 🚀 Начало Работы

### 📋 Предварительные Требования
- Python 3.x
- MongoDB (локальная установка или MongoDB Atlas)
- Virtual Environment (виртуальное окружение, рекомендуется)
- Node.js и NPM (для установки фронтенд-зависимостей, если требуется)

### 🔧 Установка и Настройка

1. **Клонируйте репозиторий:**
```bash
git clone https://github.com/elapen/secure_chat.git
cd secure_chat
```

2. **Создайте виртуальное окружение:**
```bash
# На Windows
python -m venv venv
venv\Scripts\activate

# На macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Установите зависимости:**
```bash
pip install -r requirements.txt
```

4. **Настройте переменные окружения:**
   
   Создайте файл `.env` в корневой директории проекта со следующим содержимым:
```env
MONGODB_URL="your_mongodb_connection_string"
```
   *Важно:* Замените "your_mongodb_connection_string" на ваш реальный URL подключения к MongoDB.

5. **Запустите MongoDB (если используете локально):**
```bash
# На Windows
net start MongoDB

# На macOS/Linux
sudo service mongod start
```

6. **Запустите приложение:**
```bash
python app.py
```

Приложение будет доступно по адресу `http://localhost:5000`.

## 🌐 Использование

1. **Откройте приложение в браузере:**
```
http://localhost:5000
```

2. **Войдите в систему:**
   - Введите уникальное имя пользователя
   - После входа будут сгенерированы ключи Диффи-Хеллмана

3. **Начните общение:**
   - Введите имя пользователя получателя
   - Напишите сообщение и нажмите Отправить
   - Сообщение будет зашифровано и отправлено получателю

## 📁 Структура Проекта
```
secure_chat/
├── app.py
├── templates/
│   ├── index.html
│   └── chat.html
├── static/
│   └── (статические файлы, например, CSS или JS)
├── requirements.txt
├── .env
└── README.md
```

- `app.py`: Основной файл приложения Flask
- `templates/`: HTML-шаблоны для фронтенда
- `static/`: Статические файлы (стили, скрипты)
- `requirements.txt`: Список зависимостей Python
- `.env`: Файл с переменными окружения (MongoDB URL)

## 🛠️ Технологии и Библиотеки

### Backend:
- Flask: Легковесный веб-фреймворк для Python
- Flask-SocketIO: Реализация Socket.IO для Flask
- PyMongo: Официальный драйвер MongoDB для Python
- PyCryptodome: Криптографические примитивы для Python
- python-dotenv: Работа с переменными окружения

### Frontend:
- Socket.IO: Библиотека для работы с WebSocket
- BigInteger.js: Работа с большими целыми числами в JavaScript
- CryptoJS: Криптографические функции для JavaScript

## 👨‍💻 Об Авторе
Бекзат Жаксыбаев — студент первого курса магистратуры, разработал это приложение в рамках курсовой работы, демонстрируя применение криптографических алгоритмов на практике.

## 📞 Контакты
- Email: bekzat.zhm@gmail.com
- GitHub: https://github.com/elapen/secure_chat

## 📄 Лицензия
Этот проект лицензирован на условиях лицензии MIT — подробности см. в файле LICENSE.

## 🙏 Благодарности
- **Университет:** За предоставленную возможность и ресурсы для разработки проекта
- **Преподаватели и Наставники:** За поддержку и руководство

</details>

<details>
<summary>🇺🇸 English</summary>

**Author:** Bekzat Zhaksybayev  
**Course Work for:** First-year Master's Student

## 📖 Project Description
This application is a secure chat that implements the Diffie-Hellman key exchange algorithm to ensure protected communication between users.

### Key Features:
- 🔐 **Secure Key Exchange:** Implementation of the Diffie-Hellman algorithm for establishing a shared secret key
- 🛡️ **Message Encryption:** Symmetric encryption (AES) for protecting transmitted messages
- 💬 **User-Friendly Interface:** Simple and intuitive web application for communication

## 🚀 Getting Started

### 📋 Prerequisites
- Python 3.x
- MongoDB (local installation or MongoDB Atlas)
- Virtual Environment (recommended)
- Node.js and NPM (for frontend dependencies if required)

### 🔧 Installation and Setup

1. **Clone the repository:**
```bash
git clone https://github.com/elapen/secure_chat.git
cd secure_chat
```

2. **Create a virtual environment:**
```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables:**
   
   Create a `.env` file in the project root directory with the following content:
```env
MONGODB_URL="your_mongodb_connection_string"
```
   *Important:* Replace "your_mongodb_connection_string" with your actual MongoDB connection URL.

5. **Start MongoDB (if using locally):**
```bash
# On Windows
net start MongoDB

# On macOS/Linux
sudo service mongod start
```

6. **Run the application:**
```bash
python app.py
```

The application will be available at `http://localhost:5000`.

## 🌐 Usage

1. **Open the application in a browser:**
```
http://localhost:5000
```

2. **Log in:**
   - Enter a unique username
   - Diffie-Hellman keys will be generated after login

3. **Start chatting:**
   - Enter the recipient's username
   - Write a message and click Send
   - The message will be encrypted and sent to the recipient

## 📁 Project Structure
```
secure_chat/
├── app.py
├── templates/
│   ├── index.html
│   └── chat.html
├── static/
│   └── (static files, e.g., CSS or JS)
├── requirements.txt
├── .env
└── README.md
```

- `app.py`: Main Flask application file
- `templates/`: HTML templates for frontend
- `static/`: Static files (styles, scripts)
- `requirements.txt`: Python dependencies list
- `.env`: Environment variables file (MongoDB URL)

## 🛠️ Technologies and Libraries

### Backend:
- Flask: Lightweight web framework for Python
- Flask-SocketIO: Socket.IO implementation for Flask
- PyMongo: Official MongoDB driver for Python
- PyCryptodome: Cryptographic primitives for Python
- python-dotenv: Environment variables management

### Frontend:
- Socket.IO: WebSocket library
- BigInteger.js: Large integer operations in JavaScript
- CryptoJS: Cryptographic functions for JavaScript

## 👨‍💻 About the Author
Bekzat Zhaksybayev — first-year Master's student, developed this application as part of coursework, demonstrating the practical application of cryptographic algorithms.

## 📞 Contacts
- Email: bekzat.zhm@gmail.com
- GitHub: https://github.com/elapen/secure_chat

## 📄 License
This project is licensed under the MIT License — see the LICENSE file for details.

## 🙏 Acknowledgments
- **University:** For providing the opportunity and resources for project development
- **Teachers and Mentors:** For support and guidance

</details>
