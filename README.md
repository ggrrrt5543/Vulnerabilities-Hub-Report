##############################################################################
# ФАЙЛ: README.md
##############################################################################

# Hub App — Отчет по безопасности и руководство по устранению

## О проекте
Этот репозиторий содержит результаты аудита безопасности приложения Hub (org.hubnet.android) — веб-версии и мобильного API. В ходе тестирования были найдены уязвимости класса IDOR, позволяющие читать чужие сообщения, профили и метаданные чатов. Также найдена уязвимость User Enumeration.

## Краткое резюме
| # | Уязвимость | Критичность | Эндпоинт |
|---|-----------|-------------|----------|
| 1 | IDOR: чтение чужих сообщений | Критическая | GET /api/message/{chatId} |
| 2 | IDOR: чтение чужого профиля | Средняя | GET /api/profile/{publicId} |
| 3 | IDOR: чтение метаданных чата | Средняя | GET /api/chats/{chatId} |
| 4 | User Enumeration | Низкая | POST /api/auth/password/request-code |

**Что НЕ подтвердилось (защита работает):**
- RCE через загрузку файлов — сервер конвертирует в webp и вырезает код.
- XSS (Stored/Reflected) — HTML экранируется везде (bio, сообщения, названия групп).
- CSWSH — сервер строго проверяет заголовок Origin.
- SSRF — сервер не инициирует запросы по переданному URL.
- Подделка authorId/userId через WebSocket — сервер игнорирует эти поля.

## Структура репозитория
hub-audit/
├── README.md
├── FIXES_GUIDE.md
├── poc/
│   ├── idor_messages.sh
│   ├── idor_profile.sh
│   └── enum_emails.py
└── fixes/
    ├── idor_messages_flask.py
    ├── idor_profile_express.js
    ├── enum_fix_flask.py
    ├── nginx_ratelimit.conf
    ├── captcha_middleware.py
    ├── jwt_rotation.py
    └── ws_secure.py

## Описание уязвимостей

### 1. IDOR: Чтение чужих сообщений (Критическая)
**Эндпоинт:** GET /api/message/{chatId}?skip=0&take=20
**Суть проблемы:** Сервер проверяет валидность токена x-session-token, но не проверяет, является ли пользователь участником запрашиваемого чата. Любой авторизованный пользователь может выкачать историю сообщений из чужого чата, если знает его chatId.
**PoC:**
bash poc/idor_messages.sh oJcUOEDM5SnqDt4hzjBc44ByIyb_FvdB3rPztGVg5tM 34dcbb1e-9912-4e6b-82a0-271589e36df4
**Ожидаемый результат (уязвимо):** 200 OK + JSON с сообщениями чужого чата.
**Ожидаемый результат (после фикса):** 403 Access denied.

### 2. IDOR: Чтение чужого профиля (Средняя)
**Эндпоинт:** GET /api/profile/{publicId}
**Суть проблемы:** Любой авторизованный пользователь может получить профиль другого пользователя по его publicId. Сервер отдает имя, фамилию, дату регистрации, роль.
**PoC:**
bash poc/idor_profile.sh o8_1FxyP1amYg6W_3J7ogUmIjgn3UY6vUK1kPoBlKro fghhgg3453
**Ожидаемый результат (после фикса):** 403 если профиль не публичный.

### 3. IDOR: Чтение метаданных чата (Средняя)
**Эндпоинт:** GET /api/chats/{chatId}
**Суть проблемы:** Сервер не проверяет членство. Можно получить данные собеседника, тип чата, email владельца.

### 4. User Enumeration (Низкая)
**Эндпоинт:** POST /api/auth/password/request-code
**Суть проблемы:** Сервер возвращает разные ответы для существующих и несуществующих email.
**PoC:**
python poc/enum_emails.py babibasik@mail.ru qwerty123@mail.ru
**Ожидаемый результат (после фикса):** Все ответы 200 OK с текстом "Если аккаунт существует, код отправлен".

## 🔧 Как применять фиксы (Пошагово)
1. **Подготовка:** Сделай бэкап БД (pg_dump). Подними Redis (docker run -d -p 6379:6379 redis:7-alpine). Установи зависимости (pip install flask flask-jwt-extended sqlalchemy psycopg2-binary redis requests; npm install express pg jsonwebtoken).
2. **Миграции БД:** Добавь is_public BOOLEAN DEFAULT false в profiles. Убедись, что chat_members(chat_id, user_id) имеет составной PK.
3. **Патч IDOR (сообщения):** Замени хэндлер /api/message/{chatId} на код из fixes/idor_messages_flask.py.
4. **Патч IDOR (профиль):** Замени хэндлер /api/profile/{publicId} на код из fixes/idor_profile_express.js.
5. **Патч Enumeration:** Замени хэндлер /api/auth/password/request-code на код из fixes/enum_fix_flask.py.
6. **Rate Limiting и CAPTCHA:** Подключи конфиг fixes/nginx_ratelimit.conf. Добавь fixes/captcha_middleware.py на эндпоинты /request-code и /register.
7. **Ротация токенов:** Внедри /api/auth/refresh из fixes/jwt_rotation.py. Access-токен: 15 минут. Refresh-токен: 7 дней, с ротацией.
8. **WebSocket:** Замени логику на fixes/ws_secure.py. Токен передавай в первом сообщении после подключения, а не в query string.

## Чек-лист после внедрения
| Уязвимость | Проверка | Ожидание |
|-----------|----------|----------|
| IDOR messages | bash poc/idor_messages.sh <чужой_токен> <чужой_chatId> | 403 Access denied |
| IDOR profile | bash poc/idor_profile.sh <токен> <чужой_id> | 403 или 200 с ограниченными полями |
| IDOR metadata | curl .../api/chats/<чужой_chatId> | 403 |
| Enumeration | python poc/enum_emails.py nonexistent@test.com | 200 с унифицированным сообщением |
| CSWSH | WebSocket с Origin: https://evil.com | Соединение отклонено (400) |
| JWT expiry | Использовать старый access-токен через 20 минут | 401 Unauthorized |
| Refresh rotation | Использовать refresh дважды | Второй раз 401 + отзыв всех сессий |

## Дисклеймер
Данный репозиторий создан исключительно в образовательных целях. Все тесты проводились на тестовых аккаунтах в изолированной среде. Автор не несет ответственности за использование материалов третьими лицами.
