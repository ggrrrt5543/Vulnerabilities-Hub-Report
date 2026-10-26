# Сценарий проверки прав доступа на явно заданном тестовом стенде.
"""Сравнение HTTP-ответов двух СВОИХ тестовых адресов без массового перебора."""

import argparse
import os
from urllib.parse import urlsplit

import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("existing", help="Адрес вашего зарегистрированного тестового аккаунта")
    parser.add_argument("missing", help="Контрольный адрес в вашем тестовом домене")
    args = parser.parse_args()
    base = os.environ.get("BASE_URL", "")
    parsed = urlsplit(base)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (
            parsed.scheme != "https"
            and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"})
        )
    ):
        parser.error("Укажите BASE_URL разрешённого HTTPS-стенда или localhost")
    results = []
    try:
        for email in (args.existing, args.missing):
            response = requests.post(
                base.rstrip("/") + "/api/auth/password/request-code",
                json={"email": email},
                timeout=10,
                allow_redirects=False,
            )
            results.append((response.status_code, response.content))
    except requests.RequestException:
        parser.exit(1, "Ошибка запроса к тестовому стенду\n")
    print("Коды HTTP:", results[0][0], results[1][0])
    print("Тела ответов совпадают:", "да" if results[0][1] == results[1][1] else "нет")
    print("Это не доказывает существование аккаунта и не проверяет временные каналы.")


if __name__ == "__main__":
    main()
