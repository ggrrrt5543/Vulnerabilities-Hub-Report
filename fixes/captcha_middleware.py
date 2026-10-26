# Серверные примеры защиты прав доступа, восстановления пароля и сессий.
"""Проверка CAPTCHA с отказом при ошибках провайдера."""

from functools import wraps

import requests
from flask import jsonify, request


def verify_captcha(token, secret, expected_hostname, post=requests.post):
    if not isinstance(token, str) or not token or len(token) > 8192:
        return False
    if not secret or not expected_hostname:
        return False
    try:
        response = post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": secret, "response": token},
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        return (
            isinstance(data, dict)
            and data.get("success") is True
            and data.get("hostname") == expected_hostname
        )
    except (requests.RequestException, ValueError):
        return False


def require_captcha(secret, expected_hostname):
    # Пример для reCAPTCHA v2; для v3 нужны также проверки action и score.
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True)
            token = data.get("captcha") if isinstance(data, dict) else None
            if not verify_captcha(token, secret, expected_hostname):
                return jsonify(error="Проверка CAPTCHA не пройдена"), 400
            return func(*args, **kwargs)

        return wrapper

    return decorator
