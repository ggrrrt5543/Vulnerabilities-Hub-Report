"""Одинаковый ответ без поиска аккаунта в HTTP-обработчике."""

from flask import Flask, jsonify, request

MESSAGE = "Если аккаунт существует, код отправлен"


def create_app(enqueue_request):
    """enqueue_request ставит в очередь ЛЮБОЙ синтаксически допустимый адрес.

    Рабочий процесс отдельно проверяет существование пользователя, создаёт
    одноразовый код с TTL и отправляет письмо. Реализация очереди здесь не скрыта
    за pass: её обязан предоставить интегратор. Задержка sleep защитой не является.
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 4096

    @app.post("/api/auth/password/request-code")
    def request_code():
        data = request.get_json(silent=True)
        email = data.get("email") if isinstance(data, dict) else None
        if not isinstance(email, str):
            return jsonify(error="Укажите корректный адрес электронной почты"), 400
        email = email.strip()
        if (
            len(email) > 254
            or email.count("@") != 1
            or any(c.isspace() or ord(c) < 32 for c in email)
            or not all(email.split("@"))
        ):
            return jsonify(error="Укажите корректный адрес электронной почты"), 400
        # Не меняем регистр локальной части: нормализация должна совпадать с регистрацией.
        try:
            enqueue_request(email)
        except Exception:
            app.logger.exception("Очередь запросов восстановления недоступна")
            return jsonify(error="Сервис временно недоступен"), 503
        return jsonify(message=MESSAGE), 200

    return app
