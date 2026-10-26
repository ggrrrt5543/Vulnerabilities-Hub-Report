# Серверные примеры защиты прав доступа, восстановления пароля и сессий.
"""Socket.IO: авторизация на этапе соединения и проверка членства на отправке.

Это Socket.IO, а не совместимый с произвольным WebSocket-клиентом сервер.
Зависимости передаются явно; пустых заглушек чтения БД нет.
"""

import socketio


def create_server(lookup_user_by_token, db_member_exists, save_message, allowed_origins):
    if not allowed_origins or "*" in allowed_origins:
        raise ValueError("Нужен явный список разрешённых источников")
    sio = socketio.AsyncServer(
        async_mode="asgi", cors_allowed_origins=list(allowed_origins), max_http_buffer_size=16_384
    )

    @sio.event
    async def connect(sid, environ, auth):
        # Клиент передаёт auth={token: ...} в пакете подключения Socket.IO, не в URL.
        token = auth.get("token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token or len(token) > 8192:
            return False
        user = await lookup_user_by_token(token)
        if not isinstance(user, dict) or (not isinstance(user.get("id"), str) or not user["id"]):
            return False
        await sio.save_session(sid, {"user_id": user["id"], "token": token})
        return True

    @sio.event
    async def sendMessage(sid, data):
        try:
            session = await sio.get_session(sid)
        except KeyError:
            return {"error": "Требуется авторизация"}
        # Повторная проверка выявляет истечение и отзыв токена после подключения.
        user = await lookup_user_by_token(session.get("token"))
        if not isinstance(user, dict) or user.get("id") != session.get("user_id"):
            await sio.disconnect(sid)
            return {"error": "Требуется авторизация"}
        if not isinstance(data, dict):
            return {"error": "Неверный формат сообщения"}
        chat_id, text = data.get("chatId"), data.get("text")
        if (
            not isinstance(chat_id, str)
            or not 1 <= len(chat_id) <= 128
            or not isinstance(text, str)
            or not text.strip()
            or len(text) > 4000
        ):
            return {"error": "Неверный чат или текст сообщения"}
        if not await db_member_exists(session["user_id"], chat_id):
            return {"error": "Доступ запрещён"}
        # authorId и userId из входных данных не используются.
        await save_message(chat_id, session["user_id"], text)
        return {"status": "ok"}

    # Подписки и рассылка намеренно не реализованы: удалённый участник не должен
    # оставаться в комнате и продолжать получать события без новой проверки доступа.
    return sio
