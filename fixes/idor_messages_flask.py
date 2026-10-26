# Серверные примеры защиты прав доступа, восстановления пароля и сессий.
"""Контроль доступа к сообщениям и метаданным на тестовой схеме SQLAlchemy."""

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, get_jwt_identity, jwt_required
from sqlalchemy import Integer, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    chat_id: Mapped[str] = mapped_column(String, index=True)
    text: Mapped[str] = mapped_column(String)
    author_id: Mapped[str] = mapped_column(String)


class ChatMember(Base):
    __tablename__ = "chat_members"
    chat_id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, primary_key=True)


class Chat(Base):
    __tablename__ = "chats"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String)


def is_member(db, chat_id, user_id):
    return db.get(ChatMember, (chat_id, user_id)) is not None


def create_app(engine, jwt_secret, session_is_active, issuer="hub-examples", audience="hub-api"):
    # Секрет передаёт вызывающее приложение; небезопасного значения по умолчанию нет.
    if len(jwt_secret.encode()) < 32:
        raise ValueError("Секрет JWT должен содержать не менее 32 байт")
    app = Flask(__name__)
    app.config.update(
        JWT_SECRET_KEY=jwt_secret,
        JWT_TOKEN_LOCATION=["headers"],
        JWT_DECODE_ISSUER=issuer,
        JWT_ENCODE_ISSUER=issuer,
        JWT_DECODE_AUDIENCE=audience,
        JWT_ENCODE_AUDIENCE=audience,
    )
    manager = JWTManager(app)

    @manager.token_in_blocklist_loader
    def token_is_revoked(_header, payload):
        # Ошибка хранилища не должна превращаться в разрешение доступа.
        return not session_is_active(payload)

    @manager.unauthorized_loader
    def missing_token(_reason):
        return jsonify(error="Требуется авторизация"), 401

    @manager.invalid_token_loader
    def invalid_token(_reason):
        return jsonify(error="Недействительный токен"), 401

    @manager.expired_token_loader
    def expired_token(_header, _payload):
        return jsonify(error="Срок действия токена истёк"), 401

    @manager.revoked_token_loader
    def revoked_token(_header, _payload):
        return jsonify(error="Сессия отозвана"), 401

    sessions = sessionmaker(bind=engine)

    @app.get("/api/message/<chat_id>")
    @jwt_required()
    def get_messages(chat_id):
        with sessions() as db:
            # Сначала проверка членства; затем чтение данных.
            if not is_member(db, chat_id, get_jwt_identity()):
                return jsonify(error="Доступ запрещён"), 403
            try:
                skip = int(request.args.get("skip", "0"))
                take = int(request.args.get("take", "20"))
            except (ValueError, TypeError):
                return jsonify(error="Параметры skip и take должны быть целыми"), 400
            if not 0 <= skip <= 100_000 or not 1 <= take <= 100:
                return jsonify(error="Допустимо: skip от 0 до 100000, take от 1 до 100"), 400
            query = (
                select(Message)
                .where(Message.chat_id == chat_id)
                .order_by(Message.id)
                .offset(skip)
                .limit(take)
            )
            return jsonify(
                [{"id": m.id, "text": m.text, "authorId": m.author_id} for m in db.scalars(query)]
            )

    @app.get("/api/chats/<chat_id>")
    @jwt_required()
    def get_chat(chat_id):
        with sessions() as db:
            if not is_member(db, chat_id, get_jwt_identity()):
                return jsonify(error="Доступ запрещён"), 403
            chat = db.get(Chat, chat_id)
            if chat is None:
                return jsonify(error="Чат не найден"), 404
            # Явный список полей: адрес владельца не раскрывается.
            return jsonify(id=chat.id, type=chat.kind)

    return app
