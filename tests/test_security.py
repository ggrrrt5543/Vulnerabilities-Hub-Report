import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import AsyncMock, Mock

import fakeredis
import jwt
import pytest
import requests
import socketio
from flask import Flask
from flask_jwt_extended import create_access_token, create_refresh_token
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from fixes.captcha_middleware import require_captcha, verify_captcha
from fixes.enum_fix_flask import create_app as create_reset_app
from fixes.idor_messages_flask import Base, Chat, ChatMember, Message, create_app
from fixes.jwt_rotation import TokenService
from fixes.ws_secure import create_server

SECRET = "s" * 48


@pytest.fixture
def api():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Chat(id="chat-a", kind="private"),
                ChatMember(chat_id="chat-a", user_id="alice"),
                Message(id=1, chat_id="chat-a", author_id="alice", text="Первое"),
                Message(id=2, chat_id="chat-a", author_id="alice", text="Второе"),
            ]
        )
        db.commit()
    app = create_app(engine, SECRET, lambda _payload: True)
    app.config["TESTING"] = True

    def token(user="alice", **kwargs):
        with app.app_context():
            return {"Authorization": "Bearer " + create_access_token(identity=user, **kwargs)}

    yield app.test_client(), token, app, engine
    engine.dispose()


@pytest.mark.parametrize("path", ["/api/message/chat-a", "/api/chats/chat-a"])
def test_no_anonymous_or_foreign_access(api, path):
    client, token, _, _ = api
    assert client.get(path).status_code == 401
    assert client.get(path, headers=token("bob")).status_code == 403
    assert client.get(path.replace("chat-a", "absent"), headers=token()).status_code == 403


def test_read_and_pagination(api):
    client, token, _, _ = api
    response = client.get("/api/message/chat-a?skip=1&take=1", headers=token())
    assert response.status_code == 200
    assert response.json == [{"id": 2, "text": "Второе", "authorId": "alice"}]
    assert client.get("/api/chats/chat-a", headers=token()).json == {
        "id": "chat-a",
        "type": "private",
    }


@pytest.mark.parametrize(
    "query",
    [
        "skip=-1",
        "skip=100001",
        "take=0",
        "take=101",
        "skip=no",
        "take=1.5",
        "take=",
    ],
)
def test_bad_pagination(api, query):
    client, token, _, _ = api
    assert client.get("/api/message/chat-a?" + query, headers=token()).status_code == 400


def test_membership_revocation(api):
    client, token, _, engine = api
    headers = token()
    with Session(engine) as db:
        db.delete(db.get(ChatMember, ("chat-a", "alice")))
        db.commit()
    assert client.get("/api/message/chat-a", headers=headers).status_code == 403


def test_expired_and_refresh_tokens_rejected(api):
    client, token, app, _ = api
    assert (
        client.get(
            "/api/message/chat-a",
            headers=token(expires_delta=timedelta(seconds=-1)),
        ).status_code
        == 401
    )
    with app.app_context():
        refresh = create_refresh_token(identity="alice")
    assert (
        client.get(
            "/api/message/chat-a",
            headers={"Authorization": "Bearer " + refresh},
        ).status_code
        == 401
    )


def test_reset_is_uniform_and_queued():
    queue = []
    client = create_reset_app(queue.append).test_client()
    first = client.post("/api/auth/password/request-code", json={"email": "known@example.test"})
    second = client.post("/api/auth/password/request-code", json={"email": "missing@example.test"})
    assert first.status_code == second.status_code == 200
    assert first.data == second.data
    assert queue == ["known@example.test", "missing@example.test"]


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {"email": 1},
        {"email": ""},
        {"email": "a b@x"},
        {"email": "@x"},
        {"email": "a@@x"},
    ],
)
def test_invalid_reset_input(body):
    queue = Mock()
    client = create_reset_app(queue).test_client()
    assert client.post("/api/auth/password/request-code", json=body).status_code == 400
    queue.assert_not_called()


def test_queue_unavailable():
    client = create_reset_app(Mock(side_effect=RuntimeError("offline"))).test_client()
    assert (
        client.post("/api/auth/password/request-code", json={"email": "a@example.test"}).status_code
        == 503
    )


def captcha_response(data):
    response = Mock()
    response.json.return_value = data
    return Mock(return_value=response)


def test_captcha_provider_and_hostname():
    assert verify_captcha(
        "token",
        "secret",
        "example.test",
        captcha_response({"success": True, "hostname": "example.test"}),
    )
    assert not verify_captcha(
        "token",
        "secret",
        "example.test",
        captcha_response({"success": True, "hostname": "other.test"}),
    )
    assert not verify_captcha("token", "secret", "example.test", captcha_response([]))
    assert not verify_captcha("token", "secret", "example.test", Mock(side_effect=requests.Timeout))
    assert not verify_captcha("", "secret", "example.test")


def test_captcha_decorator_preserves_endpoint_names():
    app = Flask(__name__)

    @app.post("/first")
    @require_captcha("secret", "example.test")
    def first():
        return "ok"

    @app.post("/second")
    @require_captcha("secret", "example.test")
    def second():
        return "ok"

    assert app.test_client().post("/first", json=[]).status_code == 400


@pytest.fixture
def tokens():
    return TokenService(fakeredis.FakeRedis(), SECRET)


def test_rotation_and_replay_revokes_family(tokens):
    original = tokens.issue_tokens("alice")
    second = tokens.rotate_refresh(original["refresh"])
    assert tokens.verify_access(second["access"])["sub"] == "alice"
    assert original["refresh"] != second["refresh"]
    with pytest.raises(ValueError, match="Повторный"):
        tokens.rotate_refresh(original["refresh"])
    for access in (original["access"], second["access"]):
        with pytest.raises(ValueError):
            tokens.verify_access(access)
    with pytest.raises(ValueError):
        tokens.rotate_refresh(second["refresh"])


def test_logout_isolates_other_sessions(tokens):
    first, other = tokens.issue_tokens("alice"), tokens.issue_tokens("alice")
    tokens.revoke_session(first["access"])
    with pytest.raises(ValueError):
        tokens.verify_access(first["access"])
    with pytest.raises(ValueError):
        tokens.rotate_refresh(first["refresh"])
    assert tokens.verify_access(other["access"])["sub"] == "alice"


def test_token_type_and_claims(tokens):
    pair = tokens.issue_tokens("alice")
    with pytest.raises(ValueError):
        tokens.verify_access(pair["refresh"])
    with pytest.raises(ValueError):
        tokens.rotate_refresh(pair["access"])
    with pytest.raises(jwt.InvalidTokenError):
        tokens.verify_access("invalid")
    with pytest.raises(jwt.InvalidTokenError):
        tokens.verify_access(jwt.encode({"sub": "alice"}, SECRET, algorithm="HS256"))


def test_refresh_deadline_is_absolute(tokens):
    first = tokens.issue_tokens("alice")
    second = tokens.rotate_refresh(first["refresh"])
    assert tokens._decode(first["refresh"], "refresh")["exp"] == tokens._decode(
        second["refresh"],
        "refresh",
    )["exp"]


def test_concurrent_refresh_one_winner_and_revoke(tokens):
    first = tokens.issue_tokens("alice")

    def rotate():
        try:
            return tokens.rotate_refresh(first["refresh"])
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: rotate(), range(2)))
    winners = [item for item in results if item]
    assert len(winners) == 1
    with pytest.raises(ValueError):
        tokens.verify_access(winners[0]["access"])


def test_expiry_signature_and_store_failure(tokens):
    pair = tokens.issue_tokens("alice")
    payload = tokens._decode(pair["access"], "access")
    payload["exp"] = 1
    with pytest.raises(jwt.ExpiredSignatureError):
        tokens.verify_access(jwt.encode(payload, SECRET, algorithm="HS256"))
    payload["exp"] = tokens._now() + 60
    with pytest.raises(jwt.InvalidSignatureError):
        tokens.verify_access(jwt.encode(payload, "x" * 48, algorithm="HS256"))
    tokens.store = Mock()
    tokens.store.get.side_effect = ConnectionError("offline")
    with pytest.raises(ConnectionError):
        tokens.verify_access(pair["access"])


def test_socket_auth_membership_and_author():
    async def run():
        lookup = AsyncMock(return_value={"id": "alice"})
        member = AsyncMock(return_value=True)
        save = AsyncMock()
        sio = create_server(lookup, member, save, ["https://example.test"])
        sio.save_session = AsyncMock()
        sio.get_session = AsyncMock(return_value={"user_id": "alice", "token": "valid"})
        sio.disconnect = AsyncMock()
        connect = sio.handlers["/"]["connect"]
        send = sio.handlers["/"]["sendMessage"]
        assert await connect("sid", {}, None) is False
        assert await connect("sid", {}, {"token": "valid"}) is True
        data = {"chatId": "chat-a", "text": "Привет", "authorId": "bob"}
        assert await send("sid", data) == {"status": "ok"}
        save.assert_awaited_once_with("chat-a", "alice", "Привет")
        member.return_value = False
        assert "error" in await send("sid", data)
        assert save.await_count == 1
        member.return_value = True
        assert "error" in await send("sid", [])
        assert "error" in await send("sid", {"chatId": "chat-a", "text": "x" * 4001})
        lookup.return_value = None
        assert "error" in await send("sid", data)
        sio.disconnect.assert_awaited_once_with("sid")

    asyncio.run(run())


def test_socket_rejects_foreign_origin_at_engineio_layer():
    async def run():
        sio = create_server(AsyncMock(), AsyncMock(), AsyncMock(), ["https://example.test"])
        app = socketio.ASGIApp(sio)
        send = AsyncMock()
        receive = AsyncMock(return_value={"type": "http.request", "body": b"", "more_body": False})
        await app(
            {
                "type": "http",
                "method": "GET",
                "path": "/socket.io/",
                "query_string": b"EIO=4&transport=polling",
                "scheme": "https",
                "headers": [(b"origin", b"https://other.test"), (b"host", b"example.test")],
                "server": ("example.test", 443),
                "client": ("127.0.0.1", 1234),
                "http_version": "1.1",
            },
            receive,
            send,
        )
        assert send.call_args_list[0].args[0]["status"] == 400

    asyncio.run(run())


def test_flask_integration_with_session_revocation():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(ChatMember(chat_id="chat-a", user_id="alice"))
        db.commit()
    service = TokenService(fakeredis.FakeRedis(), SECRET)
    client = create_app(engine, SECRET, service.session_is_active).test_client()
    pair = service.issue_tokens("alice")
    headers = {"Authorization": "Bearer " + pair["access"]}
    assert client.get("/api/message/chat-a", headers=headers).status_code == 200
    service.revoke_session(pair["access"])
    assert client.get("/api/message/chat-a", headers=headers).status_code == 401
    engine.dispose()
