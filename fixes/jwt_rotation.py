"""Ротация refresh-токенов с атомарным переходом состояния в Redis.

Одна семья соответствует одной сессии входа. Повторное использование отзывает
эту семью, но не все устройства пользователя. Redis должен быть общим для узлов.
"""

import uuid
from datetime import UTC, datetime

import jwt
from redis.exceptions import WatchError

ACCESS_TTL = 15 * 60
REFRESH_TTL = 7 * 24 * 60 * 60


class TokenService:
    def __init__(self, store, secret, issuer="hub-examples", audience="hub-api"):
        if len(secret.encode()) < 32:
            raise ValueError("Секрет JWT должен содержать не менее 32 байт")
        self.store, self.secret = store, secret
        self.issuer, self.audience = issuer, audience

    def _now(self):
        return int(datetime.now(UTC).timestamp())

    def _pair(self, user_id, family, deadline):
        now = self._now()
        common = {
            "sub": user_id,
            "sid": family,
            "iat": now,
            "iss": self.issuer,
            "aud": self.audience,
        }
        access = jwt.encode(
            {
                **common,
                "jti": str(uuid.uuid4()),
                "type": "access",
                "exp": min(now + ACCESS_TTL, deadline),
            },
            self.secret,
            algorithm="HS256",
        )
        refresh = jwt.encode(
            {**common, "jti": str(uuid.uuid4()), "type": "refresh", "exp": deadline},
            self.secret,
            algorithm="HS256",
        )
        return {"access": access, "refresh": refresh}

    def _decode(self, token, kind):
        data = jwt.decode(
            token,
            self.secret,
            algorithms=["HS256"],
            issuer=self.issuer,
            audience=self.audience,
            options={"require": ["sub", "sid", "jti", "iat", "exp", "type"]},
        )
        if data["type"] != kind or any(
            not isinstance(data[k], str) or not data[k] for k in ("sub", "sid", "jti")
        ):
            raise ValueError("Неверный тип или поля токена")
        return data

    def issue_tokens(self, user_id):
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("Нужен строковый идентификатор пользователя")
        family = str(uuid.uuid4())
        pair = self._pair(user_id, family, self._now() + REFRESH_TTL)
        data = self._decode(pair["refresh"], "refresh")
        self.store.setex(f"family:{family}", REFRESH_TTL, data["jti"])
        return pair

    def rotate_refresh(self, token):
        data = self._decode(token, "refresh")
        key = f"family:{data['sid']}"
        # WATCH защищает сравнение и замену от параллельного использования токена.
        for _ in range(10):
            with self.store.pipeline() as pipe:
                try:
                    pipe.watch(key)
                    current = pipe.get(key)
                    if isinstance(current, bytes):
                        current = current.decode()
                    if current is None:
                        raise ValueError("Сессия отозвана или истекла")
                    ttl = data["exp"] - self._now()
                    if ttl <= 0:
                        raise ValueError("Срок действия сессии истёк")
                    if current != data["jti"]:
                        pipe.multi()
                        pipe.delete(key)
                        pipe.execute()
                        raise ValueError("Повторный refresh: сессия отозвана")
                    pair = self._pair(data["sub"], data["sid"], data["exp"])
                    new_data = self._decode(pair["refresh"], "refresh")
                    pipe.multi()
                    pipe.setex(key, ttl, new_data["jti"])
                    pipe.execute()
                    return pair
                except WatchError:
                    continue
        raise RuntimeError("Конфликт обновления сессии; повторите запрос")

    def verify_access(self, token):
        data = self._decode(token, "access")
        # Проверка состояния обязательна: без неё отзыв не остановит access-токен.
        if not self.session_is_active(data):
            raise ValueError("Сессия отозвана или истекла")
        return data

    def session_is_active(self, verified_payload):
        """Вызывать только после проверки подписи, exp, iss, aud и типа JWT."""
        family = verified_payload.get("sid")
        return (
            isinstance(family, str)
            and bool(family)
            and self.store.get(f"family:{family}") is not None
        )

    def revoke_session(self, token):
        data = self._decode(token, "access")
        self.store.delete(f"family:{data['sid']}")
