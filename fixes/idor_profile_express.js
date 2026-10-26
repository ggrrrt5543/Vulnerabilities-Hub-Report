'use strict';
const express = require('express');
const jwt = require('jsonwebtoken');
function createApp({ pool, jwtSecret, issuer, audience, sessionIsActive }) {
  if (!jwtSecret || Buffer.byteLength(jwtSecret) < 32 || !issuer || !audience || typeof sessionIsActive !== 'function') {
    throw new Error('Нужны секрет не менее 32 байт, издатель, аудитория и проверка сессии');
  }
  const app = express();
  app.disable('x-powered-by');

  async function authMiddleware(req, res, next) {
    const header = req.get('authorization') || '';
    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Требуется авторизация' });
    }
    try {
      const payload = jwt.verify(header.slice(7), jwtSecret, {
        algorithms: ['HS256'], issuer, audience,
      });
      if (typeof payload !== 'object' || payload.type !== 'access' ||
          typeof payload.sub !== 'string' || !payload.sub ||
          !Number.isInteger(payload.exp)) throw new Error('Неверные поля токена');
      if (!await sessionIsActive(payload)) {
        return res.status(401).json({ error: 'Сессия отозвана' });
      }
      req.userId = payload.sub;
      next();
    } catch {
      return res.status(401).json({ error: 'Недействительный токен' });
    }
  }

  app.get('/api/profile/:publicId', authMiddleware, async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT public_id, first_name FROM profiles
         WHERE public_id = $1 AND (user_id = $2 OR is_public = TRUE)`,
        [req.params.publicId, req.userId],
      );
      if (!result.rowCount) return res.status(403).json({ error: 'Доступ запрещён' });
      const { public_id, first_name } = result.rows[0];
      return res.json({ profile: { public_id, first_name } });
    } catch {
      return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
  });
  return app;
}

module.exports = { createApp };
