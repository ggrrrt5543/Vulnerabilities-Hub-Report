// Регрессионные проверки авторизации, доступа к данным и безопасности сессий.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApp } = require('../fixes/idor_profile_express');
const secret = 's'.repeat(48);
const options = { issuer: 'hub-examples', audience: 'hub-api' };

function token(payload = {}, signOptions = {}) {
  return jwt.sign({ sub: 'alice', type: 'access', ...payload }, secret,
    { algorithm: 'HS256', expiresIn: '15m', ...options, ...signOptions });
}

async function withServer(pool, run, sessionIsActive = async () => true) {
  const server = createApp({ pool, jwtSecret: secret, ...options, sessionIsActive }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const url = `http://127.0.0.1:${server.address().port}/api/profile/public-a`;
  try { await run(url); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

// Это модель доступа для тестов, а не реальный PostgreSQL.
function fakePool({ isPublic = false, owner = 'alice', missing = false } = {}) {
  return { async query(sql, args) {
    assert.match(sql, /user_id = \$2 OR is_public = TRUE/);
    assert.deepEqual(args, ['public-a', 'alice']);
    if (missing || (!isPublic && owner !== args[1])) return { rowCount: 0, rows: [] };
    return { rowCount: 1, rows: [{ public_id: 'public-a', first_name: 'Алиса', email: 'private', role: 'admin' }] };
  } };
}

for (const [name, config, status] of [
  ['Свой профиль', {}, 200], ['Чужой закрытый', { owner: 'bob' }, 403],
  ['Чужой публичный', { owner: 'bob', isPublic: true }, 200],
  ['Отсутствующий', { missing: true }, 403],
]) {
  test(name, async () => withServer(fakePool(config), async url => {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token()}` } });
    assert.equal(response.status, status);
    if (status === 200) assert.deepEqual(await response.json(), {
      profile: { public_id: 'public-a', first_name: 'Алиса' },
    });
  }));
}

test('Отказ без токена, с refresh, просроченным, неверной аудиторией или подписью', async () => {
  const pool = { query() { throw new Error('БД не должна вызываться'); } };
  await withServer(pool, async url => {
    const invalid = ['', 'not-a-jwt', token({ type: 'refresh' }),
      token({}, { expiresIn: -1 }), token({}, { audience: 'other' }),
      jwt.sign({ sub: 'alice', type: 'access' }, 'x'.repeat(48), { expiresIn: '15m', ...options })];
    for (const value of invalid) {
      const response = await fetch(url, { headers: { Authorization: `Bearer ${value}` } });
      assert.equal(response.status, 401);
    }
  });
});

test('Ошибки БД не раскрываются клиенту', async () => withServer({
  async query() { throw new Error('Секретное подключение'); },
}, async url => {
  const response = await fetch(url, { headers: { Authorization: `Bearer ${token()}` } });
  assert.equal(response.status, 500);
  assert.deepEqual(await response.json(), { error: 'Внутренняя ошибка сервера' });
}));

test('Запрещены слабые настройки', () => {
  assert.throws(() => createApp({ pool: {}, jwtSecret: 'short', ...options }));
});


test('Отозванная сессия и сбой хранилища не дают доступ', async () => {
  for (const check of [async () => false, async () => { throw new Error('offline'); }]) {
    await withServer({ query() { throw new Error('БД не должна вызываться'); } }, async url => {
      const response = await fetch(url, { headers: { Authorization: `Bearer ${token()}` } });
      assert.equal(response.status, 401);
    }, check);
  }
});
