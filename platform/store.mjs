// User/entitlement store for Juss Protect Me.
// Production: Cloudflare KV binding USERS_KV. Local/tests: in-memory.
// Same contract either way — the payments module never knows which.
//
// Record shapes:
//   user:<id>        { id, email, plan, entitlement, stripeCustomerId,
//                      apiKeyHash, apiKeyPrefix, createdAt, updatedAt }
//   email:<email>    -> user id
//   event:<stripeId> -> processed marker (webhook idempotency)
//   ledger           -> { payments: [{ amount, currency, mode, at, email }] }

export function createStore(env = {}) {
  if (env.USERS_KV) {
    const kv = env.USERS_KV;
    return {
      kind: 'kv',
      async get(key) { const v = await kv.get(key); return v ? JSON.parse(v) : null; },
      async put(key, value) { await kv.put(key, JSON.stringify(value)); },
      async del(key) { await kv.delete(key); },
    };
  }
  const map = new Map();
  return {
    kind: 'memory',
    async get(key) { return map.has(key) ? structuredClone(map.get(key)) : null; },
    async put(key, value) { map.set(key, structuredClone(value)); },
    async del(key) { map.delete(key); },
  };
}

export async function getUserByEmail(store, email) {
  const id = await store.get(`email:${email}`);
  return id ? store.get(`user:${id}`) : null;
}

export async function saveUser(store, user) {
  await store.put(`user:${user.id}`, user);
  await store.put(`email:${user.email}`, user.id);
  return user;
}

export async function listUsers(store) {
  // KV listing is prefix-based; the memory store tracks an index key.
  const ids = (await store.get('index:users')) || [];
  const users = [];
  for (const id of ids) {
    const u = await store.get(`user:${id}`);
    if (u) users.push(u);
  }
  return users;
}

export async function addUser(store, user) {
  const ids = (await store.get('index:users')) || [];
  if (!ids.includes(user.id)) {
    ids.push(user.id);
    await store.put('index:users', ids);
  }
  return saveUser(store, user);
}

export async function recordPayment(store, payment) {
  const ledger = (await store.get('ledger')) || { payments: [] };
  ledger.payments.push(payment);
  await store.put('ledger', ledger);
  return ledger;
}

export async function statsFromStore(store) {
  const users = await listUsers(store);
  const ledger = (await store.get('ledger')) || { payments: [] };
  return {
    users: users.length,
    activeProtections: users.filter((u) => u.entitlement === 'active').length,
    revenueCents: ledger.payments.reduce((sum, p) => sum + (p.amount || 0), 0),
    paymentsCount: ledger.payments.length,
  };
}
