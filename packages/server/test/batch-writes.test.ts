import { randomUUID } from 'node:crypto';
import { decryptItem } from '@password-manager/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  bearer,
  createItem,
  createTestContext,
  currentManifest,
  encryptedItemPayload,
  manifestFor,
  registerAndLogin,
  unb64,
  type ItemResponse,
  type TestContext,
} from './helpers.js';

// PUT /vault-items/batch and POST /vault-items/batch-delete: many existing
// items changed in one all-or-nothing write (trash, empty trash, folders).

let ctx: TestContext;

beforeAll(async () => {
  ctx = await createTestContext();
});

afterAll(async () => {
  await ctx?.close();
});

let accounts = 0;
async function vaultWith(count: number) {
  const { user, token } = await registerAndLogin(
    ctx.app,
    `batch-writes-${++accounts}@example.com`,
    'pw-batch-writes',
  );
  const items: ItemResponse[] = [];
  for (let i = 0; i < count; i++) {
    items.push(await createItem(ctx.app, token, user.vaultKey, `{"n":${i}}`));
  }
  return { user, token, items };
}

/** Each item's next revision with new contents, plus the vault's next manifest. */
async function updateBody(
  token: string,
  vaultKey: Uint8Array,
  items: Pick<ItemResponse, 'id' | 'revision'>[],
  plaintext = (i: number) => `{"edited":${i}}`,
) {
  const entries = await Promise.all(
    items.map(async (item, i) => {
      const revision = item.revision + 1;
      return {
        id: item.id,
        revision,
        ...(await encryptedItemPayload(plaintext(i), vaultKey, { itemId: item.id, revision })),
      };
    }),
  );
  const manifest = await manifestFor(ctx.app, token, vaultKey, {
    set: entries.map(({ id, revision }) => ({ id, revision })),
  });
  return { items: entries, manifest };
}

const put = (token: string, payload: object) =>
  ctx.app.inject({ method: 'PUT', url: '/vault-items/batch', headers: bearer(token), payload });

const remove = (token: string, payload: object) =>
  ctx.app.inject({
    method: 'POST',
    url: '/vault-items/batch-delete',
    headers: bearer(token),
    payload,
  });

async function listed(token: string) {
  const response = await ctx.app.inject({
    method: 'GET',
    url: '/vault-items',
    headers: bearer(token),
  });
  return response.json<{ items: ItemResponse[] }>().items;
}

describe('PUT /vault-items/batch', () => {
  it('saves every item at its next revision and moves the manifest on once', async () => {
    const { user, token, items } = await vaultWith(3);
    const versionBefore = (await currentManifest(ctx.app, token, user.vaultKey))!.version;
    const body = await updateBody(token, user.vaultKey, [...items].reverse());

    const response = await put(token, body);
    expect(response.statusCode, response.body).toBe(200);
    const saved = response.json<{ items: ItemResponse[] }>().items;
    // In the order sent, each at revision 2, stored as sent.
    expect(saved.map((item) => item.id)).toEqual(body.items.map((item) => item.id));
    expect(saved.map((item) => item.revision)).toEqual([2, 2, 2]);
    const first = saved[0]!;
    const plaintext = await decryptItem(
      unb64(first.encrypted_data),
      unb64(first.nonce),
      user.vaultKey,
      { itemId: first.id, revision: 2 },
    );
    expect(plaintext).toBe('{"edited":0}');

    const manifest = await currentManifest(ctx.app, token, user.vaultKey);
    expect(manifest!.version).toBe(versionBefore + 1);
    expect(Object.values(manifest!.items)).toEqual([2, 2, 2]);
  });

  it('changes nothing if any item is at a stale revision, and says which', async () => {
    const { user, token, items } = await vaultWith(2);
    const stale = await updateBody(token, user.vaultKey, [
      items[0]!,
      { ...items[1]!, revision: 5 },
    ]);
    const response = await put(token, stale);
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ id: items[1]!.id, current_revision: 1 });
    expect((await listed(token)).map((item) => item.revision)).toEqual([1, 1]);
  });

  it("changes nothing if any item is missing or another user's", async () => {
    const { user, token, items } = await vaultWith(1);
    const other = await vaultWith(1);
    for (const intruder of [other.items[0]!, { id: randomUUID(), revision: 1 }]) {
      const body = await updateBody(token, user.vaultKey, [items[0]!, intruder]);
      expect((await put(token, body)).statusCode).toBe(404);
    }
    expect((await listed(token)).map((item) => item.revision)).toEqual([1]);
    expect((await listed(other.token)).map((item) => item.revision)).toEqual([1]);
  });

  it('refuses re-encrypting new contents under an item’s current nonce', async () => {
    const { user, token, items } = await vaultWith(1);
    const body = await updateBody(token, user.vaultKey, items);
    const reused = { ...body, items: [{ ...body.items[0]!, nonce: items[0]!.nonce }] };
    const response = await put(token, reused);
    expect(response.statusCode).toBe(409);
    expect(response.json().message).toMatch(/nonce/);
  });

  it('refuses a stale manifest, changing nothing', async () => {
    const { user, token, items } = await vaultWith(2);
    const body = await updateBody(token, user.vaultKey, [items[0]!]);
    await createItem(ctx.app, token, user.vaultKey, '{"meanwhile":true}');
    expect((await put(token, body)).statusCode).toBe(409);
    expect((await listed(token)).every((item) => item.revision === 1)).toBe(true);
  });

  it('refuses empty, oversized, duplicated and malformed batches', async () => {
    const { user, token, items } = await vaultWith(1);
    const body = await updateBody(token, user.vaultKey, items);
    const entry = body.items[0]!;
    for (const bad of [
      { ...body, items: [] },
      { ...body, items: Array.from({ length: 501 }, () => entry) },
      { ...body, items: [entry, entry] },
      { ...body, items: [{ ...entry, id: 'not-a-uuid' }] },
      { ...body, items: [{ ...entry, revision: 0 }] },
      { items: body.items },
    ]) {
      expect((await put(token, bad)).statusCode).toBe(400);
    }
    expect((await listed(token)).map((item) => item.revision)).toEqual([1]);
  });
});

describe('POST /vault-items/batch-delete', () => {
  it('deletes every item and moves the manifest on once', async () => {
    const { user, token, items } = await vaultWith(3);
    const versionBefore = (await currentManifest(ctx.app, token, user.vaultKey))!.version;
    const ids = [items[0]!.id, items[2]!.id];
    const manifest = await manifestFor(ctx.app, token, user.vaultKey, { remove: ids });

    const response = await remove(token, { ids, manifest });
    expect(response.statusCode, response.body).toBe(204);
    expect((await listed(token)).map((item) => item.id)).toEqual([items[1]!.id]);
    const after = await currentManifest(ctx.app, token, user.vaultKey);
    expect(after!.version).toBe(versionBefore + 1);
    expect(Object.keys(after!.items)).toEqual([items[1]!.id]);
  });

  it("deletes nothing if any id is missing or another user's", async () => {
    const { user, token, items } = await vaultWith(2);
    const other = await vaultWith(1);
    for (const intruder of [other.items[0]!.id, randomUUID()]) {
      const ids = [items[0]!.id, intruder];
      const manifest = await manifestFor(ctx.app, token, user.vaultKey, { remove: ids });
      expect((await remove(token, { ids, manifest })).statusCode).toBe(404);
    }
    expect(await listed(token)).toHaveLength(2);
    expect(await listed(other.token)).toHaveLength(1);
  });

  it('refuses a stale manifest, deleting nothing', async () => {
    const { user, token, items } = await vaultWith(1);
    const ids = [items[0]!.id];
    const manifest = await manifestFor(ctx.app, token, user.vaultKey, { remove: ids });
    await createItem(ctx.app, token, user.vaultKey, '{"meanwhile":true}');
    expect((await remove(token, { ids, manifest })).statusCode).toBe(409);
    expect(await listed(token)).toHaveLength(2);
  });

  it('refuses empty, oversized, duplicated and malformed lists', async () => {
    const { user, token, items } = await vaultWith(1);
    const id = items[0]!.id;
    const manifest = await manifestFor(ctx.app, token, user.vaultKey, { remove: [id] });
    for (const bad of [
      { ids: [], manifest },
      { ids: Array.from({ length: 501 }, () => randomUUID()), manifest },
      { ids: [id, id], manifest },
      { ids: ['not-a-uuid'], manifest },
      { ids: [id] },
    ]) {
      expect((await remove(token, bad)).statusCode).toBe(400);
    }
    expect(await listed(token)).toHaveLength(1);
  });
});
