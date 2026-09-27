import { base64Schema } from './encoding.js';
import {
  AUTH_HASH_BYTES,
  ENCRYPTED_VAULT_KEY_BYTES,
  KDF_LIMITS,
  KDF_SALT_BYTES,
  MAX_ITEM_CIPHERTEXT_BYTES,
  NONCE_BYTES,
} from './limits.js';

// Response schemas double as an allowlist: Fastify's serializer drops any
// property not listed, so a column like users.auth_hash can't leak into a
// response by accident.

export const emailSchema = {
  type: 'string',
  format: 'email',
  minLength: 3,
  maxLength: 254,
} as const;

export const kdfParamsSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['memoryCost', 'iterations', 'parallelism'],
  properties: {
    memoryCost: {
      type: 'integer',
      minimum: KDF_LIMITS.memoryCost.min,
      maximum: KDF_LIMITS.memoryCost.max,
    },
    iterations: {
      type: 'integer',
      minimum: KDF_LIMITS.iterations.min,
      maximum: KDF_LIMITS.iterations.max,
    },
    parallelism: {
      type: 'integer',
      minimum: KDF_LIMITS.parallelism.min,
      maximum: KDF_LIMITS.parallelism.max,
    },
  },
} as const;

export const signupBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: [
    'email',
    'auth_hash',
    'encrypted_vault_key',
    'vault_key_nonce',
    'kdf_salt',
    'kdf_params',
  ],
  properties: {
    email: emailSchema,
    auth_hash: base64Schema(AUTH_HASH_BYTES),
    encrypted_vault_key: base64Schema(ENCRYPTED_VAULT_KEY_BYTES),
    vault_key_nonce: base64Schema(NONCE_BYTES),
    kdf_salt: base64Schema(KDF_SALT_BYTES),
    kdf_params: kdfParamsSchema,
  },
} as const;

export const preloginBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['email'],
  properties: { email: emailSchema },
} as const;

export const SESSION_CLIENTS = ['web', 'extension'] as const;

export const loginBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['email', 'auth_hash'],
  properties: {
    email: emailSchema,
    auth_hash: base64Schema(AUTH_HASH_BYTES),
    /** Optional label shown in the session list. */
    client: { type: 'string', enum: SESSION_CLIENTS },
  },
} as const;

/**
 * Item ids are chosen by the client (they're part of the ciphertext's AAD),
 * in the lowercase form Postgres returns, so the client and server agree on
 * the exact bytes.
 */
const clientItemIdSchema = {
  type: 'string',
  pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
} as const;

/** Postgres integer range; a vault item would need billions of saves to reach it. */
const revisionSchema = { type: 'integer', minimum: 1, maximum: 2_147_483_647 } as const;

const ciphertextProperties = {
  encrypted_data: base64Schema(MAX_ITEM_CIPHERTEXT_BYTES),
  nonce: base64Schema(NONCE_BYTES),
} as const;

export const createItemBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['id', 'revision', 'encrypted_data', 'nonce'],
  properties: {
    id: clientItemIdSchema,
    revision: { type: 'integer', const: 1 },
    ...ciphertextProperties,
  },
} as const;

export const updateItemBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['revision', 'encrypted_data', 'nonce'],
  properties: { revision: revisionSchema, ...ciphertextProperties },
} as const;

export const itemIdParamsSchema = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string', format: 'uuid' } },
} as const;

export const sessionIdParamsSchema = itemIdParamsSchema;

/** Every item in the vault, re-encrypted under a new vault key at the next revision. */
export const changePasswordBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: [
    'current_auth_hash',
    'auth_hash',
    'kdf_salt',
    'kdf_params',
    'encrypted_vault_key',
    'vault_key_nonce',
    'items',
  ],
  properties: {
    current_auth_hash: base64Schema(AUTH_HASH_BYTES),
    auth_hash: base64Schema(AUTH_HASH_BYTES),
    kdf_salt: base64Schema(KDF_SALT_BYTES),
    kdf_params: kdfParamsSchema,
    encrypted_vault_key: base64Schema(ENCRYPTED_VAULT_KEY_BYTES),
    vault_key_nonce: base64Schema(NONCE_BYTES),
    items: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'revision', 'encrypted_data', 'nonce'],
        properties: { id: clientItemIdSchema, revision: revisionSchema, ...ciphertextProperties },
      },
    },
  },
} as const;

const kdfParamsResponse = {
  type: 'object',
  required: ['memoryCost', 'iterations', 'parallelism'],
  properties: {
    memoryCost: { type: 'integer' },
    iterations: { type: 'integer' },
    parallelism: { type: 'integer' },
  },
} as const;

export const itemResponseSchema = {
  type: 'object',
  required: ['id', 'revision', 'encrypted_data', 'nonce', 'created_at', 'updated_at'],
  properties: {
    id: { type: 'string' },
    revision: { type: 'integer' },
    encrypted_data: { type: 'string' },
    nonce: { type: 'string' },
    created_at: { type: 'string', format: 'date-time' },
    updated_at: { type: 'string', format: 'date-time' },
  },
} as const;

export const signupResponseSchema = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string' } },
} as const;

export const preloginResponseSchema = {
  type: 'object',
  required: ['kdf_salt', 'kdf_params'],
  properties: { kdf_salt: { type: 'string' }, kdf_params: kdfParamsResponse },
} as const;

export const loginResponseSchema = {
  type: 'object',
  required: ['token', 'expires_at'],
  properties: { token: { type: 'string' }, expires_at: { type: 'string', format: 'date-time' } },
} as const;

export const vaultKeyResponseSchema = {
  type: 'object',
  required: ['encrypted_vault_key', 'vault_key_nonce', 'kdf_salt', 'kdf_params'],
  properties: {
    encrypted_vault_key: { type: 'string' },
    vault_key_nonce: { type: 'string' },
    kdf_salt: { type: 'string' },
    kdf_params: kdfParamsResponse,
  },
} as const;

export const itemListResponseSchema = {
  type: 'object',
  required: ['items'],
  properties: { items: { type: 'array', items: itemResponseSchema } },
} as const;

export const sessionListResponseSchema = {
  type: 'object',
  required: ['sessions'],
  properties: {
    sessions: {
      type: 'array',
      items: {
        type: 'object',
        required: [
          'id',
          'client',
          'user_agent',
          'created_at',
          'last_used_at',
          'expires_at',
          'current',
        ],
        properties: {
          id: { type: 'string' },
          client: { type: ['string', 'null'] },
          user_agent: { type: ['string', 'null'] },
          created_at: { type: 'string', format: 'date-time' },
          last_used_at: { type: 'string', format: 'date-time' },
          expires_at: { type: 'string', format: 'date-time' },
          current: { type: 'boolean' },
        },
      },
    },
  },
} as const;
