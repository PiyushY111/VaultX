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

export const loginBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['email', 'auth_hash'],
  properties: { email: emailSchema, auth_hash: base64Schema(AUTH_HASH_BYTES) },
} as const;

export const itemBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['encrypted_data', 'nonce'],
  properties: {
    encrypted_data: base64Schema(MAX_ITEM_CIPHERTEXT_BYTES),
    nonce: base64Schema(NONCE_BYTES),
  },
} as const;

export const itemIdParamsSchema = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string', format: 'uuid' } },
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
  required: ['id', 'encrypted_data', 'nonce', 'created_at', 'updated_at'],
  properties: {
    id: { type: 'string' },
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
