import { describe, expect, it } from 'vitest';
import { ApiError, describeLoginFailure } from './api';

describe('describeLoginFailure', () => {
  it('shows attempts remaining', () => {
    expect(describeLoginFailure(new ApiError(401, 'x', { attempts_remaining: 2 }))).toBe(
      'Incorrect email or master password. 2 attempts left before this account is temporarily locked.',
    );
    expect(describeLoginFailure(new ApiError(401, 'x', { attempts_remaining: 1 }))).toMatch(
      /1 attempt left/,
    );
  });

  it('says when the account has just been locked', () => {
    expect(describeLoginFailure(new ApiError(401, 'x', { attempts_remaining: 0 }))).toMatch(
      /now temporarily locked/,
    );
  });

  it('says how long to wait when locked', () => {
    expect(describeLoginFailure(new ApiError(429, 'x', { retry_after_seconds: 540 }))).toBe(
      'Too many failed attempts for this account. Try again in 9 minutes.',
    );
    expect(describeLoginFailure(new ApiError(429, 'x', { retry_after_seconds: 20 }))).toMatch(
      /1 minute\./,
    );
  });

  it('falls back to the server message for the per-IP limit, and a plain message otherwise', () => {
    expect(describeLoginFailure(new ApiError(429, 'Rate limit exceeded, retry in 1 minute'))).toBe(
      'Rate limit exceeded, retry in 1 minute',
    );
    expect(describeLoginFailure(new ApiError(401, 'x'))).toBe(
      'Incorrect email or master password.',
    );
  });
});
