import { describe, expect, it } from 'vitest';
import { ApiError, describeLoginFailure } from '../src/background/api';

describe('describeLoginFailure', () => {
  it('reports attempts left and lockout duration', () => {
    expect(describeLoginFailure(new ApiError(401, 'x', { attempts_remaining: 3 }))).toMatch(
      /3 attempts left/,
    );
    expect(describeLoginFailure(new ApiError(429, 'x', { retry_after_seconds: 900 }))).toMatch(
      /Try again in 15 minutes/,
    );
  });
});
