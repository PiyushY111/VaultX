export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    /** Extra machine-readable fields merged into the JSON error body. */
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const badRequest = (message: string) => new HttpError(400, message);
export const unauthorized = (message = 'Unauthorized', details?: Record<string, unknown>) =>
  new HttpError(401, message, details);
export const notFound = (message = 'Not found') => new HttpError(404, message);
export const conflict = (message: string) => new HttpError(409, message);
export const tooManyRequests = (message: string, details?: Record<string, unknown>) =>
  new HttpError(429, message, details);
