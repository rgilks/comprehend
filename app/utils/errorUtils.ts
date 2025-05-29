import { ZodError } from 'zod';

export const extractZodErrors = (error: ZodError): string =>
  error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join(', ');
