import { z, ZodIssueCode } from 'zod';

const checkPairedEnvVars = (
  ctx: z.RefinementCtx,
  id: string | undefined,
  secret: string | undefined,
  idName: string,
  secretName: string
) => {
  if (id && !secret) {
    ctx.addIssue({
      code: ZodIssueCode.custom,
      message: `${secretName} is required when ${idName} is set`,
      path: [secretName],
    });
  }
  if (!id && secret) {
    ctx.addIssue({
      code: ZodIssueCode.custom,
      message: `${idName} is required when ${secretName} is set`,
      path: [idName],
    });
  }
};

export const authEnvSchema = z
  .object({
    GITHUB_ID: z.string().optional(),
    GITHUB_SECRET: z.string().optional(),
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    DISCORD_CLIENT_ID: z.string().optional(),
    DISCORD_CLIENT_SECRET: z.string().optional(),
    AUTH_SECRET: z.string({ required_error: '[NextAuth] ERROR: AUTH_SECRET is missing!' }),
    NEXTAUTH_URL: z.string().url().optional(),
    ADMIN_EMAILS: z
      .string()
      .optional()
      .transform((val) =>
        val
          ? val
              .split(',')
              .map((e) => e.trim())
              .filter(Boolean)
          : []
      ),
    NODE_ENV: z.enum(['development', 'production', 'test']).optional(),
  })
  .superRefine((data, ctx) => {
    checkPairedEnvVars(ctx, data.GITHUB_ID, data.GITHUB_SECRET, 'GITHUB_ID', 'GITHUB_SECRET');
    checkPairedEnvVars(
      ctx,
      data.GOOGLE_CLIENT_ID,
      data.GOOGLE_CLIENT_SECRET,
      'GOOGLE_CLIENT_ID',
      'GOOGLE_CLIENT_SECRET'
    );
    checkPairedEnvVars(
      ctx,
      data.DISCORD_CLIENT_ID,
      data.DISCORD_CLIENT_SECRET,
      'DISCORD_CLIENT_ID',
      'DISCORD_CLIENT_SECRET'
    );
  });

const authEnvVars = authEnvSchema.safeParse(process.env);

if (!authEnvVars.success) {
  const formattedErrors = JSON.stringify(authEnvVars.error.format(), null, 4);
  console.error('❌ Invalid Auth environment variables:', formattedErrors);

  if (process.env['NEXT_PHASE'] !== 'phase-production-build') {
    throw new Error('Invalid Auth environment variables: \n' + formattedErrors);
  }
}

if (
  authEnvVars.success &&
  !authEnvVars.data.NEXTAUTH_URL &&
  authEnvVars.data.NODE_ENV === 'production'
) {
  console.warn('[NextAuth] NEXTAUTH_URL is not set, this might cause issues in production');
}

export const validatedAuthEnv = authEnvVars.success
  ? authEnvVars.data
  : ({} as z.infer<typeof authEnvSchema>);
