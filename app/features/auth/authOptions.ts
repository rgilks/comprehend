import { User, Account, Session, type NextAuthOptions } from 'next-auth';
import { AdapterUser } from 'next-auth/adapters';
import { JWT } from 'next-auth/jwt';
import GitHub from 'next-auth/providers/github';
import Google from 'next-auth/providers/google';
import Discord from 'next-auth/providers/discord';
import { validatedAuthEnv } from './authEnv';
import { upsertUserOnSignIn, findUserByProvider } from 'app/repo/userRepo';

export interface UserWithEmail extends User {
  email?: string | null;
}

export const signInCallback = ({
  user,
  account,
}: {
  user: User | AdapterUser;
  account: Account | null;
}): boolean => {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (account && user) {
    try {
      upsertUserOnSignIn(user, account);
      return true;
    } catch (error) {
      console.error(
        '[AUTH SignIn Callback] Error during sign in process (upsertUserOnSignIn failed):',
        error
      );
      return false;
    }
  } else {
    console.warn('[AUTH SignIn Callback] Missing account or user object. Skipping DB upsert.');
    return true;
  }
};

export const jwtCallback = ({
  token,
  user,
  account,
}: {
  token: JWT;
  user?: UserWithEmail;
  account?: Account | null;
}): JWT => {
  if (account && user?.id && user.email) {
    token.provider = account.provider;
    token.email = user.email;

    try {
      const userRecord = findUserByProvider(user.id, account.provider);

      if (userRecord) {
        token.dbId = userRecord.id;
      } else {
        console.error(
          `[AUTH JWT Callback] CRITICAL: Could not find user in DB during JWT creation for provider_id=${user.id}, provider=${account.provider}. dbId will be missing!`
        );
      }
    } catch (error) {
      console.error('[AUTH JWT Callback] CRITICAL: Error resolving user DB ID for token:', error);
    }

    const adminEmails = validatedAuthEnv.ADMIN_EMAILS;
    if (user.email && adminEmails.length > 0) {
      token.isAdmin = adminEmails.includes(user.email);
    } else {
      token.isAdmin = false;
    }
  }

  return token;
};

export const sessionCallback = ({ session, token }: { session: Session; token: JWT }): Session => {
  if (token.sub) {
    session.user.id = token.sub;
  }
  if (typeof token.dbId === 'number') {
    session.user.dbId = token.dbId;
  } else {
    console.warn('[AUTH Session Callback] dbId missing from token. Cannot assign to session.');
  }
  if (typeof token.isAdmin === 'boolean') {
    session.user.isAdmin = token.isAdmin;
  }
  if (token.provider) {
    session.user.provider = token.provider;
  }
  return session;
};

const providers = [];

if (validatedAuthEnv.GITHUB_ID && validatedAuthEnv.GITHUB_SECRET) {
  console.log('[NextAuth] GitHub OAuth credentials found, adding provider');
  providers.push(
    GitHub({
      clientId: validatedAuthEnv.GITHUB_ID,
      clientSecret: validatedAuthEnv.GITHUB_SECRET,
    })
  );
} else if (!validatedAuthEnv.GITHUB_ID && !validatedAuthEnv.GITHUB_SECRET) {
  console.warn('[NextAuth] GitHub OAuth credentials missing (GITHUB_ID and GITHUB_SECRET)');
}

if (validatedAuthEnv.GOOGLE_CLIENT_ID && validatedAuthEnv.GOOGLE_CLIENT_SECRET) {
  console.log('[NextAuth] Google OAuth credentials found, adding provider');
  providers.push(
    Google({
      clientId: validatedAuthEnv.GOOGLE_CLIENT_ID,
      clientSecret: validatedAuthEnv.GOOGLE_CLIENT_SECRET,
    })
  );
} else if (!validatedAuthEnv.GOOGLE_CLIENT_ID && !validatedAuthEnv.GOOGLE_CLIENT_SECRET) {
  console.warn(
    '[NextAuth] Google OAuth credentials missing (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)'
  );
}

if (validatedAuthEnv.DISCORD_CLIENT_ID && validatedAuthEnv.DISCORD_CLIENT_SECRET) {
  console.log('[NextAuth] Discord OAuth credentials found, adding provider');
  providers.push(
    Discord({
      clientId: validatedAuthEnv.DISCORD_CLIENT_ID,
      clientSecret: validatedAuthEnv.DISCORD_CLIENT_SECRET,
    })
  );
} else if (!validatedAuthEnv.DISCORD_CLIENT_ID && !validatedAuthEnv.DISCORD_CLIENT_SECRET) {
  console.warn(
    '[NextAuth] Discord OAuth credentials missing (DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET)'
  );
}

console.log(`[NextAuth] Configured ${providers.length} authentication providers`);

export const authOptions: NextAuthOptions = {
  providers,
  secret: validatedAuthEnv.AUTH_SECRET,
  session: {
    strategy: 'jwt' as const,
  },
  pages: {},
  callbacks: {
    signIn: signInCallback,
    jwt: jwtCallback,
    session: sessionCallback,
  },
  cookies: {
    sessionToken: {
      name:
        (validatedAuthEnv.NODE_ENV ?? process.env.NODE_ENV) === 'production'
          ? `__Secure-next-auth.session-token`
          : `next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: (validatedAuthEnv.NODE_ENV ?? process.env.NODE_ENV) === 'production',
      },
    },
  },
};
