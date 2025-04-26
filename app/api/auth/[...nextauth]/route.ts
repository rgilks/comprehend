import NextAuth from 'next-auth';
import { authOptions } from '@/lib/authOptions';

// Revert to standard handler definition
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
