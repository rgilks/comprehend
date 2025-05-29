'use server';

import { getServerSession } from 'next-auth';
import { authOptions } from 'app/features/auth/authOptions';
import {
  getAllTableNames as repoGetAllTableNames,
  getTableData as repoGetTableData,
  type PaginatedTableData,
} from 'app/repo/adminRepo';

const ensureAdmin = async (): Promise<void> => {
  const session = await getServerSession(authOptions);
  const userEmail = session?.user.email;

  if (!userEmail) {
    throw new Error('Unauthorized');
  }

  const adminEmails = (process.env['ADMIN_EMAILS'] || '')
    .split(',')
    .map((email) => email.trim())
    .filter((email) => email.length > 0);

  if (!adminEmails.includes(userEmail)) {
    throw new Error('Unauthorized');
  }
};

const createAdminAction = <TArgs extends unknown[], TReturn>(
  action: (...args: TArgs) => Promise<TReturn> | TReturn,
  actionNameForLog: string,
  defaultFailureMessage: string
) => {
  return async (...args: TArgs): Promise<{ error?: string; data?: TReturn }> => {
    try {
      await ensureAdmin();
      const data = await action(...args);
      return { data };
    } catch (error) {
      let reportableErrorMessage: string;

      if (error instanceof Error && error.message === 'Unauthorized') {
        reportableErrorMessage = 'Unauthorized';
      } else if (error instanceof Error && error.message) {
        reportableErrorMessage = error.message;
      } else {
        reportableErrorMessage = defaultFailureMessage;
      }

      const originalErrorMsgForLog = error instanceof Error ? error.message : String(error);
      console.error(`[Admin Action: ${actionNameForLog}] Error: ${originalErrorMsgForLog}`, error);

      return { error: reportableErrorMessage };
    }
  };
};

export const getTableNames = createAdminAction(
  async () => await repoGetAllTableNames(),
  'getTableNames',
  'Failed to fetch table names'
);

export const getTableData = createAdminAction(
  async (tableName: string, page: number = 1, limit: number = 10): Promise<PaginatedTableData> =>
    await repoGetTableData(tableName, page, limit),
  'getTableData',
  'Failed to fetch table data'
);
