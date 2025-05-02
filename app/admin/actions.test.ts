import { expect } from 'vitest';
import { getTableNames, getTableData } from './actions';
import db from '@/lib/db';
import { getServerSession } from 'next-auth';
import { Mock } from 'vitest';

vi.mock('next-auth', () => ({
  getServerSession: vi.fn(),
}));

vi.mock('next/router', () => ({
  useRouter: vi.fn(() => ({
    events: {
      on: vi.fn(),
      off: vi.fn(),
    },
  })),
}));

vi.mock('@/lib/authOptions', () => ({
  authOptions: {},
}));

vi.mock('@/lib/db', () => ({
  __esModule: true,
  default: {
    prepare: vi.fn(() => ({
      all: vi.fn(),
      get: vi.fn(),
      run: vi.fn(),
    })),
    transaction: vi.fn((cb) => cb()),
  },
}));

const originalEnv = process.env;

describe('Admin actions security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv, ADMIN_EMAILS: 'admin@example.com,another@example.com' };

    const mockAll = vi.fn().mockReturnValue([{ name: 'users' }, { name: 'logs' }]);
    const mockGet = vi.fn().mockReturnValue({ totalRows: 10 });
    const mockRun = vi.fn();

    (db.prepare as Mock).mockImplementation(() => ({
      all: mockAll,
      get: mockGet,
      run: mockRun,
    }));
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('isAdmin function', () => {
    it('should return false if user is not logged in', async () => {
      (getServerSession as Mock).mockResolvedValue(null);
      const result = await getTableNames();
      expect(result).toEqual({ error: 'Unauthorized' });
    });

    it('should return false if user has no email', async () => {
      (getServerSession as Mock).mockResolvedValue({
        user: { name: 'Test User' },
      });
      const result = await getTableNames();
      expect(result).toEqual({ error: 'Unauthorized' });
    });

    it('should return false if user email is not in ADMIN_EMAILS', async () => {
      (getServerSession as Mock).mockResolvedValue({
        user: { name: 'Test User', email: 'user@example.com' },
      });
      const result = await getTableNames();
      expect(result).toEqual({ error: 'Unauthorized' });
    });

    it('should return true if user email is in ADMIN_EMAILS', async () => {
      (getServerSession as Mock).mockResolvedValue({
        user: { name: 'Admin User', email: 'admin@example.com' },
      });
      const result = await getTableNames();
      expect(result).toEqual({ data: expect.any(Array) });
    });

    it('should handle empty ADMIN_EMAILS environment variable', async () => {
      process.env.ADMIN_EMAILS = '';
      (getServerSession as Mock).mockResolvedValue({
        user: { name: 'Admin User', email: 'admin@example.com' },
      });
      const result = await getTableNames();
      expect(result).toEqual({ error: 'Unauthorized' });
    });
  });

  describe('getTableData function', () => {
    it('should return unauthorized error if user is not an admin', async () => {
      (getServerSession as Mock).mockResolvedValue({
        user: { name: 'Test User', email: 'user@example.com' },
      });
      const result = await getTableData('users');
      expect(result).toEqual({ error: 'Unauthorized' });
    });

    it('should return data if user is an admin', async () => {
      (getServerSession as Mock).mockResolvedValue({
        user: { name: 'Admin User', email: 'admin@example.com' },
      });

      const mockPaginatedData = [{ id: 1, name: 'User 1' }];
      (db.transaction as Mock).mockImplementation(() => {
        return () => {
          return {
            data: mockPaginatedData,
            totalRows: 10,
            page: 1,
            limit: 10,
          };
        };
      });

      const result = await getTableData('users');
      expect(result).toHaveProperty('data');
      const data = result.data as {
        data: unknown[];
        totalRows: number;
        page: number;
        limit: number;
      };
      expect(data).toEqual(
        expect.objectContaining({
          data: expect.any(Array),
          totalRows: expect.any(Number),
          page: expect.any(Number),
          limit: expect.any(Number),
        })
      );
    });
  });
});
