import React from 'react';
import { renderTableCellValue } from 'app/utils/rendering';

interface DataTableBodyProps<T extends Record<string, unknown>> {
  headers: (keyof T)[];
  data: T[];
  isLoading: boolean;
  minBodyHeight: number;
  onRowClick: (rowData: T) => void;
}

export const DataTableBody = <T extends Record<string, unknown>>({
  headers,
  data,
  isLoading,
  minBodyHeight,
  onRowClick,
}: DataTableBodyProps<T>) => {
  const getRowKey = (row: T, index: number): string => {
    const id = row['id'];
    if (id && (typeof id === 'string' || typeof id === 'number')) {
      return String(id);
    }
    return `index-${index}`;
  };

  return (
    <div
      className={`overflow-x-auto relative ${isLoading ? 'opacity-60 pointer-events-none' : ''} transition-opacity duration-200`}
    >
      <table className="min-w-full text-sm text-left text-gray-400">
        <thead className="text-xs text-gray-400 uppercase bg-gray-700">
          <tr>
            {headers.map((key) => (
              <th key={key as string} scope="col" className="py-3 px-6">
                {(key as string).replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
              </th>
            ))}
            {headers.length === 0 && (
              <th scope="col" className="py-3 px-6">
                &nbsp;
              </th>
            )}
          </tr>
        </thead>
        <tbody style={{ minHeight: `${minBodyHeight}px` }}>
          {isLoading && (
            <tr>
              <td colSpan={headers.length || 1} className="py-10 text-center">
                <div role="status" className="inline-flex items-center">
                  <svg
                    aria-hidden="true"
                    className="w-8 h-8 mr-2 text-gray-600 animate-spin fill-blue-500"
                    viewBox="0 0 100 101"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z"
                      fill="currentColor"
                    />
                    <path
                      d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0492C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z"
                      fill="currentFill"
                    />
                  </svg>
                  <span className="sr-only">Loading...</span>
                  Loading data...
                </div>
              </td>
            </tr>
          )}
          {!isLoading && data.length > 0 ? (
            data.map((row, rowIndex) => {
              const rowKey = getRowKey(row, rowIndex);
              return (
                <tr
                  key={rowKey}
                  className="bg-gray-800 border-b border-gray-700 hover:bg-gray-600 cursor-pointer transition-colors duration-150 ease-in-out"
                  onClick={() => {
                    onRowClick(row);
                  }}
                >
                  {headers.map((header) => (
                    <td
                      key={`${rowKey}-${header as string}`}
                      className="py-4 px-6 whitespace-nowrap"
                    >
                      {renderTableCellValue(row[header])}
                    </td>
                  ))}
                </tr>
              );
            })
          ) : !isLoading && data.length === 0 ? (
            <tr>
              <td className="py-10 text-center text-gray-500" colSpan={headers.length || 1}>
                No data found in this table.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
};
