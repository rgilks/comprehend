import React from 'react';

export const renderTableCellValue = (value: unknown): React.ReactNode => {
  if (value === null || value === undefined)
    return <span className="text-gray-500 italic">NULL</span>;
  if (typeof value === 'string')
    return value.length > 100 ? `${value.substring(0, 100)}...` : value;
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (typeof value === 'object' && !Array.isArray(value)) {
    const stringified = JSON.stringify(value);
    return stringified.length > 100 ? `${stringified.substring(0, 100)}...` : stringified;
  }
  return '[Unsupported Value]';
};
