export type ActionError = {
  error: string;
  details?: unknown;
  stack?: string;
};

export type Result<TSuccess, TError> =
  | { success: true; data: TSuccess }
  | { success: false; error: TError };

export const success = <TSuccess, TError>(data: TSuccess): Result<TSuccess, TError> => ({
  success: true,
  data,
});

export const failure = <TSuccess, TError>(error: TError): Result<TSuccess, TError> => ({
  success: false,
  error,
});
