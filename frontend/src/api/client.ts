const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8000";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const url = `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new ApiError(
      "Unable to connect to security backend. Is FastAPI running on port 8000?",
      0,
    );
  }

  if (!response.ok) {
    throw new ApiError(
      await responseErrorMessage(response, path),
      response.status,
    );
  }

  return (await response.json()) as T;
}

async function responseErrorMessage(
  response: Response,
  path: string,
): Promise<string> {
  const fallback = `Backend request failed (${response.status}) for ${path}`;

  try {
    const payload = (await response.json()) as unknown;
    if (
      typeof payload === "object" &&
      payload !== null &&
      "detail" in payload &&
      typeof payload.detail === "string" &&
      payload.detail.trim()
    ) {
      return payload.detail;
    }
  } catch {
    // Fall back to the status/path message for non-JSON error responses.
  }

  return fallback;
}

export async function apiPost<TRequest, TResponse>(
  path: string,
  body: TRequest,
): Promise<TResponse> {
  const url = `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiError(
      "Unable to connect to security backend. Is FastAPI running on port 8000?",
      0,
    );
  }

  if (!response.ok) {
    throw new ApiError(
      await responseErrorMessage(response, path),
      response.status,
    );
  }

  return (await response.json()) as TResponse;
}

export { API_BASE_URL };
