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
      `Backend request failed (${response.status}) for ${path}`,
      response.status,
    );
  }

  return (await response.json()) as T;
}

export { API_BASE_URL };
