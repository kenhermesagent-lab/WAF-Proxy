let csrf = "";

export function setCSRF(token: string) {
  csrf = token;
}

type Options = {
  method?: string;
  body?: unknown;
};

async function request<T>(path: string, opts: Options = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(path, {
    method: opts.method ?? "GET",
    headers,
    credentials: "same-origin",
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const text = await res.text();
  // A proxy or the Go server can answer with HTML (a 502 page, for example),
  // so a parse failure must not mask the real HTTP status.
  let data: { error?: string } | null = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    throw new Error(data?.error || res.statusText || `request failed (${res.status})`);
  }
  return data as T;
}

export const api = {
  get: <T>(p: string) => request<T>(p),
  post: <T>(p: string, body?: unknown) => request<T>(p, { method: "POST", body }),
  put: <T>(p: string, body?: unknown) => request<T>(p, { method: "PUT", body }),
  del: <T>(p: string) => request<T>(p, { method: "DELETE" }),
};
