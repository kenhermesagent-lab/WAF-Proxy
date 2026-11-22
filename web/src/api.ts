let csrf = "";

export function setCSRF(token: string) {
  csrf = token;
}

type Options = {
  method?: string;
  body?: unknown;
};

// read parses a response, keeping an HTML error page from masking the HTTP status.
async function read<T>(res: Response): Promise<T> {
  const text = await res.text();
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
  return read<T>(res);
}

// postRaw sends a file body (an encrypted backup) with extra headers.
async function postRaw<T>(path: string, body: BodyInit, headers: Record<string, string>): Promise<T> {
  const h = { ...headers };
  if (csrf) h["X-CSRF-Token"] = csrf;
  const res = await fetch(path, { method: "POST", headers: h, credentials: "same-origin", body });
  return read<T>(res);
}

async function upload<T>(path: string, form: FormData): Promise<T> {
  const headers: Record<string, string> = {};
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(path, { method: "POST", headers, credentials: "same-origin", body: form });
  return read<T>(res);
}

// download saves a file, keeping its JSON error body readable instead.
async function download(path: string, headers: Record<string, string> = {}) {
  const res = await fetch(path, { headers, credentials: "same-origin" });
  if (!res.ok) return read<never>(res);
  const name = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") ?? "")?.[1];
  return { blob: await res.blob(), name: name || "download" };
}

export const api = {
  get: <T>(p: string) => request<T>(p),
  post: <T>(p: string, body?: unknown) => request<T>(p, { method: "POST", body }),
  postRaw: <T>(p: string, body: BodyInit, headers: Record<string, string>) => postRaw<T>(p, body, headers),
  put: <T>(p: string, body?: unknown) => request<T>(p, { method: "PUT", body }),
  del: <T>(p: string) => request<T>(p, { method: "DELETE" }),
  upload,
  download,
};
