export type KVData = Record<string, unknown>;

export class Client {
  constructor(
    private readonly baseUrl = process.env.KNXVAULT_ADDR ?? "http://localhost:8200",
    private token = process.env.KNXVAULT_TOKEN ?? "",
  ) {}

  async health(): Promise<Record<string, unknown>> {
    return this.request("GET", "/health", undefined, false);
  }

  async kvPut(path: string, data: KVData): Promise<void> {
    await this.request("POST", `/secrets/kv/${path.replace(/^\//, "")}`, { data });
  }

  async kvGet(path: string): Promise<{ data: KVData }> {
    return this.request("GET", `/secrets/kv/${path.replace(/^\//, "")}`);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    auth = true,
  ): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (auth && this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(await res.text());
    }
    if (res.status === 204) {
      return {} as T;
    }
    return (await res.json()) as T;
  }
}