// Supabase client for the trust-scoring worker. Uses the service-role key so
// it can write to `trust_scores` (RLS bypass). The key MUST be set in Render
// env vars, never committed.

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

export interface RegistryServerRow {
  id: string;
  slug: string;
  name: string;
  source_url: string | null;
}

export interface TrustScoreUpsert {
  server_id: string;
  total_score: number;
  grade: string;
  checks: unknown;
  server_name: string | null;
  server_version: string | null;
  protocol_version: string | null;
  scanned_at: string;
  scan_duration_ms: number;
}

export function getSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url) throw new Error("SUPABASE_URL is not set.");
  if (!key) throw new Error("SUPABASE_SERVICE_ROLE_KEY is not set.");
  return createClient(url, key, {
    auth: { persistSession: false },
  });
}

/**
 * Page through every active server in the registry. `source_url` may be null;
 * the resolver decides whether the server is scannable.
 */
export async function listActiveServers(
  client: SupabaseClient,
): Promise<RegistryServerRow[]> {
  const pageSize = 500;
  const rows: RegistryServerRow[] = [];
  let from = 0;

  for (;;) {
    const to = from + pageSize - 1;
    // The registry schema uses `source_url` as a column on `servers`
    // (see MCP Registry - 2 install-resolver) — pull it directly.
    const { data, error } = await client
      .from("servers")
      .select("id,slug,name,source_url")
      .is("deleted_at", null)
      .order("created_at", { ascending: true })
      .range(from, to);

    if (error) throw new Error(`Failed to list servers: ${error.message}`);
    if (!data || data.length === 0) break;

    rows.push(...(data as RegistryServerRow[]));
    if (data.length < pageSize) break;
    from += pageSize;
  }

  return rows;
}

export async function upsertTrustScore(
  client: SupabaseClient,
  row: TrustScoreUpsert,
): Promise<void> {
  const { error } = await client
    .from("trust_scores")
    .upsert(row, { onConflict: "server_id" });
  if (error) {
    throw new Error(`Failed to upsert trust_score for ${row.server_id}: ${error.message}`);
  }
}
