// Supabase client for the trust-scoring worker. Uses the service-role key so
// it can write to `trust_scores` (RLS bypass). The key MUST be set in Render
// env vars, never committed.
//
// Source-URL resolution: the registry stores the canonical install URL on
// `server_versions.source_url` (npmjs.com or github URL). We pick the latest
// version's source_url and fall back to `servers.repo_url` when no version
// row has one. The install-resolver then maps that URL → `npx -y <pkg>`.

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

export interface RegistryServerRow {
  id: string;
  slug: string;
  name: string;
  source_url: string | null;
}

interface ServerWithVersionsRow {
  id: string;
  slug: string;
  name: string;
  repo_url: string | null;
  server_versions: { source_url: string | null; published_at: string | null }[] | null;
  trust_scores: { scanned_at: string | null }[] | null;
}

function pickSourceUrl(row: ServerWithVersionsRow): string | null {
  const versions = row.server_versions ?? [];
  if (versions.length > 0) {
    const sorted = [...versions].sort((a, b) => {
      const ta = a.published_at ? Date.parse(a.published_at) : 0;
      const tb = b.published_at ? Date.parse(b.published_at) : 0;
      return tb - ta;
    });
    const url = sorted.find((v) => v.source_url)?.source_url ?? null;
    if (url) return url;
  }
  return row.repo_url;
}

function lastScannedAt(row: ServerWithVersionsRow): number {
  const ts = row.trust_scores?.[0]?.scanned_at;
  return ts ? Date.parse(ts) : 0;
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
 * Page through every active server in the registry, joining each row with its
 * `server_versions` (for source_url) and `trust_scores` (for prioritization).
 *
 * The registry has thousands of servers; a single cron run can't scan them
 * all in the platform's time budget. We fetch every active row, sort
 * unscanned-first then oldest-scanned-first, and the worker takes the top
 * `maxPerRun` so each cron tick advances coverage instead of restarting
 * from the top of the alphabet.
 */
export async function listActiveServers(
  client: SupabaseClient,
  maxPerRun: number,
): Promise<RegistryServerRow[]> {
  const pageSize = 1000;
  const raw: ServerWithVersionsRow[] = [];
  let from = 0;

  for (;;) {
    const to = from + pageSize - 1;
    const { data, error } = await client
      .from("servers")
      .select(
        "id,slug,name,repo_url,server_versions(source_url,published_at),trust_scores(scanned_at)",
      )
      .is("deleted_at", null)
      .order("created_at", { ascending: true })
      .range(from, to);

    if (error) throw new Error(`Failed to list servers: ${error.message}`);
    if (!data || data.length === 0) break;

    raw.push(...(data as ServerWithVersionsRow[]));
    if (data.length < pageSize) break;
    from += pageSize;
  }

  // Unscanned (scanned_at = 0) first, then oldest scan first. Cron runs every
  // 6h with maxPerRun rows, so each row gets re-scanned roughly every
  // (rows / (maxPerRun * 4)) days.
  raw.sort((a, b) => lastScannedAt(a) - lastScannedAt(b));

  return raw.slice(0, maxPerRun).map((row) => ({
    id: row.id,
    slug: row.slug,
    name: row.name,
    source_url: pickSourceUrl(row),
  }));
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
