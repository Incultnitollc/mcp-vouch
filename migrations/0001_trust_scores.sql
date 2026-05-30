-- =============================================================================
-- MCP Vouch — trust_scores migration
-- File: migrations/0001_trust_scores.sql
-- Applies to: MCP Registry Supabase project (kpqxrtsdcmwbszznpeem)
--
-- Stores the latest trust report per server. One row per servers(id) so the
-- scoring worker can upsert and the badge endpoint can read with a single
-- equality lookup. Historical scans are NOT preserved here — keep this table
-- thin and hot. If we want history later, add a `trust_score_runs` table.
--
-- RLS: public read so the registry web app + shields badge endpoint can fetch
-- with the anon key. Writes are service-role only (worker uses service-role
-- key from Render env), so no INSERT/UPDATE policy needed — service_role
-- bypasses RLS in Supabase.
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.trust_scores (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id         uuid NOT NULL REFERENCES public.servers(id) ON DELETE CASCADE,

  -- TrustReport surface (see mcp-vouch src/types/index.ts)
  total_score       smallint NOT NULL CHECK (total_score BETWEEN 0 AND 100),
  grade             text NOT NULL CHECK (grade IN ('A','B','C','D','F')),
  checks            jsonb NOT NULL DEFAULT '[]'::jsonb,

  -- ServerInfo as reported during MCP initialize
  server_name       text,
  server_version    text,
  protocol_version  text,

  scanned_at        timestamptz NOT NULL,
  scan_duration_ms  integer NOT NULL CHECK (scan_duration_ms >= 0),

  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT trust_scores_server_unique UNIQUE (server_id)
);

CREATE INDEX IF NOT EXISTS trust_scores_server_id
  ON public.trust_scores (server_id);

CREATE INDEX IF NOT EXISTS trust_scores_total_score
  ON public.trust_scores (total_score DESC);

CREATE INDEX IF NOT EXISTS trust_scores_scanned_at
  ON public.trust_scores (scanned_at DESC);

-- Reuse the registry's updated_at trigger function (defined in
-- 20260419000001_init_registry.sql). If applying this file to a fresh DB
-- that doesn't have public.set_updated_at(), create it first.
CREATE TRIGGER trg_trust_scores_updated_at
  BEFORE UPDATE ON public.trust_scores
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- =============================================================================
-- RLS
-- =============================================================================
ALTER TABLE public.trust_scores ENABLE ROW LEVEL SECURITY;

CREATE POLICY trust_scores_public_select
  ON public.trust_scores FOR SELECT
  TO anon, authenticated
  USING (true);

-- No INSERT/UPDATE/DELETE policies for anon/authenticated => default deny.
-- service_role bypasses RLS for the scoring worker.

-- =============================================================================
-- Worker upsert reference (TypeScript pseudocode for src/worker)
--
--   await supabase.from('trust_scores').upsert({
--     server_id,
--     total_score: report.totalScore,
--     grade: report.grade,
--     checks: report.checks,
--     server_name: report.serverInfo.name,
--     server_version: report.serverInfo.version,
--     protocol_version: report.serverInfo.protocolVersion,
--     scanned_at: report.scannedAt,
--     scan_duration_ms: report.duration,
--   }, { onConflict: 'server_id' })
-- =============================================================================
