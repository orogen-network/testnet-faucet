/**
 * Faucet sybil-resistance policy.
 *
 * Rules per plan §1.7:
 *   - Per-drip cap: configurable; default 10 tFORGE per /drip call.
 *   - Cap per attested operator: configurable; default 1000 tFORGE/day.
 *   - Cap per /24 IP block: 1 drip every 30 min.
 *   - Cap per attestation report hash: 1 drip every 10 min.
 *   - Hard daily total: 100k tFORGE/day across all drips.
 *
 * Security model (CRIT-SVC-004):
 *   - The client request body MUST NOT include source_ip_24_hash. The server
 *     derives that from req.ip honouring the configured trusted-proxy list.
 *   - The client supplies the attestation_report_id. The server resolves it
 *     against attestation-service to obtain the actual report_hash + freshness.
 */

import { createHash } from "node:crypto";
import { z } from "zod";

export const DripRequest = z.object({
  recipient: z.string().min(1).max(128),
  amount: z.number().int().positive().max(1_000_000),
  attestation_report_id: z.string().min(1).max(128),
});
export type DripRequest = z.infer<typeof DripRequest>;

export interface PolicyState {
  byRecipient: Map<string, { last_ms: number; total_today: number }>;
  bySourceIp24: Map<string, number>;
  byAttestation: Map<string, number>;
  totalToday: number;
  dayStartedAtMs: number;
}

export const DEFAULT_LIMITS = {
  per_drip_cap: 10,
  per_recipient_per_day: 1000,
  per_source_ip_24_min_interval_ms: 30 * 60 * 1000,
  per_attestation_min_interval_ms: 10 * 60 * 1000,
  daily_total: 100_000,
} as const;

export type Limits = typeof DEFAULT_LIMITS;

export function freshState(now_ms: number): PolicyState {
  return {
    byRecipient: new Map(),
    bySourceIp24: new Map(),
    byAttestation: new Map(),
    totalToday: 0,
    dayStartedAtMs: now_ms,
  };
}

/**
 * Derive the /24 hash of an IPv4 address (or /48 for IPv6) server-side.
 * The caller MUST supply a real peer IP (Fastify's `req.ip` with the trusted
 * proxy list configured), never a client-controlled value.
 */
export function deriveSourceIp24Hash(ip: string): string {
  // Normalise IPv6-mapped IPv4 (`::ffff:1.2.3.4`).
  let normalised = ip;
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped && mapped[1]) normalised = mapped[1];
  let bucket: string;
  if (normalised.includes(".")) {
    const parts = normalised.split(".");
    if (parts.length !== 4) bucket = normalised;
    else bucket = `${parts[0] ?? ""}.${parts[1] ?? ""}.${parts[2] ?? ""}.0/24`;
  } else {
    // IPv6: bucket by /48.
    const parts = normalised.split(":");
    bucket = `${parts.slice(0, 3).join(":")}::/48`;
  }
  return createHash("sha256").update(bucket).digest("hex");
}

export interface ServerSidePolicyInputs {
  recipient: string;
  amount: number;
  /** Resolved from attestation-service, NEVER from the client. */
  attestation_report_hash: string;
  /** Derived from req.ip by the server, NEVER trusted from the client. */
  source_ip_24_hash: string;
}

export function checkAndRecord(
  state: PolicyState,
  req: ServerSidePolicyInputs,
  now_ms: number,
  limits: Limits = DEFAULT_LIMITS,
): { ok: true } | { ok: false; reason: string } {
  if (now_ms - state.dayStartedAtMs > 24 * 60 * 60 * 1000) {
    Object.assign(state, freshState(now_ms));
  }
  if (req.amount > limits.per_drip_cap) {
    return { ok: false, reason: "per-drip cap exceeded" };
  }
  if (state.totalToday + req.amount > limits.daily_total) {
    return { ok: false, reason: "daily total exceeded" };
  }
  const recip = state.byRecipient.get(req.recipient);
  if (recip && recip.total_today + req.amount > limits.per_recipient_per_day) {
    return { ok: false, reason: "per-recipient daily cap exceeded" };
  }
  const lastIp = state.bySourceIp24.get(req.source_ip_24_hash);
  if (lastIp !== undefined && now_ms - lastIp < limits.per_source_ip_24_min_interval_ms) {
    return { ok: false, reason: "per-/24 rate limit" };
  }
  const lastAtt = state.byAttestation.get(req.attestation_report_hash);
  if (lastAtt !== undefined && now_ms - lastAtt < limits.per_attestation_min_interval_ms) {
    return { ok: false, reason: "per-attestation rate limit" };
  }
  state.byRecipient.set(req.recipient, {
    last_ms: now_ms,
    total_today: (recip?.total_today ?? 0) + req.amount,
  });
  state.bySourceIp24.set(req.source_ip_24_hash, now_ms);
  state.byAttestation.set(req.attestation_report_hash, now_ms);
  state.totalToday += req.amount;
  return { ok: true };
}
