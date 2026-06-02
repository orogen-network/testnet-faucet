/**
 * Faucet HTTP server.
 *
 * Security model:
 *   - All clients carry a bearer token from `FAUCET_API_TOKENS` (csv).
 *     Refuses to start in `OROGEN_ENV=production` without a token configured.
 *   - The client-supplied attestation_report_id is resolved against
 *     attestation-service to obtain the actual `attestation_report_hash`,
 *     so an attacker can't rotate it freely.
 *   - source_ip_24_hash is derived server-side from `req.ip`. The trusted
 *     proxy list is configured via TRUSTED_PROXIES env (csv of CIDRs).
 *   - Listens on 127.0.0.1 by default — front with mTLS proxy (LOW-SVC-018).
 */

import Fastify from "fastify";

import {
  PolkadotFaucetClient,
  MockFaucetChainClient,
  orogToPlanck,
} from "./chain.js";
import type { FaucetChainClient } from "./chain.js";
import {
  DEFAULT_LIMITS,
  PUBLIC_DRIP_OROG,
  PUBLIC_LIMITS,
  DripRequest,
  PublicDripRequest,
  checkAndRecord,
  deriveSourceIp24Hash,
  freshState,
} from "./policy.js";

interface BuildOpts {
  /** URL of the attestation-service used to resolve report ids. */
  attestationServiceUrl?: string;
  /** Internal token to call the attestation service. */
  attestationServiceToken?: string;
  /** API tokens that authorize /drip calls. */
  apiTokens?: Set<string>;
  /** Trust X-Forwarded-For from these proxies (csv of IPs/CIDRs). */
  trustProxy?: string[] | boolean;
  /** Per-IP rate limit window. */
  rateLimitMax?: number;
  rateLimitWindowMs?: number;
  /** On-chain transfer client. Tests inject a mock; otherwise derived from env. */
  chainClient?: FaucetChainClient;
}

function envCsv(name: string): Set<string> {
  return new Set(
    (process.env[name] ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

export function buildApp(opts: BuildOpts = {}) {
  const isProd = (process.env.OROGEN_ENV ?? "").toLowerCase() === "production";
  const apiTokens =
    opts.apiTokens ?? envCsv("FAUCET_API_TOKENS");
  if (isProd && apiTokens.size === 0) {
    throw new Error(
      "FAUCET_API_TOKENS must be set in production (OROGEN_ENV=production)",
    );
  }
  const attestationUrl =
    opts.attestationServiceUrl ?? process.env.ATTESTATION_SERVICE_URL ?? "";
  const attestationToken =
    opts.attestationServiceToken ?? process.env.ATTESTATION_SERVICE_TOKEN ?? "";
  if (isProd && !attestationUrl) {
    throw new Error(
      "ATTESTATION_SERVICE_URL must be set in production so attestation_report_id is resolved server-side",
    );
  }

  const rpcUrl = process.env.OROGEN_RPC_URL ?? "wss://forge-rpc.orogen.network";
  const mnemonic = process.env.FAUCET_SIGNER_MNEMONIC ?? "";
  // In production a real signer is mandatory — without it the faucet cannot
  // move tokens. Placed AFTER the attestation-URL check so the existing
  // production-config test still trips on ATTESTATION_SERVICE_URL first.
  if (isProd && !mnemonic && !opts.chainClient) {
    throw new Error(
      "FAUCET_SIGNER_MNEMONIC must be set in production so the faucet can transfer OROG on-chain",
    );
  }
  const chainClient: FaucetChainClient =
    opts.chainClient ??
    (mnemonic ? new PolkadotFaucetClient(rpcUrl, mnemonic) : new MockFaucetChainClient());

  const trustProxy =
    opts.trustProxy ??
    (process.env.TRUSTED_PROXIES
      ? process.env.TRUSTED_PROXIES.split(",").map((s) => s.trim()).filter(Boolean)
      : false);

  const app = Fastify({ logger: true, trustProxy });

  // Browser CORS for the public bootstrap lane. Kept tight: only the known
  // Orogen frontends, only the methods/headers /drip-public actually needs.
  // Never "*". Overridable via FAUCET_CORS_ORIGINS (csv).
  const corsOrigins =
    process.env.FAUCET_CORS_ORIGINS
      ? new Set(
          process.env.FAUCET_CORS_ORIGINS.split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        )
      : new Set([
          "https://onboarding.orogen.network",
          "https://app.orogen.network",
          "https://orogen.network",
        ]);

  app.addHook("onRequest", async (req, reply) => {
    const origin = req.headers["origin"];
    if (typeof origin === "string" && corsOrigins.has(origin)) {
      reply.header("access-control-allow-origin", origin);
      reply.header("vary", "Origin");
      reply.header("access-control-allow-methods", "POST, OPTIONS");
      reply.header("access-control-allow-headers", "content-type");
      reply.header("access-control-max-age", "600");
    }
    // Answer the CORS preflight before auth/rate-limit hooks run.
    if (req.method === "OPTIONS") {
      reply.code(204);
      return reply.send();
    }
  });

  const state = freshState(Date.now());
  // Separate ledger for the public bootstrap lane so its small fixed drips
  // don't share caps with the attested /drip lane.
  const publicState = freshState(Date.now());

  // Naive in-process rate limit (LOW-SVC-018 / MED-SVC-012-style hardening).
  // For production use @fastify/rate-limit; this is sufficient for the
  // skeleton & for the test surface.
  const perIpHits: Map<string, number[]> = new Map();
  const rateLimitMax = opts.rateLimitMax ?? 30;
  const rateLimitWindowMs = opts.rateLimitWindowMs ?? 60_000;

  app.addHook("onRequest", async (req, reply) => {
    if (req.url === "/healthz") return;
    // The public bootstrap lane is intentionally unauthenticated; it is still
    // subject to per-IP rate limiting below.
    const isPublicLane = req.url === "/drip-public";
    // 1) bearer-auth
    if (!isPublicLane && apiTokens.size > 0) {
      const hdr = req.headers["authorization"] ?? "";
      const match = typeof hdr === "string" ? hdr.match(/^Bearer (.+)$/i) : null;
      const tok = match?.[1];
      if (!tok || !apiTokens.has(tok)) {
        reply.code(401);
        return reply.send({ ok: false, reason: "unauthorized" });
      }
    }
    // 2) per-IP rate limit
    const ip = req.ip ?? "unknown";
    const now = Date.now();
    const arr = perIpHits.get(ip) ?? [];
    const fresh = arr.filter((t) => now - t < rateLimitWindowMs);
    if (fresh.length >= rateLimitMax) {
      reply.code(429);
      return reply.send({ ok: false, reason: "rate-limited" });
    }
    fresh.push(now);
    perIpHits.set(ip, fresh);
  });

  app.post("/drip", async (req, reply) => {
    const parsed = DripRequest.safeParse(req.body);
    if (!parsed.success) {
      reply.code(400);
      return { ok: false, reason: "bad request", errors: parsed.error.flatten() };
    }
    const { recipient, amount, attestation_report_id } = parsed.data;

    // Server-side amount cap — also enforced inside checkAndRecord but reject
    // early for clearer errors.
    if (amount > DEFAULT_LIMITS.per_drip_cap) {
      reply.code(400);
      return { ok: false, reason: "amount exceeds per-drip cap" };
    }

    // Resolve attestation_report_id → real hash via attestation-service.
    let attestation_report_hash: string;
    if (attestationUrl) {
      try {
        const headers: Record<string, string> = {};
        if (attestationToken) {
          headers["authorization"] = `Bearer ${attestationToken}`;
        }
        const url = `${attestationUrl.replace(/\/$/, "")}/v1/reports/${encodeURIComponent(attestation_report_id)}`;
        const resp = await fetch(url, { headers });
        if (!resp.ok) {
          reply.code(401);
          return { ok: false, reason: "attestation not found" };
        }
        const body = (await resp.json()) as { report_hash?: string; report?: { timestamp_ms?: number; validity_window_ms?: number } };
        if (!body.report_hash) {
          reply.code(401);
          return { ok: false, reason: "attestation missing report_hash" };
        }
        // Freshness check.
        const ts = body.report?.timestamp_ms;
        const ttl = body.report?.validity_window_ms ?? 0;
        if (ts !== undefined && ttl > 0 && Date.now() > ts + ttl) {
          reply.code(401);
          return { ok: false, reason: "attestation expired" };
        }
        attestation_report_hash = body.report_hash;
      } catch (err) {
        reply.code(503);
        return { ok: false, reason: `attestation lookup failed: ${(err as Error).message}` };
      }
    } else {
      // Dev/test fall-through only. Production refuses to start without
      // ATTESTATION_SERVICE_URL, so public deployments never trust the
      // client-supplied attestation_report_id as a rate-limit key.
      attestation_report_hash = attestation_report_id;
    }

    const source_ip_24_hash = deriveSourceIp24Hash(req.ip ?? "0.0.0.0");

    const result = checkAndRecord(
      state,
      { recipient, amount, attestation_report_hash, source_ip_24_hash },
      Date.now(),
      DEFAULT_LIMITS,
    );
    if (!result.ok) {
      reply.code(429);
      return result;
    }

    try {
      const { txHash } = await chainClient.transfer(recipient, orogToPlanck(amount));
      return { ok: true, recipient, amount, tx_hash: txHash };
    } catch (err) {
      reply.code(503);
      return { ok: false, reason: `transfer failed: ${(err as Error).message}` };
    }
  });

  // Public no-attestation bootstrap lane: a stranger supplies only a recipient
  // address and receives a small fixed amount (PUBLIC_DRIP_OROG) so they can
  // post the operator MinStake. No bearer; per-IP rate limiting still applies.
  app.post("/drip-public", async (req, reply) => {
    const parsed = PublicDripRequest.safeParse(req.body);
    if (!parsed.success) {
      reply.code(400);
      return { ok: false, reason: "bad request", errors: parsed.error.flatten() };
    }
    const { recipient } = parsed.data;
    const amount = PUBLIC_DRIP_OROG;

    const source_ip_24_hash = deriveSourceIp24Hash(req.ip ?? "0.0.0.0");

    const result = checkAndRecord(
      publicState,
      {
        recipient,
        amount,
        // The public lane carries no attestation; that axis is disabled
        // (interval 0) in PUBLIC_LIMITS, so a fixed sentinel key is fine.
        attestation_report_hash: "public",
        source_ip_24_hash,
      },
      Date.now(),
      PUBLIC_LIMITS,
    );
    if (!result.ok) {
      reply.code(429);
      return result;
    }

    try {
      const { txHash } = await chainClient.transfer(recipient, orogToPlanck(amount));
      return { ok: true, recipient, amount, tx_hash: txHash };
    } catch (err) {
      reply.code(503);
      return { ok: false, reason: `transfer failed: ${(err as Error).message}` };
    }
  });

  app.get("/healthz", async () => ({ ok: true }));

  return app;
}

// `app` is exported for the test harness.
const app = buildApp();
export { app };

if (process.argv[1]?.endsWith("server.ts") || process.argv[1]?.endsWith("server.js")) {
  const port = Number(process.env.PORT ?? 8080);
  // Bind to 127.0.0.1 by default — front with a TLS-terminating reverse proxy.
  const host = process.env.BIND_HOST ?? "127.0.0.1";
  app.listen({ port, host });
}
