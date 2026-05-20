import { describe, expect, it } from "vitest";

import {
  DEFAULT_LIMITS,
  ServerSidePolicyInputs,
  checkAndRecord,
  deriveSourceIp24Hash,
  freshState,
} from "../src/policy.js";
import { buildApp } from "../src/server.js";

const sampleReq = (over: Partial<ServerSidePolicyInputs> = {}): ServerSidePolicyInputs => ({
  recipient: over.recipient ?? "5DfhG1",
  amount: over.amount ?? 10,
  attestation_report_hash: over.attestation_report_hash ?? "0x" + "ab".repeat(32),
  source_ip_24_hash: over.source_ip_24_hash ?? "ip24-A",
});

describe("checkAndRecord", () => {
  it("allows first request", () => {
    const state = freshState(0);
    const result = checkAndRecord(state, sampleReq(), 1000);
    expect(result).toEqual({ ok: true });
    expect(state.totalToday).toBe(10);
  });

  it("rejects above per-drip cap", () => {
    const state = freshState(0);
    const result = checkAndRecord(state, sampleReq({ amount: 11 }), 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/per-drip/);
  });

  it("rejects under per-/24 rate limit", () => {
    const state = freshState(0);
    checkAndRecord(state, sampleReq(), 1000);
    const result = checkAndRecord(
      state,
      sampleReq({ recipient: "5DfhG2", attestation_report_hash: "0x" + "cd".repeat(32) }),
      1500,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/per-\/24/);
  });

  it("rejects under per-attestation rate limit", () => {
    const state = freshState(0);
    checkAndRecord(state, sampleReq(), 1000);
    const result = checkAndRecord(
      state,
      sampleReq({ recipient: "5DfhG2", source_ip_24_hash: "ip24-B" }),
      1500,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/per-attestation/);
  });

  it("rejects above daily total", () => {
    const state = freshState(0);
    state.totalToday = DEFAULT_LIMITS.daily_total - 5;
    const result = checkAndRecord(state, sampleReq({ amount: 10 }), 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/daily total/);
  });

  it("rolls over to fresh day after 24h", () => {
    const state = freshState(0);
    state.totalToday = DEFAULT_LIMITS.daily_total - 1;
    const after_25h = 25 * 60 * 60 * 1000;
    const result = checkAndRecord(state, sampleReq({ amount: 10 }), after_25h);
    expect(result.ok).toBe(true);
    expect(state.totalToday).toBe(10); // reset
  });
});

describe("deriveSourceIp24Hash", () => {
  it("buckets by IPv4 /24", () => {
    const a = deriveSourceIp24Hash("192.168.1.42");
    const b = deriveSourceIp24Hash("192.168.1.250");
    const c = deriveSourceIp24Hash("192.168.2.42");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  it("normalises IPv4-mapped IPv6", () => {
    const v4 = deriveSourceIp24Hash("10.0.0.1");
    const mapped = deriveSourceIp24Hash("::ffff:10.0.0.99");
    expect(mapped).toBe(v4);
  });

  it("returns deterministic hex digest", () => {
    expect(deriveSourceIp24Hash("1.2.3.4")).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("production app configuration", () => {
  it("requires attestation-service URL in production", async () => {
    const oldEnv = process.env.OROGEN_ENV;
    const oldUrl = process.env.ATTESTATION_SERVICE_URL;
    process.env.OROGEN_ENV = "production";
    delete process.env.ATTESTATION_SERVICE_URL;
    try {
      expect(() => buildApp({ apiTokens: new Set(["token"]) })).toThrow(
        /ATTESTATION_SERVICE_URL/,
      );
    } finally {
      if (oldEnv === undefined) delete process.env.OROGEN_ENV;
      else process.env.OROGEN_ENV = oldEnv;
      if (oldUrl === undefined) delete process.env.ATTESTATION_SERVICE_URL;
      else process.env.ATTESTATION_SERVICE_URL = oldUrl;
    }
  });
});
