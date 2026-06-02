import { describe, expect, it } from "vitest";

import { MockFaucetChainClient, orogToPlanck } from "../src/chain.js";
import { buildApp } from "../src/server.js";

describe("orogToPlanck", () => {
  it("converts whole OROG units to plancks (12 decimals)", () => {
    expect(orogToPlanck(1)).toBe(1_000_000_000_000n);
    expect(orogToPlanck(5)).toBe(5_000_000_000_000n);
    expect(orogToPlanck(10)).toBe(10_000_000_000_000n);
  });
});

describe("POST /drip", () => {
  it("transfers via the injected chain client and returns tx_hash", async () => {
    const mock = new MockFaucetChainClient();
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "POST",
      url: "/drip",
      headers: { authorization: "Bearer t0k3n" },
      payload: {
        recipient: "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9Aylc9HVT6L0VWa",
        amount: 7,
        attestation_report_id: "report-1",
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(true);
    expect(body.recipient).toBe("5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9Aylc9HVT6L0VWa");
    expect(body.amount).toBe(7);
    expect(typeof body.tx_hash).toBe("string");
    expect(body.tx_hash).toMatch(/^0x[0-9a-f]{64}$/);

    expect(mock.sent).toHaveLength(1);
    expect(mock.sent[0]?.recipient).toBe("5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9Aylc9HVT6L0VWa");
    // amount converted to plancks (7 OROG * 10^12).
    expect(mock.sent[0]?.amountPlanck).toBe(7_000_000_000_000n);

    await app.close();
  });

  it("rejects without a valid bearer token", async () => {
    const mock = new MockFaucetChainClient();
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "POST",
      url: "/drip",
      payload: { recipient: "5Dfh", amount: 1, attestation_report_id: "r" },
    });

    expect(res.statusCode).toBe(401);
    expect(mock.sent).toHaveLength(0);
    await app.close();
  });

  it("replies 503 when the chain transfer fails", async () => {
    const mock = new MockFaucetChainClient({ failWith: new Error("node offline") });
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "POST",
      url: "/drip",
      headers: { authorization: "Bearer t0k3n" },
      payload: { recipient: "5Dfh", amount: 1, attestation_report_id: "r" },
    });

    expect(res.statusCode).toBe(503);
    const body = res.json();
    expect(body.ok).toBe(false);
    expect(body.reason).toMatch(/node offline/);
    await app.close();
  });
});

describe("CORS for /drip-public", () => {
  it("answers the preflight for an allowed origin", async () => {
    const mock = new MockFaucetChainClient();
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "OPTIONS",
      url: "/drip-public",
      headers: {
        origin: "https://onboarding.orogen.network",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });

    expect(res.statusCode).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe(
      "https://onboarding.orogen.network",
    );
    expect(res.headers["access-control-allow-methods"]).toMatch(/POST/);
    expect(res.headers["access-control-allow-headers"]).toMatch(/content-type/);
    expect(mock.sent).toHaveLength(0);

    await app.close();
  });

  it("echoes the allow-origin header on the actual POST", async () => {
    const mock = new MockFaucetChainClient();
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "POST",
      url: "/drip-public",
      headers: { origin: "https://onboarding.orogen.network" },
      payload: { recipient: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" },
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe(
      "https://onboarding.orogen.network",
    );

    await app.close();
  });

  it("does not echo allow-origin for an unknown origin", async () => {
    const mock = new MockFaucetChainClient();
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "POST",
      url: "/drip-public",
      headers: { origin: "https://evil.example.com" },
      payload: { recipient: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" },
    });

    expect(res.headers["access-control-allow-origin"]).toBeUndefined();

    await app.close();
  });
});

describe("POST /drip-public", () => {
  it("drips a fixed amount with no bearer and returns tx_hash", async () => {
    const mock = new MockFaucetChainClient();
    // apiTokens set to prove the public lane skips bearer auth.
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const res = await app.inject({
      method: "POST",
      url: "/drip-public",
      payload: { recipient: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(true);
    // Fixed amount (PUBLIC_DRIP_OROG default 5).
    expect(body.amount).toBe(5);
    expect(body.tx_hash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(mock.sent).toHaveLength(1);
    expect(mock.sent[0]?.amountPlanck).toBe(5_000_000_000_000n);

    await app.close();
  });

  it("rate-limits a second public drip from the same IP", async () => {
    const mock = new MockFaucetChainClient();
    const app = buildApp({ chainClient: mock, apiTokens: new Set(["t0k3n"]) });

    const first = await app.inject({
      method: "POST",
      url: "/drip-public",
      payload: { recipient: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" },
    });
    expect(first.statusCode).toBe(200);

    const second = await app.inject({
      method: "POST",
      url: "/drip-public",
      payload: { recipient: "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty" },
    });
    expect(second.statusCode).toBe(429);
    const body = second.json();
    expect(body.ok).toBe(false);
    // Same recipient and IP both block; the per-/24 axis fires here.
    expect(body.reason).toMatch(/per-\/24|per-recipient/);
    expect(mock.sent).toHaveLength(1);

    await app.close();
  });
});
