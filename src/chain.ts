/**
 * Faucet on-chain transfer client.
 *
 * The faucet HTTP layer depends only on the small `FaucetChainClient`
 * interface so that policy/unit tests can inject a deterministic mock without
 * pulling in the heavy @polkadot/api dependency. The real implementation
 * (`PolkadotFaucetClient`) loads @polkadot lazily via dynamic import, so merely
 * importing this module — or running the policy tests — never requires
 * @polkadot to be present or initialised.
 */

/** SS58 prefix for the Orogen / Forge chain. */
export const OROGEN_SS58_FORMAT = 42;

/** OROG has 12 decimals. */
export const OROG_DECIMALS = 12;

/**
 * Convert a whole-OROG amount to plancks (the chain's base unit).
 * Policy caps are expressed in whole OROG units; the chain expects plancks.
 */
export function orogToPlanck(amount: number): bigint {
  return BigInt(Math.trunc(amount)) * 10n ** BigInt(OROG_DECIMALS);
}

export interface FaucetChainClient {
  /**
   * Transfer `amountPlanck` base units to `recipientSs58`.
   * Resolves with the finalised/in-block transaction hash (hex).
   * Rejects if the transfer cannot be submitted or dispatch fails.
   */
  transfer(recipientSs58: string, amountPlanck: bigint): Promise<{ txHash: string }>;
}

export interface MockTransfer {
  recipient: string;
  amountPlanck: bigint;
}

/**
 * Deterministic in-memory client for tests. Records every transfer in `sent`
 * and returns a stable hash derived from the call index. If `failWith` is set,
 * every transfer rejects with that error instead.
 */
export class MockFaucetChainClient implements FaucetChainClient {
  public readonly sent: MockTransfer[] = [];
  private readonly failWith?: Error;

  constructor(opts: { failWith?: Error } = {}) {
    this.failWith = opts.failWith;
  }

  async transfer(recipientSs58: string, amountPlanck: bigint): Promise<{ txHash: string }> {
    if (this.failWith) throw this.failWith;
    this.sent.push({ recipient: recipientSs58, amountPlanck });
    const idx = this.sent.length;
    const txHash = "0x" + idx.toString(16).padStart(64, "0");
    return { txHash };
  }
}

/**
 * Real chain client backed by @polkadot/api. Connects lazily on first transfer
 * and reuses the connection thereafter. @polkadot modules are imported
 * dynamically so this file is cheap to import and policy tests stay
 * dependency-free.
 */
export class PolkadotFaucetClient implements FaucetChainClient {
  private readonly rpcUrl: string;
  private readonly mnemonic: string;
  // Loaded lazily; typed loosely to avoid a static @polkadot type dependency.
  private apiPromise?: Promise<any>;
  private signerPromise?: Promise<any>;

  constructor(rpcUrl: string, mnemonic: string) {
    this.rpcUrl = rpcUrl;
    this.mnemonic = mnemonic;
  }

  private async getApi(): Promise<any> {
    if (!this.apiPromise) {
      this.apiPromise = (async () => {
        const { ApiPromise, WsProvider } = await import("@polkadot/api");
        const provider = new WsProvider(this.rpcUrl);
        return ApiPromise.create({ provider });
      })();
    }
    return this.apiPromise;
  }

  private async getSigner(): Promise<any> {
    if (!this.signerPromise) {
      this.signerPromise = (async () => {
        const { Keyring } = await import("@polkadot/api");
        const { cryptoWaitReady } = await import("@polkadot/util-crypto");
        await cryptoWaitReady();
        const keyring = new Keyring({ type: "sr25519", ss58Format: OROGEN_SS58_FORMAT });
        return keyring.addFromMnemonic(this.mnemonic);
      })();
    }
    return this.signerPromise;
  }

  async transfer(recipientSs58: string, amountPlanck: bigint): Promise<{ txHash: string }> {
    const [api, signer] = await Promise.all([this.getApi(), this.getSigner()]);

    return new Promise<{ txHash: string }>((resolve, reject) => {
      let unsub: (() => void) | undefined;
      api.tx.balances
        .transferKeepAlive(recipientSs58, amountPlanck)
        .signAndSend(signer, (result: any) => {
          const { status, dispatchError, txHash } = result;
          if (dispatchError) {
            let message = "dispatch error";
            if (dispatchError.isModule) {
              try {
                const decoded = api.registry.findMetaError(dispatchError.asModule);
                message = `${decoded.section}.${decoded.name}`;
              } catch {
                message = dispatchError.toString();
              }
            } else {
              message = dispatchError.toString();
            }
            if (unsub) unsub();
            reject(new Error(message));
            return;
          }
          if (status?.isInBlock) {
            if (unsub) unsub();
            resolve({ txHash: txHash.toHex() });
          }
        })
        .then((u: () => void) => {
          unsub = u;
        })
        .catch((err: unknown) => {
          reject(err instanceof Error ? err : new Error(String(err)));
        });
    });
  }
}
