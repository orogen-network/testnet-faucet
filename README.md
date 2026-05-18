# testnet-faucet

Forge testnet faucet — issues `tFORGE` to attested operators with multi-axis sybil resistance.

## Policy

- Cap per attested operator: 1000 tFORGE/day.
- Cap per /24 IP block: 1 drip every 30 min.
- Cap per attestation report hash: 1 drip every 10 min.
- Hard daily total: 100k tFORGE/day.

Per plan §1.7 + RFC-0009 (operator registration with sanctions + attestation proof). Anti-sybil ties into the same axes used by `pallet-operator-stake` registration: device cert + geo region + IP /24 hash.

## Endpoints

- `POST /drip` — body: `{ recipient, amount, attestation_report_hash, source_ip_24_hash }`
- `GET /healthz`

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```
