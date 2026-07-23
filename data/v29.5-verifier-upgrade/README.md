# v29.5 verifier upgrade (mainnet)

Verification data for the **v29.5 verifier-only upgrade** on Ethereum mainnet:
protocol version `0.29.4` (`124554051588`) → `0.29.5` (`124554051589`).
The upgrade replaces only the FFLONK/PLONK verifiers (new verification keys); facets,
genesis parameters and force deployments are unchanged.

- **Contracts source:** era-contracts `main` @ `fd129fe7` + new v29.5 verification keys
  (build commit `669b9c93`)
- **Deployer:** `0x0ECbc04414B2890695BcD5864e3b23303D9f85ec` via the deterministic
  CREATE2 factory `0x4e59b44847b379578588920cA78FbF26c0B4956C` (all 6 deployment
  transactions landed in block `25590598`, see `transactions` in the yaml)
- **Calldata cross-reference:** `transaction-simulator` branch
  `2026-07-22-verifier-upgrade-v29.5-mainnet`
  (`transactions/2026-07-22-v29.5-verifier-upgrade-mainnet.json`)

## Deployed contracts

| Contract | Role | Address |
|----------|------|---------|
| L1VerifierFflonk | FFLONK verifier (new VK) | `0x9f5C39a2790f38542065E7854b90407371923375` |
| L1VerifierPlonk | PLONK verifier (new VK) | `0xd22cA89e8991FCE568456914c616d303e3142395` |
| DualVerifier | Main verifier (FFLONK/PLONK dispatcher) | `0x47fC5273145E053A18C0BBF6d88F8d6d573C3d0e` |
| DefaultUpgrade | Upgrade contract executed by the diamond cut | `0x8f7Dd88c2435Abe3F585bFb32eb2394d397Af0AA` |
| UpgradeStageValidator | Stage guard | `0x70d2F7FcF7C136ECF608527ADFb2a86bA721067a` |
| GovernanceUpgradeTimer | Upgrade timer | `0xeb998f917e759449046361Bc278F63FB6E576f80` |

## Governance calls

| Stage | Actions |
|-------|---------|
| stage0 | `pauseMigration` (Bridgehub), `startTimer` |
| stage1 | `checkDeadline`, `checkMigrationsPaused`, `setChainCreationParams`, `setNewVersionUpgrade` (CTM) |
| stage2 | `checkProtocolUpgradePresence`, `unpauseMigration`, `checkMigrationsUnpaused` |

Chain-level execution for Era (`upgradeChainFromVersion` on
`0x32400084C286CF3E17e7B677ea9583e60a000324` from chain admin
`0x2cf3bD6a9056b39999F3883955E183F655345063`) is in the `chain_upgrade` section.

## How to verify

From the repo root (branch `vb-v0.29.5`):

```
cargo run -- --ecosystem-yaml data/v29.5-verifier-upgrade/mainnet/v29.5-ecosystem.yaml --l1-rpc "$MAINNET_RPC" --era-chain-id 324 --bridgehub-address 0x303a465B659cBB0ab36eE643eA362c509EEb5213 --contracts-commit fd129fe7f7a476cbf76d64a675d0c3361479f646
```

Expected output: all `[OK]` and a final `OK - result:` line (no errors/warnings).
No `--gw-rpc` is needed — this upgrade has no Gateway leg.

## Checks already performed on this data

- `governance_calls.stage{0,1,2}_calls` and `chain_upgrade.execute_upgrade_calls`
  decode to exactly the targets/values/calldata committed in the
  transaction-simulator branch above (byte-for-byte).
- `chain_upgrade_diamond_cut` equals the `DiamondCutData` embedded in both
  `setNewVersionUpgrade` (stage1) and `upgradeChainFromVersion` (chain-upgrade).
- On-chain (mainnet): all six contracts have code; `DualVerifier.FFLONK_VERIFIER()` /
  `PLONK_VERIFIER()` return the addresses above; the CTM
  (`0xc2eE6b6af7d616f6e27ce7F4A451Aedc2b0F5f5C`) still reports protocol version
  `124554051588` (v29.4), i.e. the upgrade is pending.
- `old_chain_creation_params`, genesis parameters and `force_deployments_data` are
  identical to the independent April 2026 verification runs
  (`2026-04-15-verifier-upgrade-v29.5-mainnet-{alocascio,deniallugo}` branches);
  only the freshly deployed contract addresses, deployer/salt and transaction
  hashes differ.
