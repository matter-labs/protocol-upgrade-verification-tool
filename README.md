# Protocol Upgrade Verification Tool v27

Tool to analyze the zkSync upgrades.

**This is a version for $${\color{red} v27}$$ upgrade.**

**IMPORTANT**

There will be a specific version of this tool, for each release.
So make sure that you pick the correct branch, as new versions of the tool will NOT support verifying older releases.

**For earlier version - please pick the proper github tag.**


First, you need to get the gateway_ecosystem_upgrade_output.yaml file.
(you can find it in contracts/l1-contracts/upgrade-envs/outputs )

## Example use:

To conduct the full verification, you need to provide:
- `ecosystem-yaml`, the path to the output file.
- `l1-rpc`, the JSON RPC client for Layer 1. 
- `era-chain-id`, the chain id of the zkSync Era.
- `bridgheub-address`, the address of the bridgehub in the ecosystem.
- `contracts-commit`/`era-commit` (optional), the commits of `era-contracts` and `zksync-era` server to base the verification on. If not provided, a sensible default value will be used.
- `testnet-contract`, (optional, FOR TESTNETS ONLY), if provided, it will assume that testnet verifier should be used. 

```
cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output.yaml --l1-rpc http://localhost:8545 --contracts-commit a80a24beb7cfe97387bcc9359ad023a4b5b56943 --era-commit 99c3905a9e92416e76d37b0858da7f6c7e123e0b --era-chain-id 270 --testnet-contracts  --bridgehub-address 0xb244E9B485fc872e3242960b786dB5189f6A6d2A
```

### Stage verification

```
cargo run -- --ecosystem-yaml data/v28-ecosystem-stage.yaml --l1-rpc https://1rpc.io/sepolia  --era-chain-id 270 --bridgehub-address 0x236D1c3Ff32Bd0Ca26b72Af287E895627c0478cE --testnet-contracts --gw-rpc https://rpc.era-gateway-stage.zksync.dev/
```

### Testnet verification

```
cargo run -- --ecosystem-yaml data/v28-ecosystem-testnet.yaml --l1-rpc https://1rpc.io/sepolia  --era-chain-id 300 --testnet-contracts  --bridgehub-address 0x35A54c8C757806eB6820629bc82d90E056394C92
```


### Mainnet verification

```
cargo run -- --ecosystem-yaml data/v28-ecosystem-mainnet.yaml --l1-rpc <l1-rpc>  --era-chain-id 324 --bridgehub-address 0x303a465B659cBB0ab36eE643eA362c509EEb5213 --gw-rpc https://rpc.era-gateway-mainnet.zksync.dev/
```

### V28.1 patch verification

The commands below allow to check the upgrades' content and ensure that the diff from the previous upgrade's data is minimal. To also display the upgrade calldata, add `--display-upgrade-data true` to the command below.

#### Testnet

cargo run -- --ecosystem-yaml data/v28-1-ecosystem-testnet.yaml --v28-ecosystem-yaml data/v28-ecosystem-testnet.yaml --l1-rpc $ALCHEMY_SEPOLIA  --contracts-commit 6754d814334d885574d0a2238449ec64a5ec6100 --era-commit  2b87e7b8f781b61bc7c13b81639908bd1e0c297d  --era-chain-id 300 --bridgehub-address 0x35a54c8c757806eb6820629bc82d90e056394c92 --gw-rpc https://rpc.era-gateway-testnet.zksync.dev --testnet-contracts 

#### Mainnet 

cargo run -- --ecosystem-yaml data/v28-1-ecosystem-mainnet.yaml --v28-ecosystem-yaml data/v28-ecosystem-mainnet.yaml --l1-rpc $ALCHEMY_MAINNET  --contracts-commit 941f3e1c6edcccfd41ccdbbba9ccff7c13a96623 --era-commit  2b87e7b8f781b61bc7c13b81639908bd1e0c297d  --era-chain-id 324 --bridgehub-address 0x303a465B659cBB0ab36eE643eA362c509EEb5213 --gw-rpc https://rpc.era-gateway-mainnet.zksync.dev

#### Tally upgrade data

You should provide `--display-upgrade-data true` to the command to also display the `UpgradeData` for both stage1 and stage2 calls, i.e:

```
cargo run -- --ecosystem-yaml data/gateway_ecosystem_upgrade_output_mainnet.yaml --l1-rpc <your-l1-rpc> --contracts-commit a80a24beb7cfe97387bcc9359ad023a4b5b56943 --era-commit 99c3905a9e92416e76d37b0858da7f6c7e123e0b  --era-chain-id 324 --bridgehub-address 0x303a465B659cBB0ab36eE643eA362c509EEb5213 --display-upgrade-data true
```

These encoded `UpgradeData` structs should be the content that is sent to L1.

## Abilities and limitations of the tool

This tool will check that:
- The deployed contracts contain the bytecode that is in line with the hashes stored in the era-contracts repo. It is assumed that it is the job of the CI to maintain the correct hashes. If a verifier does not trust the CI, they rebuild the contracts and verify the correctness of the hashes.
- The genesis params are aligned with the ones in the `zksync-era` repo. The same CI protection as with the contracts' hashes is applied here.
- The calldata of the inner calls, chain creation params, etc are correct and consistent with the output file provided.

### Checks for contracts that are deployed with temporary initial owners

Some contracts are initially deployed with a temporary initial owner (to facilitate easier initialization) and then the ownership is granted to the governance. Note, that this tool only checks that the ownership has been transferred as well as that the final state of the contract (e.g. ownership, etc) are correct. 

It does not check whether any malicious activity has been done during the initialization of the contracts. Thus, it is desirable to cross check via using an explorer (e.g. Etherscan) that no additional malicious activity was done before the transfer of the ownership. 

In case of the v26 upgrade, the above applies to the following contracts:
- `ValidatorTimelock` (`validator_timelock_addr`)
- `L1AssetRouter` (`shared_bridge_proxy_addr`)
- `L1NativeTokenVault` (`native_token_vault_addr`)
- `RollupDAManager` (`l1_rollup_da_manager`)

### Checks for the new implementation of ProtocolUpgradeHandler

The tool will check that the immutable variables that are derived from the constructor args are correct. However, the new implementaiton is not a part of the `era-contracts` repo and so it will have to be manually checked to be equal to the bytecode from the [`zk-governance`](https://github.com/zksync-association/zk-governance) repo.
