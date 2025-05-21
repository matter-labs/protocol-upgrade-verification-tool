# Changelog

## Gateway Whitelisting

This upgrade handles the whitelisting and initialization of Gateway, a ZK Rollup with chain id 9075, as a valid settlement layer for other chains. In order to efficiently deploy all the ecosystem contracts and set them up correctly we created the `GatewayCTMDeployer` contract which handles all of this within its constructor. As part of the calldata there are 2 different sets that are generated; ecosystem and governance.

The ecosystem calls, which are meant to be called by the ecosystem admin, contain 2 calls:

1. Setting the `ServerNotifier` for the `ChainTypeManager`
2. Accepting ownership of the `ServerNotifier` contract

The governance calls contain:

1. Add the `ChainTypeManager` as a valid CTM within the Gateway `Bridgehub`
2. Set the admin of the Gateway `ChainTypeManager` to the admin of the L1 `ChainTypeManager`
3. Set the `AssetDeploymentTracker` in the `L1AssetRouter` and `CTMDeploymentTracker`
4. Add the Gateway `Bridgehub` as an asset handler for chains
5. Set the Gateway `ChainTypeManager` as the canonical CTM for chains that migrate from L1
6. Accept ownership of Gateway `RollupDAManager`, `ValidatorTimelock`, and `ServerNotifier`
7. Whitelist old L2 Rollup Address as a valid DA Pair
8. Accept admin of Gateway `ChainTypeManager`

## v27 (EVM release)

**Interface changes (in previous release):**
* in Bridgehub: `StateTransitionManager` is removed, now it is called ChainTypeManager - 
* `getAllHyperchainChainIDs` call from STM is now on Bridgehub, and called `getAllZKChainChainIDs`

**System contracts:**
Added:
* Identity.yul - precompile
* EvmGasManager.yul
* EvmPredeployManager.sol
* EvmHashesStorage.sol
* EvmEmulator.yul

**Upgrade**

* stage0 will do pauseMigration
* stage1 will update proxies, do new protocol version and upgrade chain
* stage2 will unpause migration


**Other:**

* Bytecode for create2_and_transfer has changed
* added more 'context' messages - to help with error debugging

post-upgrade calldata is now empty (and added force deployment checks into new version tx data check)


## v26 (Gateway release) 

This was the first release when this tool was used, so everything was created here.