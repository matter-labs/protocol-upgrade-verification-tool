# Changelog

## v28 (Precompiles)

**System contracts:**
Added:
* Modexp - precompile

**Upgrade**

* stage0 will do pauseMigration on L1 and on Gateway
* stage1 will upgrade proxies, update protocol version, upgrade gateway, update protocol version / chain creation params on gateway, and force deploy ecosystem/system contracts
* stage2 will unpauseMigration on L1 and Gateway, 

**Other:**

* Calls at the beginning of each stage were added so we can ensure they're run in order

post-upgrade calldata is now empty (and added force deployment checks into new version tx data check)

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