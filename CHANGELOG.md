# Changelog

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