# Changelog


## v27 (EVM release)

**Interface changes:**
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

* stage1 is just doing suspendMigrations (and might be fully removed)
* setChainCreationParams moved to stage2


**Other:**

* Bytecode for create2_and_transfer has changed
* added more 'context' messages - to help with error debugging
* verify_protocol_upgrade_handler - needs some rework, as it has different behavior on local network.


postugprade calldata is now empty (and added force deployment checks into new version tx data check)





## v26 (Gateway release) 

This was the first release when this tool was used, so everything was created here.