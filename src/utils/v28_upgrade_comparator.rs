//! This file is dedicated to parsing the previous v28 upgrade data.
//! The results will be used to ensure minimal changes in v28.1 patch.

use alloy::{dyn_abi::SolType, primitives::Address, sol_types::SolCall};

use crate::{elements::{call_list::{Call, CallList}, governance_stage_calls::{setChainCreationParamsCall, GovernanceStage1Calls}, initialize_data_new_chain::InitializeDataNewChain, UpgradeOutput}, verifiers};
use alloy::sol;


struct V28UpgradeComparator {
    v28_set_chain_creation_call: Call,
    v28_set_new_version_call: Call,
    v28_gw_set_chain_creation_call: Call,
    v28_gw_set_new_version_call: Call,
}

fn validate_new_set_chain_creation_call(
    previous: &Call,
    new: &Call,
    new_verifier: Address
) -> anyhow::Result<()> {
    assert_eq!(previous.target, new.target, "Set chain creation call target should be the same.");
    assert_eq!(previous.value, new.value, "Set chain creation call value should be the same.");

    let previous_params = setChainCreationParamsCall::abi_decode(&previous.data, true)?._chainCreationParams;
    let new_params = setChainCreationParamsCall::abi_decode(&new.data, true)?._chainCreationParams;

    assert_eq!(previous_params.genesisUpgrade, new_params.genesisUpgrade, "Genesis upgrade should be the same.");
    assert_eq!(previous_params.genesisBatchHash, new_params.genesisBatchHash, "Genesis batch hash should be the same.");
    assert_eq!(previous_params.genesisIndexRepeatedStorageChanges, new_params.genesisIndexRepeatedStorageChanges, "Genesis index repeated storage changes should be the same.");
    assert_eq!(previous_params.genesisBatchCommitment, new_params.genesisBatchCommitment, "Genesis batch commitment should be the same.");
    assert_eq!(previous_params.forceDeploymentsData, new_params.forceDeploymentsData, "Force deployments data should be the same.");

    // Now, comparing the diamond cut

    assert_eq!(previous_params.diamondCut.initAddress, new_params.diamondCut.initAddress, "Diamond cut init address should be the same.");
    assert_eq!(previous_params.diamondCut.facetCuts, new_params.diamondCut.facetCuts, "Diamond cut facet cuts should be the same.");

    let previous_init_data =
        InitializeDataNewChain::abi_decode(&previous_params.diamondCut.initCalldata, true)?;
    let new_init_data =
        InitializeDataNewChain::abi_decode(&new_params.diamondCut.initCalldata, true)?;

    // Now we check that all is equal except for veriifer address.

    assert_eq!(previous_init_data.verifierParams, new_init_data.verifierParams, "Verifier params should be the same.");
    assert_eq!(previous_init_data.l2BootloaderBytecodeHash, new_init_data.l2BootloaderBytecodeHash, "L2 bootloader bytecode hash should be the same.");
    assert_eq!(previous_init_data.l2DefaultAccountBytecodeHash, new_init_data.l2DefaultAccountBytecodeHash, "L2 default account bytecode hash should be the same.");
    assert_eq!(previous_init_data.l2EvmEmulatorBytecodeHash, new_init_data.l2EvmEmulatorBytecodeHash, "L2 EVM emulator bytecode hash should be the same.");
    assert_eq!(previous_init_data.priorityTxMaxGasLimit, new_init_data.priorityTxMaxGasLimit, "Priority TX max gas limit should be the same.");
    assert_eq!(previous_init_data.feeParams, new_init_data.feeParams, "Fee params should be the same.");
    assert_eq!(previous_init_data.blobVersionedHashRetriever, new_init_data.blobVersionedHashRetriever, "Blob versioned hash retriever should be the same.");   

    assert!(previous_init_data.verifier != new_verifier, "Verifier address should be changed to the new one.");
    assert!(new_init_data.verifier == new_verifier, "Verifier address should be changed to the new one.");

    Ok(())
}

fn validate_set_new_version_upgrade_call(
    previous: &Call,
    new: &Call,
    new_verifier: Address
) {
    // The new version should be the same as in the previous upgrade.
    if previous.data != new.data {
        panic!("New set new version call is different from the previous one.");
    }
}

fn validate_set_upgrade_diamond_cut_call(
    previous_set_new_version_upgrade_call: &Call,
    new: &Call,
    new_verifier: Address
) {
    
}

impl V28UpgradeComparator {
    fn new(v28_upgrade_config: UpgradeOutput) -> Self {
        let UpgradeOutput {
            governance_calls,
            ..
        } = v28_upgrade_config;

        const SET_CHAIN_CREATION_INDEX: usize = 8;
        const SET_NEW_VERSION_INDEX: usize = 9;
        const GATEWAY_SET_NEW_VERSION: usize = 12;
        const GATEWAY_NEW_CHAIN_CREATION_PARAMS: usize = 14;
        
        let stage1_calls: CallList =  CallList::parse(&governance_calls.governance_stage1_calls);

        let set_chain_creation_call = stage1_calls.elems[SET_CHAIN_CREATION_INDEX].clone();
        let set_new_version_call = stage1_calls.elems[SET_NEW_VERSION_INDEX].clone();
        let gw_set_chain_creation_call = stage1_calls.elems[GATEWAY_NEW_CHAIN_CREATION_PARAMS].clone();
        let gw_set_new_version_call = stage1_calls.elems[GATEWAY_SET_NEW_VERSION].clone();

        Self {
            v28_gw_set_chain_creation_call: gw_set_chain_creation_call,
            v28_gw_set_new_version_call: gw_set_new_version_call,
            v28_set_chain_creation_call: set_chain_creation_call,
            v28_set_new_version_call: set_new_version_call,
        }
    }

    fn verify(
        &self,
        patch_upgrade_calls: &CallList,
        new_l1_verifier: Address,
        new_gw_verifier: Address,
    ) -> anyhow::Result<()> {
        const SET_UPGRADE_DIAMOND_CUT_INDEX: usize = 0;   
        const NEW_VERSION_UPGRADE_INDEX: usize = 1;
        const SET_CHAIN_CREATION_INDEX: usize = 2;
        const GATEWAY_SET_UPGRADE_DIAMOND_CUT_INDEX: usize = 3;
        const GATEWAY_NEW_VERSION_UPGRADE_INDEX: usize = 4;
        const GATEWAY_SET_CHAIN_CREATION_INDEX: usize = 5;

        let set_upgrade_diamond_cut_call = patch_upgrade_calls.elems[SET_UPGRADE_DIAMOND_CUT_INDEX].clone();
        let new_version_upgrade_call = patch_upgrade_calls.elems[NEW_VERSION_UPGRADE_INDEX].clone();
        let set_chain_creation_call = patch_upgrade_calls.elems[SET_CHAIN_CREATION_INDEX].clone();
        let gw_set_upgrade_diamond_cut_call = patch_upgrade_calls.elems[GATEWAY_SET_UPGRADE_DIAMOND_CUT_INDEX].clone();
        let gw_new_version_upgrade_call = patch_upgrade_calls.elems[GATEWAY_NEW_VERSION_UPGRADE_INDEX].clone();
        let gw_set_chain_creation_call = patch_upgrade_calls.elems[GATEWAY_SET_CHAIN_CREATION_INDEX].clone();

        validate_new_set_chain_creation_call(
            &self.v28_set_chain_creation_call,
            &set_chain_creation_call,
            new_l1_verifier
        )?;
        validate_set_new_version_upgrade_call(
            &self.v28_set_new_version_call,
            &new_version_upgrade_call,
            new_l1_verifier
        );
        validate_set_upgrade_diamond_cut_call(
            &self.v28_set_new_version_call,
            &set_upgrade_diamond_cut_call,
            new_l1_verifier
        );

        validate_new_set_chain_creation_call(
            &self.v28_gw_set_chain_creation_call,
            &gw_set_chain_creation_call,
            new_gw_verifier
        )?;
        validate_set_new_version_upgrade_call(
            &self.v28_gw_set_new_version_call,
            &gw_new_version_upgrade_call,
            new_gw_verifier
        );
        validate_set_upgrade_diamond_cut_call(
            &self.v28_gw_set_new_version_call,
            &gw_set_upgrade_diamond_cut_call,
            new_gw_verifier
        );
        
    }
}
