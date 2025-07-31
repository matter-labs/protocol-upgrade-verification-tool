//! This file is dedicated to parsing the previous v28 upgrade data.
//! The results will be used to ensure minimal changes in v28.1 patch.

use alloy::{dyn_abi::SolType, hex, primitives::{Address, FixedBytes, U256}, sol_types::{SolCall, SolValue}};

use crate::{elements::{call_list::{Call, CallList}, governance_stage_calls::{setChainCreationParamsCall, GovernanceStage0Calls, GovernanceStage1Calls, GovernanceStage2Calls}, initialize_data_new_chain::InitializeDataNewChain, set_new_version_upgrade::{setNewVersionUpgradeCall, setUpgradeDiamondCutCall, upgradeCall}, UpgradeOutput}, verifiers};
use alloy::sol;


pub(crate) struct V28UpgradeComparator {
    v28_set_chain_creation_call: Call,
    v28_set_new_version_call: Call,
    v28_gw_set_chain_creation_call: Call,
    v28_gw_set_new_version_call: Call,
    
    l1_bridgehub_address: Address,
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
        <InitializeDataNewChain as SolType>::abi_decode(&previous_params.diamondCut.initCalldata, true)?;
    let new_init_data =
        <InitializeDataNewChain as SolType>::abi_decode(&new_params.diamondCut.initCalldata, true)?;

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
    new_verifier: Address,
    expected_upgrade_diamond_cut: String
) -> anyhow::Result<()>{
    assert_eq!(previous.target, new.target, "Set chain creation call target should be the same.");
    assert_eq!(previous.value, new.value, "Set chain creation call value should be the same.");

    let previous_params = setNewVersionUpgradeCall::abi_decode(&previous.data, true)?;
    let new_params = setNewVersionUpgradeCall::abi_decode(&new.data, true)?;

    // Changing from the previous to the new version
    assert_eq!(new_params.oldProtocolVersion, previous_params.newProtocolVersion);
    // Patch upgrade, so should increment the protocol version by 1.
    let correct_new_version = previous_params.newProtocolVersion + U256::from(1);
    assert_eq!(new_params.newProtocolVersion, correct_new_version);

    // TODO: decide on the deadline
    assert_eq!(new_params.diamondCut.facetCuts.len(), 0, "Diamond cut facet cuts should be empty.");
    assert_eq!(new_params.diamondCut.initAddress, previous_params.diamondCut.initAddress, "Diamond cut init address should be the same.");

    let new_upgrade_data = upgradeCall::abi_decode(&new_params.diamondCut.initCalldata, true)?;

    // Updating the verifier address
    assert_eq!(new_upgrade_data._proposedUpgrade.verifier, new_verifier, "Upgrade timestamp should be zero for patch upgrade.");

    // The rest of the fields are empty, i.e. not updated.
    assert_eq!(new_upgrade_data._proposedUpgrade.l2ProtocolUpgradeTx, Default::default(), "L2 protocol upgrade tx should be default for patch upgrade.");
    assert_eq!(new_upgrade_data._proposedUpgrade.bootloaderHash, FixedBytes::<32>::default(), "Bootloader hash should be default for patch upgrade.");
    assert_eq!(new_upgrade_data._proposedUpgrade.defaultAccountHash, FixedBytes::<32>::default(), "Default account hash should be default for patch upgrade.");
    assert_eq!(new_upgrade_data._proposedUpgrade.evmEmulatorHash, FixedBytes::<32>::default(), "EVM emulator hash should be default for patch upgrade.");
    assert_eq!(new_upgrade_data._proposedUpgrade.verifierParams, Default::default(), "Verifier params should be default for patch upgrade.");
    assert!(new_upgrade_data._proposedUpgrade.postUpgradeCalldata.is_empty(), "Post upgrade calldata should be empty for patch upgrade.");
    assert_eq!(new_upgrade_data._proposedUpgrade.upgradeTimestamp, U256::ZERO, "Upgrade timestamp should be zero for patch upgrade.");
    assert_eq!(new_upgrade_data._proposedUpgrade.newProtocolVersion, new_params.newProtocolVersion, "New protocol version should match for patch upgrade.");

    assert_eq!(hex::encode(new_params.diamondCut.abi_encode()), expected_upgrade_diamond_cut[2..].to_string(), "Upgrade diamond cut should match the expected one.");

    Ok(())
}

fn validate_set_upgrade_diamond_cut_call(
    previous_set_new_version_upgrade_call: &Call,
    new: &Call,
    new_verifier: Address
) -> anyhow::Result<()> {
    assert_eq!(previous_set_new_version_upgrade_call.target, new.target, "Set chain creation call target should be the same.");
    assert_eq!(previous_set_new_version_upgrade_call.value, new.value, "Set chain creation call value should be the same.");

    let previous_params = setNewVersionUpgradeCall::abi_decode(&previous_set_new_version_upgrade_call.data, true)?;
    let new_params = setUpgradeDiamondCutCall::abi_decode(&new.data, true)?;

    // Overwriting old protocol version's upgrade.
    assert_eq!(new_params._oldProtocolVersion, previous_params.oldProtocolVersion);

    assert_eq!(new_params._cutData.initAddress, previous_params.diamondCut.initAddress, "Diamond cut init address should be the same.");
    assert_eq!(new_params._cutData.facetCuts, previous_params.diamondCut.facetCuts, "Diamond cut facet cuts should be the same.");

    let previous_upgrade_data = upgradeCall::abi_decode(&previous_params.diamondCut.initCalldata, true)?;
    let new_upgrade_data = upgradeCall::abi_decode(&new_params._cutData.initCalldata, true)?;

    assert_eq!(previous_upgrade_data._proposedUpgrade.l2ProtocolUpgradeTx, new_upgrade_data._proposedUpgrade.l2ProtocolUpgradeTx, "L2 protocol upgrade tx should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.bootloaderHash, new_upgrade_data._proposedUpgrade.bootloaderHash, "Bootloader hash should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.defaultAccountHash, new_upgrade_data._proposedUpgrade.defaultAccountHash, "Default account hash should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.evmEmulatorHash, new_upgrade_data._proposedUpgrade.evmEmulatorHash, "EVM emulator hash should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.verifierParams, new_upgrade_data._proposedUpgrade.verifierParams, "Verifier params should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.l1ContractsUpgradeCalldata, new_upgrade_data._proposedUpgrade.l1ContractsUpgradeCalldata, "L1 contracts upgrade calldata should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.postUpgradeCalldata, new_upgrade_data._proposedUpgrade.postUpgradeCalldata, "Post upgrade calldata should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.upgradeTimestamp, new_upgrade_data._proposedUpgrade.upgradeTimestamp, "Upgrade timestamp should be the same.");
    assert_eq!(previous_upgrade_data._proposedUpgrade.newProtocolVersion, new_upgrade_data._proposedUpgrade.newProtocolVersion, "New protocol version should be the same.");

    // The verifier address is expected to change to the new one.
    assert!(previous_upgrade_data._proposedUpgrade.verifier != new_verifier, "Verifier address should be changed to the new one.");
    assert!(new_upgrade_data._proposedUpgrade.verifier == new_verifier, "Verifier address should be changed to the new one.");

    Ok(())
}


impl V28UpgradeComparator {
    pub(crate) fn new(v28_upgrade_config: UpgradeOutput, l1_bridgehub_address: Address) -> Self {
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
            l1_bridgehub_address,
        }
    }

    fn verify_stage0_calls(
        &self,
        stage0_upgrade_calls: CallList,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {
        // The stage0 calls are close to the v28, we can reuse the same verification logic.
        let stage0_calls = GovernanceStage0Calls {
            calls: stage0_upgrade_calls,
        };

        stage0_calls.verify(verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;
        Ok(())
    }

    fn verify_stage2_calls(
        &self,
        stage0_upgrade_calls: CallList,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64
    ) -> anyhow::Result<()> {
        // The stage2 calls are close to the v28, we can reuse the same verification logic.
        let stage2_calls = GovernanceStage2Calls {
            calls: stage0_upgrade_calls,
        };

        stage2_calls.verify(verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;
        Ok(())
    }

    fn verify_stage1_calls(
        &self, 
        result: &mut crate::verifiers::VerificationResult,
        v28_patch_upgrade_config: &UpgradeOutput,
        patch_upgrade_calls: CallList,
        new_l1_verifier: Address,
        new_gw_verifier: Address
    ) -> anyhow::Result<()> {
        let v28_patch_upgrade_cut = v28_patch_upgrade_config.chain_upgrade_diamond_cut.clone();
        println!("=== Gov stage 1 calls ===");

        validate_set_new_version_upgrade_call(
            &self.v28_set_new_version_call,
            &patch_upgrade_calls.elems[1],
            new_l1_verifier,
            v28_patch_upgrade_cut
        )?;
        result.report_ok("Set new version upgrade (L1) call is valid");
        return Ok(());

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

        // validate_new_set_chain_creation_call(
        //     &self.v28_set_chain_creation_call,
        //     &set_chain_creation_call,
        //     new_l1_verifier
        // )?;
        // validate_set_new_version_upgrade_call(
        //     &self.v28_set_new_version_call,
        //     &new_version_upgrade_call,
        //     new_l1_verifier
        // )?;
        // validate_set_upgrade_diamond_cut_call(
        //     &self.v28_set_new_version_call,
        //     &set_upgrade_diamond_cut_call,
        //     new_l1_verifier
        // )?;

        // validate_new_set_chain_creation_call(
        //     &self.v28_gw_set_chain_creation_call,
        //     &gw_set_chain_creation_call,
        //     new_gw_verifier
        // )?;
        // validate_set_new_version_upgrade_call(
        //     &self.v28_gw_set_new_version_call,
        //     &gw_new_version_upgrade_call,
        //     new_gw_verifier
        // )?;
        // validate_set_upgrade_diamond_cut_call(
        //     &self.v28_gw_set_new_version_call,
        //     &gw_set_upgrade_diamond_cut_call,
        //     new_gw_verifier
        // )?;



        Ok(())
    }

    pub(crate) fn verify(
        &self,
        v28_patch_upgrade_config: &UpgradeOutput,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {

        let stage0_upgrade_calls = CallList::parse(&v28_patch_upgrade_config.governance_calls.governance_stage0_calls);

        println!("{:#?}", stage0_upgrade_calls);

        let stage1_upgrade_calls = CallList::parse(&v28_patch_upgrade_config.governance_calls.governance_stage1_calls);

        println!("{:#?}", stage1_upgrade_calls);

        let stage2_upgrade_calls = CallList::parse(&v28_patch_upgrade_config.governance_calls.governance_stage2_calls);

        println!("{:#?}", stage2_upgrade_calls);

        let new_l1_verifier = v28_patch_upgrade_config.deployed_addresses.state_transition.verifier_addr;
        let new_gw_verifier = Address::ZERO;

        self.verify_stage0_calls(stage0_upgrade_calls, verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;

        self.verify_stage1_calls(
            result,
            v28_patch_upgrade_config,
            stage1_upgrade_calls,
            new_l1_verifier,
            new_gw_verifier
        )?;

        self.verify_stage2_calls(stage2_upgrade_calls, verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;


        Ok(())
        
    }
}
