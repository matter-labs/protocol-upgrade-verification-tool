//! This file is dedicated to parsing the previous v28 upgrade data.
//! The results will be used to ensure minimal changes in v28.1 patch.

use std::result;

use alloy::{dyn_abi::SolType, hex, primitives::{Address, FixedBytes, U256}, sol_types::{SolCall, SolConstructor, SolValue}};

use crate::{elements::{call_list::{Call, CallList}, deployed_addresses::{DualVerifier, UpgradeStageValidator}, governance_stage_calls::{check_and_parse_inner_call_from_gateway_transaction, setChainCreationParamsCall, GovernanceStage0Calls, GovernanceStage1Calls, GovernanceStage2Calls}, initialize_data_new_chain::InitializeDataNewChain, set_new_version_upgrade::{setNewVersionUpgradeCall, setUpgradeDiamondCutCall, upgradeCall}, UpgradeOutput}, verifiers};
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

    assert!(previous_init_data.verifier != new_verifier, "Verifier same as the previous one.");
    assert_eq!(new_init_data.verifier, new_verifier, "New verifier is not consistent with config.");

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
    assert!(previous_upgrade_data._proposedUpgrade.verifier != new_verifier, "Verifier same as the previous one.");
    assert_eq!(new_upgrade_data._proposedUpgrade.verifier, new_verifier, "New verifier is not consistent with config.");

    Ok(())
}

impl V28UpgradeComparator {
    pub(crate) fn new(
        result: &mut crate::verifiers::VerificationResult,
        v28_upgrade_config: UpgradeOutput, 
        l1_bridgehub_address: Address,
        gateway_chain_id: u64
    ) -> Self {
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
        let gw_set_chain_creation_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_calls.elems[GATEWAY_NEW_CHAIN_CREATION_PARAMS].data,
            gateway_chain_id,
            None
        );
        let gw_set_new_version_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_calls.elems[GATEWAY_SET_NEW_VERSION].data,
            gateway_chain_id,
            None
        );

        Self {
            v28_gw_set_chain_creation_call: gw_set_chain_creation_call,
            v28_gw_set_new_version_call: gw_set_new_version_call,
            v28_set_chain_creation_call: set_chain_creation_call,
            v28_set_new_version_call: set_new_version_call,
            l1_bridgehub_address,
        }
    }

    pub(crate) fn display_encoded_previous_data(&self) {
        let previous_chain_creation_call = setChainCreationParamsCall::abi_decode(&self.v28_set_chain_creation_call.data, true).expect("Failed to decode previous set chain creation call");
        println!("=== v28 previous set chain creation params (L1) ===\n{}\n", hex::encode(&previous_chain_creation_call._chainCreationParams.abi_encode()));

        let previous_chain_creation_call_gw = setChainCreationParamsCall::abi_decode(&self.v28_gw_set_chain_creation_call.data, true).expect("Failed to decode previous set chain creation call");
        println!("=== v28 previous set chain creation params (GWs) ===\n{}\n", hex::encode(&previous_chain_creation_call_gw._chainCreationParams.abi_encode()));

        let previous_set_new_version_call = setNewVersionUpgradeCall::abi_decode(&self.v28_set_new_version_call.data, true).expect("Failed to decode previous set new version call");
        println!("===v28 previous set new version call (L1)===\n{}\n", hex::encode(&previous_set_new_version_call.diamondCut.abi_encode()));
        
        let previous_set_new_version_call_gw = setNewVersionUpgradeCall::abi_decode(&self.v28_gw_set_new_version_call.data, true).expect("Failed to decode previous set new version call");
        println!("===v28 previous set new version call (GW)===\n{}\n", hex::encode(&previous_set_new_version_call_gw.diamondCut.abi_encode()));
    }

    fn verify_stage0_calls(
        &self,
        stage0_upgrade_calls: CallList,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {
        println!("stage0_upgrade_calls {:#?}", stage0_upgrade_calls);
        // The stage0 calls are close to the v28, we can reuse the same verification logic.
        let stage0_calls = GovernanceStage0Calls {
            calls: stage0_upgrade_calls,
        };

        stage0_calls.verify(verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;
        Ok(())
    }

    fn verify_stage2_calls(
        &self,
        stage2_upgrade_calls: CallList,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64
    ) -> anyhow::Result<()> {
        println!("stage2_upgrade_calls {:#?}", stage2_upgrade_calls);

        // The stage2 calls are close to the v28, we can reuse the same verification logic.
        let stage2_calls = GovernanceStage2Calls {
            calls: stage2_upgrade_calls,
        };

        stage2_calls.verify(verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;
        Ok(())
    }

    fn verify_stage1_calls(
        &self, 
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        v28_patch_upgrade_config: &UpgradeOutput,
        stage1_upgrade_calls: CallList,
        new_l1_verifier: Address,
        new_gw_verifier: Address,
    ) -> anyhow::Result<()> {
        println!("stage1_upgrade_calls {:#?}", stage1_upgrade_calls);

        const SET_CHAIN_CREATION_PARAMS_L1_INDEX: usize = 1;
        const SET_UPGRADE_DIAMOND_CUT_INDEX: usize = 2;

        let v28_patch_upgrade_cut = v28_patch_upgrade_config.chain_upgrade_diamond_cut.clone();
        let v28_gw_path_upgrade_call =v28_patch_upgrade_config.gateway.upgrade_cut_data.clone();
        println!("=== Gov stage 1 calls v28 ===");

        // TODO
        validate_new_set_chain_creation_call(
            &self.v28_set_chain_creation_call,
            &stage1_upgrade_calls.elems[SET_CHAIN_CREATION_PARAMS_L1_INDEX],
            new_l1_verifier
        )?;
        println!("=== kl todo 1");
        validate_set_new_version_upgrade_call(
            &self.v28_set_new_version_call,
            &stage1_upgrade_calls.elems[2],
            new_l1_verifier,
            v28_patch_upgrade_cut
        )?;
        println!("=== kl todo 2");

        validate_set_upgrade_diamond_cut_call(
            &self.v28_set_new_version_call,
            &stage1_upgrade_calls.elems[3],
            new_l1_verifier
        )?;

        let gw_new_set_new_version_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_upgrade_calls.elems[5].data,
            v28_patch_upgrade_config.gateway_chain_id,
            Some(v28_patch_upgrade_config.priority_txs_l2_gas_limit)
        );
        validate_set_new_version_upgrade_call(
            &self.v28_gw_set_new_version_call,
            &gw_new_set_new_version_call,
            new_gw_verifier,
            v28_gw_path_upgrade_call
        )?;

        let gw_chain_creation_params_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_upgrade_calls.elems[7].data,
            v28_patch_upgrade_config.gateway_chain_id,
            Some(v28_patch_upgrade_config.priority_txs_l2_gas_limit)
        );
        validate_new_set_chain_creation_call(
            &self.v28_gw_set_chain_creation_call,
            &gw_chain_creation_params_call,
            new_gw_verifier
        )?;

        let set_upgrade_diamond_cut_params_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_upgrade_calls.elems[9].data,
            v28_patch_upgrade_config.gateway_chain_id,
            Some(v28_patch_upgrade_config.priority_txs_l2_gas_limit)
        );
        validate_set_upgrade_diamond_cut_call(
            &self.v28_gw_set_new_version_call,
            &set_upgrade_diamond_cut_params_call,
            new_gw_verifier
        )?;


        result.report_ok("Set new version upgrade (L1) call is valid");
        return Ok(());
    }

    async fn verify_deployed_addresses(
        &self,
        result: &mut crate::verifiers::VerificationResult,
        v28_patch_upgrade_config: &UpgradeOutput,
        verifiers: &mut verifiers::Verifiers,
    ) -> anyhow::Result<()> {
        let bridgehub_info = verifiers.network_verifier.get_bridgehub_info(verifiers.bridgehub_address).await;
        result.expect_create2_params(
            verifiers,
            &v28_patch_upgrade_config.deployed_addresses.upgrade_stage_validator,
            UpgradeStageValidator::constructorCall::new((
                bridgehub_info.stm_address,
                U256::from(v28_patch_upgrade_config.contracts_config.as_ref().unwrap().new_protocol_version),
            )).abi_encode(),
            "l1-contracts/UpgradeStageValidator",
        );

        let state_transition = &v28_patch_upgrade_config.deployed_addresses.state_transition;
        result.expect_create2_params(
            verifiers,
            &state_transition.verifier_plonk_addr,
            Vec::new(),
            "l1-contracts/L1VerifierPlonk",
        );

        result.expect_create2_params(
            verifiers,
            &state_transition.verifier_fflonk_addr,
            Vec::new(),
            "l1-contracts/L1VerifierFflonk",
        );

        let expected_constructor_params = DualVerifier::constructorCall::new((
            state_transition.verifier_fflonk_addr,
            state_transition.verifier_plonk_addr,
        ))
        .abi_encode();

        result.expect_create2_params(
            verifiers,
            &state_transition.verifier_addr,
            expected_constructor_params,
            if verifiers.testnet_contracts {
                "l1-contracts/TestnetVerifier"
            } else {
                "l1-contracts/DualVerifier"
            },
        );

        let gateway_state_transition = &v28_patch_upgrade_config.gateway.gateway_state_transition;
        
        // result.expect_zk_create2_address(
        //     verifiers, 
        //     &gateway_state_transition.verifier_fflonk_addr, 
        //     Vec::new(), 
        //     "l1-contracts/L1VerifierFflonk",
        //     Default::default()
        // );
        // result.expect_zk_create2_address(
        //     verifiers, 
        //     &gateway_state_transition.verifier_plonk_addr, 
        //     Vec::new(), 
        //     "l1-contracts/L1VerifierPlonk",
        //     Default::default()
        // );
        // let expected_constructor_params = DualVerifier::constructorCall::new((
        //     gateway_state_transition.verifier_fflonk_addr,
        //     gateway_state_transition.verifier_plonk_addr,
        // ))
        // .abi_encode();

        // result.expect_zk_create2_address(
        //     verifiers, 
        //     &gateway_state_transition.verifier_addr, 
        //     expected_constructor_params, 
        // if verifiers.testnet_contracts {
        //         "l1-contracts/TestnetVerifier"
        //     } else {
        //         "l1-contracts/DualVerifier"
        //     },
        //     Default::default()
        // );

        Ok(())
    }

    pub(crate) async fn verify(
        &self,
        v28_patch_upgrade_config: &UpgradeOutput,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {

        self.verify_deployed_addresses(
            result,
            v28_patch_upgrade_config,
            verifiers
        ).await?;

        let stage0_upgrade_calls = CallList::parse(&v28_patch_upgrade_config.governance_calls.governance_stage0_calls);

        println!("{:#?}", stage0_upgrade_calls);

        let stage1_upgrade_calls = CallList::parse(&v28_patch_upgrade_config.governance_calls.governance_stage1_calls);

        println!("{:#?}", stage1_upgrade_calls);

        let stage2_upgrade_calls = CallList::parse(&v28_patch_upgrade_config.governance_calls.governance_stage2_calls);

        println!("{:#?}", stage2_upgrade_calls);

        let new_l1_verifier = v28_patch_upgrade_config.deployed_addresses.state_transition.verifier_addr;
        let new_gw_verifier = v28_patch_upgrade_config.gateway.gateway_state_transition.verifier_addr;

        self.verify_stage0_calls(stage0_upgrade_calls, verifiers, result, gateway_chain_id, priority_txs_l2_gas_limit)?;

        self.verify_stage1_calls(
            verifiers,
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
