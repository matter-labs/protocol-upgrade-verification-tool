//! This file is dedicated to parsing the previous v28 upgrade data.
//! The results will be used to ensure minimal changes in v28.1 patch.

use crate::{
    elements::{
        call_list::{Call, CallList},
        deployed_addresses::{DualVerifier, UpgradeStageValidator},
        governance_stage_calls::{
            check_and_parse_inner_call_from_gateway_transaction, setChainCreationParamsCall,
            GovernanceStage0Calls, GovernanceStage2Calls,
        },
        initialize_data_new_chain::InitializeDataNewChain,
        set_new_version_upgrade::{
            setNewVersionUpgradeCall, setUpgradeDiamondCutCall, upgradeCall,
        },
        UpgradeOutput,
    },
    verifiers,
};
use alloy::{
    dyn_abi::SolType,
    hex,
    primitives::{Address, FixedBytes, U256},
    sol_types::{SolCall, SolConstructor, SolValue},
};

pub(crate) struct V28UpgradeComparator {
    v28_set_chain_creation_call: Call,
    v28_set_new_version_call: Call,
    v28_gw_set_chain_creation_call: Call,
    v28_gw_set_new_version_call: Call,
}

fn validate_new_set_chain_creation_call(
    previous: &Call,
    new: &Call,
    new_verifier: Address,
    expected_diamond_cut: String,
) -> anyhow::Result<()> {
    assert_eq!(
        previous.target, new.target,
        "Set chain creation call target should be the same."
    );
    assert_eq!(
        previous.value, new.value,
        "Set chain creation call value should be the same."
    );

    let previous_params =
        setChainCreationParamsCall::abi_decode(&previous.data, true)?._chainCreationParams;
    let new_params = setChainCreationParamsCall::abi_decode(&new.data, true)?._chainCreationParams;

    assert_eq!(
        previous_params.genesisUpgrade, new_params.genesisUpgrade,
        "Genesis upgrade should be the same."
    );
    assert_eq!(
        previous_params.genesisBatchHash, new_params.genesisBatchHash,
        "Genesis batch hash should be the same."
    );
    assert_eq!(
        previous_params.genesisIndexRepeatedStorageChanges,
        new_params.genesisIndexRepeatedStorageChanges,
        "Genesis index repeated storage changes should be the same."
    );
    assert_eq!(
        previous_params.genesisBatchCommitment, new_params.genesisBatchCommitment,
        "Genesis batch commitment should be the same."
    );
    assert_eq!(
        previous_params.forceDeploymentsData, new_params.forceDeploymentsData,
        "Force deployments data should be the same."
    );

    // Now, comparing the diamond cut

    assert_eq!(
        previous_params.diamondCut.initAddress, new_params.diamondCut.initAddress,
        "Diamond cut init address should be the same."
    );
    assert_eq!(
        previous_params.diamondCut.facetCuts, new_params.diamondCut.facetCuts,
        "Diamond cut facet cuts should be the same."
    );

    let previous_init_data = <InitializeDataNewChain as SolType>::abi_decode(
        &previous_params.diamondCut.initCalldata,
        true,
    )?;
    let new_init_data =
        <InitializeDataNewChain as SolType>::abi_decode(&new_params.diamondCut.initCalldata, true)?;

    assert_eq!(
        &expected_diamond_cut[2..],
        hex::encode(new_params.diamondCut.abi_encode()),
        "Diamond cut should match the expected one."
    );

    // Now we check that all is equal except for veriifer address.

    assert_eq!(
        previous_init_data.verifierParams, new_init_data.verifierParams,
        "Verifier params should be the same."
    );
    assert_eq!(
        previous_init_data.l2BootloaderBytecodeHash, new_init_data.l2BootloaderBytecodeHash,
        "L2 bootloader bytecode hash should be the same."
    );
    assert_eq!(
        previous_init_data.l2DefaultAccountBytecodeHash, new_init_data.l2DefaultAccountBytecodeHash,
        "L2 default account bytecode hash should be the same."
    );
    assert_eq!(
        previous_init_data.l2EvmEmulatorBytecodeHash, new_init_data.l2EvmEmulatorBytecodeHash,
        "L2 EVM emulator bytecode hash should be the same."
    );
    assert_eq!(
        previous_init_data.priorityTxMaxGasLimit, new_init_data.priorityTxMaxGasLimit,
        "Priority TX max gas limit should be the same."
    );
    assert_eq!(
        previous_init_data.feeParams, new_init_data.feeParams,
        "Fee params should be the same."
    );
    assert_eq!(
        previous_init_data.blobVersionedHashRetriever, new_init_data.blobVersionedHashRetriever,
        "Blob versioned hash retriever should be the same."
    );

    assert!(
        previous_init_data.verifier != new_verifier,
        "Verifier must change in a patch upgrade."
    );
    assert_eq!(
        new_init_data.verifier, new_verifier,
        "New verifier is not consistent with config."
    );

    Ok(())
}

fn validate_set_new_version_upgrade_call(
    previous: &Call,
    new: &Call,
    new_verifier: Address,
    expected_new_version: U256,
    expected_upgrade_diamond_cut: String,
) -> anyhow::Result<()> {
    assert_eq!(
        previous.target, new.target,
        "Set chain creation call target should be the same."
    );
    assert_eq!(
        previous.value, new.value,
        "Set chain creation call value should be the same."
    );

    let previous_params = setNewVersionUpgradeCall::abi_decode(&previous.data, true)?;
    let new_params = setNewVersionUpgradeCall::abi_decode(&new.data, true)?;

    // Changing from the previous to the new version
    assert_eq!(
        new_params.oldProtocolVersion,
        previous_params.newProtocolVersion
    );
    // Patch upgrade, so should increment the protocol version by 1.
    let correct_new_version = previous_params.newProtocolVersion + U256::from(1);
    assert_eq!(
        new_params.newProtocolVersion, correct_new_version,
        "The protocol version should be incremented by 1 for patch upgrade."
    );
    assert_eq!(
        new_params.newProtocolVersion, expected_new_version,
        "New protocol version should match the expected one."
    );

    assert_eq!(
        new_params.oldProtocolVersionDeadline,
        U256::MAX,
        "Old protocol version deadline should be max for patch upgrade."
    );
    assert!(
        new_params.diamondCut.facetCuts.is_empty(),
        "Diamond cut facet cuts should be empty."
    );
    assert_eq!(
        new_params.diamondCut.initAddress, previous_params.diamondCut.initAddress,
        "Diamond cut init address should be the same."
    );

    let new_upgrade_data = upgradeCall::abi_decode(&new_params.diamondCut.initCalldata, true)?;

    // Updating the verifier address
    assert_eq!(
        new_upgrade_data._proposedUpgrade.verifier, new_verifier,
        "Verifier was not updated to the new one."
    );

    // The rest of the fields are empty, i.e. not updated.
    assert_eq!(
        new_upgrade_data._proposedUpgrade.l2ProtocolUpgradeTx,
        Default::default(),
        "L2 protocol upgrade tx should be default for patch upgrade."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.bootloaderHash,
        FixedBytes::<32>::default(),
        "Bootloader hash should be default for patch upgrade."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.defaultAccountHash,
        FixedBytes::<32>::default(),
        "Default account hash should be default for patch upgrade."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.evmEmulatorHash,
        FixedBytes::<32>::default(),
        "EVM emulator hash should be default for patch upgrade."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.verifierParams,
        Default::default(),
        "Verifier params should be default for patch upgrade."
    );
    assert!(
        new_upgrade_data
            ._proposedUpgrade
            .postUpgradeCalldata
            .is_empty(),
        "Post upgrade calldata should be empty for patch upgrade."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.upgradeTimestamp,
        U256::ZERO,
        "Upgrade timestamp should be zero for patch upgrade."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.newProtocolVersion, new_params.newProtocolVersion,
        "New protocol version should match for patch upgrade."
    );

    assert_eq!(
        hex::encode(new_params.diamondCut.abi_encode()),
        expected_upgrade_diamond_cut[2..].to_string(),
        "Upgrade diamond cut should match the expected one."
    );

    Ok(())
}

fn validate_set_upgrade_diamond_cut_call(
    previous_set_new_version_upgrade_call: &Call,
    new: &Call,
    new_verifier: Address,
) -> anyhow::Result<()> {
    assert_eq!(
        previous_set_new_version_upgrade_call.target, new.target,
        "Set chain creation call target should be the same."
    );
    assert_eq!(
        previous_set_new_version_upgrade_call.value, new.value,
        "Set chain creation call value should be the same."
    );

    let previous_params =
        setNewVersionUpgradeCall::abi_decode(&previous_set_new_version_upgrade_call.data, true)?;
    let new_params = setUpgradeDiamondCutCall::abi_decode(&new.data, true)?;

    // Overwriting old protocol version's upgrade.
    assert_eq!(
        new_params._oldProtocolVersion,
        previous_params.oldProtocolVersion
    );

    assert_eq!(
        new_params._cutData.initAddress, previous_params.diamondCut.initAddress,
        "Diamond cut init address should be the same."
    );
    assert_eq!(
        new_params._cutData.facetCuts, previous_params.diamondCut.facetCuts,
        "Diamond cut facet cuts should be the same."
    );

    let previous_upgrade_data =
        upgradeCall::abi_decode(&previous_params.diamondCut.initCalldata, true)?;
    let new_upgrade_data = upgradeCall::abi_decode(&new_params._cutData.initCalldata, true)?;

    assert_eq!(
        previous_upgrade_data._proposedUpgrade.l2ProtocolUpgradeTx,
        new_upgrade_data._proposedUpgrade.l2ProtocolUpgradeTx,
        "L2 protocol upgrade tx should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.bootloaderHash,
        new_upgrade_data._proposedUpgrade.bootloaderHash,
        "Bootloader hash should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.defaultAccountHash,
        new_upgrade_data._proposedUpgrade.defaultAccountHash,
        "Default account hash should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.evmEmulatorHash,
        new_upgrade_data._proposedUpgrade.evmEmulatorHash,
        "EVM emulator hash should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.verifierParams,
        new_upgrade_data._proposedUpgrade.verifierParams,
        "Verifier params should be the same."
    );
    assert_eq!(
        previous_upgrade_data
            ._proposedUpgrade
            .l1ContractsUpgradeCalldata,
        new_upgrade_data._proposedUpgrade.l1ContractsUpgradeCalldata,
        "L1 contracts upgrade calldata should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.postUpgradeCalldata,
        new_upgrade_data._proposedUpgrade.postUpgradeCalldata,
        "Post upgrade calldata should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.upgradeTimestamp,
        new_upgrade_data._proposedUpgrade.upgradeTimestamp,
        "Upgrade timestamp should be the same."
    );
    assert_eq!(
        previous_upgrade_data._proposedUpgrade.newProtocolVersion,
        new_upgrade_data._proposedUpgrade.newProtocolVersion,
        "New protocol version should be the same."
    );

    // The verifier address is expected to change to the new one.
    assert!(
        previous_upgrade_data._proposedUpgrade.verifier != new_verifier,
        "Verifier same as the previous one."
    );
    assert_eq!(
        new_upgrade_data._proposedUpgrade.verifier, new_verifier,
        "New verifier is not consistent with config."
    );

    Ok(())
}

impl V28UpgradeComparator {
    pub(crate) fn new(
        result: &mut crate::verifiers::VerificationResult,
        v28_upgrade_config: UpgradeOutput,
        gateway_chain_id: u64,
    ) -> Self {
        let UpgradeOutput {
            governance_calls, ..
        } = v28_upgrade_config;

        const SET_CHAIN_CREATION_INDEX: usize = 8;
        const SET_NEW_VERSION_INDEX: usize = 9;
        const GATEWAY_SET_NEW_VERSION: usize = 12;
        const GATEWAY_NEW_CHAIN_CREATION_PARAMS: usize = 14;

        let stage1_calls: CallList = CallList::parse(&governance_calls.governance_stage1_calls);

        let set_chain_creation_call = stage1_calls.elems[SET_CHAIN_CREATION_INDEX].clone();
        let set_new_version_call = stage1_calls.elems[SET_NEW_VERSION_INDEX].clone();
        let gw_set_chain_creation_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_calls.elems[GATEWAY_NEW_CHAIN_CREATION_PARAMS].data,
            gateway_chain_id,
            None,
        );
        let gw_set_new_version_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_calls.elems[GATEWAY_SET_NEW_VERSION].data,
            gateway_chain_id,
            None,
        );

        Self {
            v28_gw_set_chain_creation_call: gw_set_chain_creation_call,
            v28_gw_set_new_version_call: gw_set_new_version_call,
            v28_set_chain_creation_call: set_chain_creation_call,
            v28_set_new_version_call: set_new_version_call,
        }
    }

    pub(crate) fn display_encoded_previous_data(&self) {
        let previous_chain_creation_call =
            setChainCreationParamsCall::abi_decode(&self.v28_set_chain_creation_call.data, true)
                .expect("Failed to decode previous set chain creation call");
        println!(
            "=== v28 previous set chain creation params (L1) ===\n{}\n",
            hex::encode(
                &previous_chain_creation_call
                    ._chainCreationParams
                    .abi_encode()
            )
        );

        let previous_chain_creation_call_gw =
            setChainCreationParamsCall::abi_decode(&self.v28_gw_set_chain_creation_call.data, true)
                .expect("Failed to decode previous set chain creation call");
        println!(
            "=== v28 previous set chain creation params (GW) ===\n{}\n",
            hex::encode(
                &previous_chain_creation_call_gw
                    ._chainCreationParams
                    .abi_encode()
            )
        );

        let previous_set_new_version_call =
            setNewVersionUpgradeCall::abi_decode(&self.v28_set_new_version_call.data, true)
                .expect("Failed to decode previous set new version call");
        println!(
            "===v28 previous set new version call (L1)===\n{}\n",
            hex::encode(&previous_set_new_version_call.diamondCut.abi_encode())
        );

        let previous_set_new_version_call_gw =
            setNewVersionUpgradeCall::abi_decode(&self.v28_gw_set_new_version_call.data, true)
                .expect("Failed to decode previous set new version call");
        println!(
            "===v28 previous set new version call (GW)===\n{}\n",
            hex::encode(&previous_set_new_version_call_gw.diamondCut.abi_encode())
        );
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

        stage0_calls.verify(
            verifiers,
            result,
            gateway_chain_id,
            priority_txs_l2_gas_limit,
        )?;
        Ok(())
    }

    fn verify_stage2_calls(
        &self,
        stage2_upgrade_calls: CallList,
        verifiers: &mut verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {
        // The stage2 calls are close to the v28, we can reuse the same verification logic.
        let stage2_calls = GovernanceStage2Calls {
            calls: stage2_upgrade_calls,
        };

        stage2_calls.verify(
            verifiers,
            result,
            gateway_chain_id,
            priority_txs_l2_gas_limit,
        )?;
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
        println!("=== Gov stage 1 calls v28 ===");

        let list_of_calls = [
            // Check that migrations are paused
            ("upgrade_stage_validator", "checkMigrationsPaused()"),
            // Set new version upgrade in the L1 state transition manager (the content will be checked later in this function).
            // Allows chains to upgrade from v28.0 to v28.1.
            (
                "state_transition_manager",
                "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
            ),
            // Set chain creation params in the L1 state transition manager (the content will be checked later in this function).
            // Ensures that new chains will only use the new version.
            ("state_transition_manager",
            "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)"),
            // Update the upgrade diamond cut for v27 in the L1 state transition manager (the content will be checked later in this function).
            // Ensures that chains that currently have version v27 will be able to upgrade to v28.1 rightaway.
            ("state_transition_manager",
            "setUpgradeDiamondCut(((address,uint8,bool,bytes4[])[],address,bytes),uint256)"),
            // Approve base token
            ("gateway_base_token", "approve(address,uint256)"),
            // Set new version upgrade in the GW state transition manager (the content will be checked later in this function).
            // Allows chains to upgrade from v28.0 to v28.1.
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
            // Approve base token
            ("gateway_base_token", "approve(address,uint256)"),
            // Set chain creation params in the GW state transition manager (the content will be checked later in this function).
            // Ensures that chains that connect to GW will only use the new version.
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
            // Approve base token
            ("gateway_base_token", "approve(address,uint256)"),
            // Update the upgrade diamond cut for v27 in the GW state transition manager (the content will be checked later in this function).
            // Ensures that chains that currently have version v27 will be able to upgrade to v28.1 rightaway.
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
        ];

        stage1_upgrade_calls.verify(&list_of_calls, verifiers, result)?;

        const SET_CHAIN_CREATION_PARAMS_L1_INDEX: usize = 1;
        const SET_UPGRADE_DIAMOND_CUT_INDEX: usize = 2;
        const SET_NEW_VERSION_UPGRADE_INDEX: usize = 3;

        const GW_SET_NEW_VERSION_UPGRADE_INDEX: usize = 5;
        const GW_SET_CHAIN_CREATION_PARAMS_INDEX: usize = 7;
        const GW_SET_UPGRADE_DIAMOND_CUT_INDEX: usize = 9;

        let v28_patch_upgrade_cut = v28_patch_upgrade_config.chain_upgrade_diamond_cut.clone();
        let v28_gw_path_upgrade_call = v28_patch_upgrade_config.gateway.upgrade_cut_data.clone();

        let v28_patch_diamond_cut_data = v28_patch_upgrade_config
            .contracts_config
            .as_ref()
            .unwrap()
            .diamond_cut_data
            .clone();
        let v28_gw_patch_upgrade_call = v28_patch_upgrade_config.gateway.diamond_cut_data.clone();

        validate_new_set_chain_creation_call(
            &self.v28_set_chain_creation_call,
            &stage1_upgrade_calls.elems[SET_CHAIN_CREATION_PARAMS_L1_INDEX],
            new_l1_verifier,
            v28_patch_diamond_cut_data,
        )?;
        result.report_ok("Set chain new creation params (L1) call is valid");

        validate_set_new_version_upgrade_call(
            &self.v28_set_new_version_call,
            &stage1_upgrade_calls.elems[SET_UPGRADE_DIAMOND_CUT_INDEX],
            new_l1_verifier,
            U256::from(
                v28_patch_upgrade_config
                    .contracts_config
                    .as_ref()
                    .unwrap()
                    .new_protocol_version,
            ),
            v28_patch_upgrade_cut,
        )?;
        result.report_ok("Set new version upgrade (L1) call is valid");

        validate_set_upgrade_diamond_cut_call(
            &self.v28_set_new_version_call,
            &stage1_upgrade_calls.elems[SET_NEW_VERSION_UPGRADE_INDEX],
            new_l1_verifier,
        )?;
        result.report_ok("Set upgrade diamond cut (L1) call is valid");

        let gw_new_set_new_version_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_upgrade_calls.elems[GW_SET_NEW_VERSION_UPGRADE_INDEX].data,
            v28_patch_upgrade_config.gateway_chain_id,
            Some(v28_patch_upgrade_config.priority_txs_l2_gas_limit),
        );
        validate_set_new_version_upgrade_call(
            &self.v28_gw_set_new_version_call,
            &gw_new_set_new_version_call,
            new_gw_verifier,
            U256::from(
                v28_patch_upgrade_config
                    .contracts_config
                    .as_ref()
                    .unwrap()
                    .new_protocol_version,
            ),
            v28_gw_path_upgrade_call,
        )?;
        result.report_ok("Set new version upgrade (GW) call is valid");

        let gw_chain_creation_params_call = check_and_parse_inner_call_from_gateway_transaction(
            result,
            &stage1_upgrade_calls.elems[GW_SET_CHAIN_CREATION_PARAMS_INDEX].data,
            v28_patch_upgrade_config.gateway_chain_id,
            Some(v28_patch_upgrade_config.priority_txs_l2_gas_limit),
        );
        validate_new_set_chain_creation_call(
            &self.v28_gw_set_chain_creation_call,
            &gw_chain_creation_params_call,
            new_gw_verifier,
            v28_gw_patch_upgrade_call,
        )?;
        result.report_ok("Set chain new creation params (GW) call is valid");

        let set_upgrade_diamond_cut_params_call =
            check_and_parse_inner_call_from_gateway_transaction(
                result,
                &stage1_upgrade_calls.elems[GW_SET_UPGRADE_DIAMOND_CUT_INDEX].data,
                v28_patch_upgrade_config.gateway_chain_id,
                Some(v28_patch_upgrade_config.priority_txs_l2_gas_limit),
            );
        validate_set_upgrade_diamond_cut_call(
            &self.v28_gw_set_new_version_call,
            &set_upgrade_diamond_cut_params_call,
            new_gw_verifier,
        )?;
        result.report_ok("Set upgrade diamond cut (GW) call is valid");

        return Ok(());
    }

    async fn verify_deployed_addresses(
        &self,
        result: &mut crate::verifiers::VerificationResult,
        v28_patch_upgrade_config: &UpgradeOutput,
        verifiers: &mut verifiers::Verifiers,
    ) -> anyhow::Result<()> {
        let bridgehub_info = verifiers
            .network_verifier
            .get_bridgehub_info(verifiers.bridgehub_address)
            .await;
        result.expect_create2_params(
            verifiers,
            &v28_patch_upgrade_config
                .deployed_addresses
                .upgrade_stage_validator,
            UpgradeStageValidator::constructorCall::new((
                bridgehub_info.stm_address,
                U256::from(
                    v28_patch_upgrade_config
                        .contracts_config
                        .as_ref()
                        .unwrap()
                        .new_protocol_version,
                ),
            ))
            .abi_encode(),
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

        result.expect_zk_create2_address(
            verifiers,
            &gateway_state_transition.verifier_fflonk_addr,
            Vec::new(),
            "l1-contracts/L1VerifierFflonk",
            Default::default(),
        );
        result.expect_zk_create2_address(
            verifiers,
            &gateway_state_transition.verifier_plonk_addr,
            Vec::new(),
            "l1-contracts/L1VerifierPlonk",
            Default::default(),
        );
        let expected_constructor_params = DualVerifier::constructorCall::new((
            gateway_state_transition.verifier_fflonk_addr,
            gateway_state_transition.verifier_plonk_addr,
        ))
        .abi_encode();

        result.expect_zk_create2_address(
            verifiers,
            &gateway_state_transition.verifier_addr,
            expected_constructor_params,
            if verifiers.testnet_contracts {
                "l1-contracts/TestnetVerifier"
            } else {
                "l1-contracts/DualVerifier"
            },
            Default::default(),
        );

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
        self.verify_deployed_addresses(result, v28_patch_upgrade_config, verifiers)
            .await?;

        let stage0_upgrade_calls = CallList::parse(
            &v28_patch_upgrade_config
                .governance_calls
                .governance_stage0_calls,
        );
        let stage1_upgrade_calls = CallList::parse(
            &v28_patch_upgrade_config
                .governance_calls
                .governance_stage1_calls,
        );
        let stage2_upgrade_calls = CallList::parse(
            &v28_patch_upgrade_config
                .governance_calls
                .governance_stage2_calls,
        );
        let new_l1_verifier = v28_patch_upgrade_config
            .deployed_addresses
            .state_transition
            .verifier_addr;
        let new_gw_verifier = v28_patch_upgrade_config
            .gateway
            .gateway_state_transition
            .verifier_addr;

        self.verify_stage0_calls(
            stage0_upgrade_calls,
            verifiers,
            result,
            gateway_chain_id,
            priority_txs_l2_gas_limit,
        )?;
        self.verify_stage1_calls(
            verifiers,
            result,
            v28_patch_upgrade_config,
            stage1_upgrade_calls,
            new_l1_verifier,
            new_gw_verifier,
        )?;
        self.verify_stage2_calls(
            stage2_upgrade_calls,
            verifiers,
            result,
            gateway_chain_id,
            priority_txs_l2_gas_limit,
        )?;

        Ok(())
    }
}
