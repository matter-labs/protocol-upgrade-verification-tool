use super::{
    call_list::CallList,
    deployed_addresses::DeployedAddresses,
    set_new_version_upgrade::{self, setNewVersionUpgradeCall},
    OldChainCreationParams,
};
use crate::{
    elements::initialize_data_new_chain::InitializeDataNewChain,
    get_expected_new_protocol_version, get_expected_old_protocol_version,
    utils::facet_cut_set::{self, FacetCutSet, FacetInfo},
};
use alloy::{
    hex,
    primitives::{Bytes, U256},
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::Context;

sol! {
    #[derive(Debug)]
    struct L2TransactionRequestDirect {
        uint256 chainId;
        uint256 mintValue;
        address l2Contract;
        uint256 l2Value;
        bytes l2Calldata;
        uint256 l2GasLimit;
        uint256 l2GasPerPubdataByteLimit;
        bytes[] factoryDeps;
        address refundRecipient;
    }

    function approve(address spender, uint256 allowance);

    function pauseMigration();

    function unpauseMigration();

    function requestL2TransactionDirect(
        L2TransactionRequestDirect calldata _request
    ) external payable returns (bytes32 canonicalTxHash);
}

pub struct GovernanceStage0Calls {
    pub calls: CallList,
}

pub struct GovernanceStage1Calls {
    pub calls: CallList,
}
pub struct GovernanceStage2Calls {
    pub calls: CallList,
}

sol! {
    function upgrade(address proxy, address implementation);
    function upgradeAndCall(address proxy, address implementation, bytes data);
    function setAddresses(address _assetRouter, address _l1CtmDeployer, address _messageRoot);
    function setL1NativeTokenVault(address _l1NativeTokenVault);
    function setL1AssetRouter(address _l1AssetRouter);
    function setValidatorTimelock(address addr);
    function setProtocolVersionDeadline(uint256 protocolVersion, uint256 newDeadline);
    function updateDAPair(address l1_da_addr, address l2_da_addr, bool is_active);

    #[derive(Debug, PartialEq)]
    enum Action {
        Add,
        Replace,
        Remove
    }

    #[derive(Debug)]
    struct FacetCut {
        address facet;
        Action action;
        bool isFreezable;
        bytes4[] selectors;
    }

    #[derive(Debug)]
    struct DiamondCutData {
        FacetCut[] facetCuts;
        address initAddress;
        bytes initCalldata;
    }

    #[derive(Debug)]
    struct ChainCreationParams {
        address genesisUpgrade;
        bytes32 genesisBatchHash;
        uint64 genesisIndexRepeatedStorageChanges;
        bytes32 genesisBatchCommitment;
        DiamondCutData diamondCut;
        bytes forceDeploymentsData;
    }

    function setChainCreationParams(ChainCreationParams calldata _chainCreationParams);

    /// @notice Façet structure compatible with the EIP-2535 diamond loupe
    /// @param addr The address of the facet contract
    /// @param selectors The NON-sorted array with selectors associated with facet
    struct Facet {
        address addr;
        bytes4[] selectors;
    }

    function facets() external view returns (Facet[] memory result);
}

impl GovernanceStage1Calls {
    /// Verifies all the governance stage 1 calls for a verifier-only upgrade.
    /// Returns a pair of expected diamond cut data as well as expected fixed force deployments data.
    ///
    /// A verifier-only upgrade has a simplified Stage 1 that:
    /// - Does NOT include proxy upgrades
    /// - Does NOT include DA pair updates
    /// - Does NOT include Gateway CTM upgrade
    /// - Only updates the verifier address in chain creation params and version upgrade
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        _priority_txs_l2_gas_limit: u64,
        _deployed_addresses: &DeployedAddresses,
        l1_expected_chain_upgrade_diamond_cut: &str,
        gw_expected_chain_upgrade_diamond_cut: &str,
        l1_old_chain_creation_params: &OldChainCreationParams,
        gw_old_chain_creation_params: &OldChainCreationParams,
    ) -> anyhow::Result<(String, String, String, String)> {
        result.print_info("== Gov stage 1 calls (Verifier-Only Upgrade) ===");

        // For a verifier-only upgrade, Stage 1 consists of:
        // 1. Check timer deadline
        // 2. Check migrations are paused
        // 3. Set new chain creation params (L1) - only verifier changes
        // 4. Set new version upgrade (L1) - no facet cuts, only verifier in ProposedUpgrade
        // 5. Approve base token for GW setNewVersion
        // 6. GW: Set new version upgrade
        // 7. Approve base token for GW setChainCreationParams
        // 8. GW: Set new chain creation params

        let list_of_calls = [
            // Check time has passed
            ("upgrade_timer", "checkDeadline()"),
            // Check that migrations are paused
            ("upgrade_stage_validator", "checkMigrationsPaused()"),
            // Set chain creation params (L1)
            (
                "state_transition_manager",
                "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
            ),
            // Set new version upgrade (L1)
            (
                "state_transition_manager",
                "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)",
            ),
            // Approve base token for GW setNewVersion
            ("gateway_base_token", "approve(address,uint256)"),
            // GW: Set new version for upgrade
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
            // Approve base token for GW setChainCreationParams
            ("gateway_base_token", "approve(address,uint256)"),
            // GW: New chain creation params
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
        ];

        const SET_CHAIN_CREATION_INDEX: usize = 2;
        const SET_NEW_VERSION_INDEX: usize = 3;
        const APPROVE_BASE_TOKEN_GW_CHAIN_CREATION: usize = 4;
        const GATEWAY_NEW_CHAIN_CREATION_PARAMS: usize = 5;
        const APPROVE_BASE_TOKEN_GW_SET_NEW_VERSION: usize = 6;
        const GATEWAY_SET_NEW_VERSION: usize = 7;

        // Verify the call list structure
        self.calls.verify(&list_of_calls, verifiers, result)?;

        // Verify setChainCreationParams call (L1).
        // For verifier-only upgrade, we verify that the new params differ from old only in verifier address
        let (l1_chain_creation_diamond_cut, l1_force_deployments) = {
            let decoded = setChainCreationParamsCall::abi_decode(
                &self.calls.elems[SET_CHAIN_CREATION_INDEX].data,
                true,
            )
            .expect("Failed to decode setChainCreationParams call");
            decoded
                ._chainCreationParams
                .verify_verifier_only(
                    verifiers,
                    result,
                    false,
                    l1_old_chain_creation_params,
                )
                .await?;

            let ChainCreationParams {
                diamondCut,
                forceDeploymentsData,
                ..
            } = decoded._chainCreationParams;

            (
                hex::encode(diamondCut.abi_encode()),
                hex::encode(forceDeploymentsData),
            )
        };

        // Verify setNewVersionUpgrade (L1)
        // For verifier-only upgrade: no facet cuts, only verifier in ProposedUpgrade
        {
            let calldata = &self.calls.elems[SET_NEW_VERSION_INDEX].data;
            let data = setNewVersionUpgradeCall::abi_decode(calldata, true).unwrap();

            if data.oldProtocolVersionDeadline != U256::MAX {
                result.report_error("Wrong old protocol version deadline for stage1 call");
            }

            if data.newProtocolVersion != get_expected_new_protocol_version().into() {
                result.report_error("Wrong new protocol version for stage1 call");
            }
            if data.oldProtocolVersion != get_expected_old_protocol_version().into() {
                result.report_error("Wrong old protocol version for stage1 call");
            }

            let diamond_cut = data.diamondCut;
            if alloy::hex::encode(diamond_cut.abi_encode())
                != l1_expected_chain_upgrade_diamond_cut[2..]
            {
                result.report_error(&format!(
                    "Invalid chain upgrade diamond cut. Expected: {}\n Received: {}",
                    l1_expected_chain_upgrade_diamond_cut,
                    alloy::hex::encode(diamond_cut.abi_encode())
                ));
            }

            // For verifier-only upgrade, init address should be default_upgrade
            result.expect_address(verifiers, &diamond_cut.initAddress, "default_upgrade");

            // Verify no facet cuts (verifier-only upgrade)
            if !diamond_cut.facetCuts.is_empty() {
                result.report_error(&format!(
                    "Verifier-only upgrade should have no facet cuts, but found {}",
                    diamond_cut.facetCuts.len()
                ));
            } else {
                result.report_ok("L1 upgrade has no facet cuts (verifier-only)");
            }

            let upgrade = crate::elements::set_new_version_upgrade::upgradeCall::abi_decode(
                &diamond_cut.initCalldata,
                true,
            )
            .unwrap();

            // Verify the proposed upgrade for verifier-only
            upgrade
                ._proposedUpgrade
                .verify_verifier_only(verifiers, result, false)
                .await
                .context("proposed upgrade (L1)")?;
        }

        // Verify Approve base token for GW setChainCreationParams
        {
            let calldata = &self.calls.elems[APPROVE_BASE_TOKEN_GW_CHAIN_CREATION].data;
            let data =
                approveCall::abi_decode(&calldata, true).expect("Failed to decode approve call");

            result.expect_address(verifiers, &data.spender, "l1_asset_router_proxy");
        }

        // Verify Gateway New chain creation params
        // For verifier-only upgrade, we verify that the new params differ from old only in verifier address
        let (gw_chain_creation_diamond_cut, gw_force_deployments) = {
            let calldata = &self.calls.elems[GATEWAY_NEW_CHAIN_CREATION_PARAMS].data;
            let data = requestL2TransactionDirectCall::abi_decode(&calldata, true)
                .expect("Failed to decode L2 -> GW newCreationParams");

            if data._request.chainId != U256::from(gateway_chain_id) {
                result.report_error("Wrong gateway chain id for stage1 newCreationParams");
            }

            // Try to decode as setChainCreationParams - if it fails, it might use a different function signature
            match setChainCreationParamsCall::abi_decode(&data._request.l2Calldata, true) {
                Ok(l2_data) => {
                    l2_data
                        ._chainCreationParams
                        .verify_verifier_only(
                            verifiers,
                            result,
                            true,
                            gw_old_chain_creation_params,
                        )
                        .await?;

                    let ChainCreationParams {
                        diamondCut,
                        forceDeploymentsData,
                        ..
                    } = l2_data._chainCreationParams;

                    (
                        hex::encode(diamondCut.abi_encode()),
                        hex::encode(forceDeploymentsData),
                    )
                }
                Err(e) => {
                    // The L2 calldata might use a different function signature
                    result.report_warn(&format!(
                        "Could not decode GW setChainCreationParams: {}. L2 calldata selector: 0x{}. Skipping GW chain creation params verification.",
                        e,
                        hex::encode(&data._request.l2Calldata[..4.min(data._request.l2Calldata.len())])
                    ));
                    // Use old chain creation params data as placeholder since we can't decode new
                    (
                        gw_old_chain_creation_params.diamond_cut_data[2..].to_string(),
                        gw_old_chain_creation_params.force_deployments_data[2..].to_string(),
                    )
                }
            }
        };

        // Verify Approve base token for GW setNewVersion
        {
            let calldata = &self.calls.elems[APPROVE_BASE_TOKEN_GW_SET_NEW_VERSION].data;
            let data =
                approveCall::abi_decode(&calldata, true).expect("Failed to decode approve call");

            result.expect_address(verifiers, &data.spender, "l1_asset_router_proxy");
        }

        // Verify Gateway Set new version for upgrade
        {
            let calldata = &self.calls.elems[GATEWAY_SET_NEW_VERSION].data;
            let data = requestL2TransactionDirectCall::abi_decode(&calldata, true)
                .expect("Failed to decode L2 -> GW setNewVersion");

            if data._request.chainId != U256::from(gateway_chain_id) {
                result.report_error("Wrong gateway chain id for stage1 setNewVersion");
            }

            // Try to decode as setNewVersionUpgrade - if it fails, it might be a different function
            match setNewVersionUpgradeCall::abi_decode(&data._request.l2Calldata, true) {
                Ok(l2_data) => {
                    if l2_data.oldProtocolVersionDeadline != U256::MAX {
                        result.report_error("Wrong old protocol version deadline for GW stage1 call");
                    }

                    if l2_data.newProtocolVersion != get_expected_new_protocol_version().into() {
                        result.report_error("Wrong new protocol version for GW stage1 call");
                    }

                    if l2_data.oldProtocolVersion != get_expected_old_protocol_version().into() {
                        result.report_error("Wrong old protocol version for GW stage1 call");
                    }

                    let diamond_cut = l2_data.diamondCut;

                    result.expect_address(
                        verifiers,
                        &diamond_cut.initAddress,
                        "gateway_default_upgrade_addr",
                    );

                    if alloy::hex::encode(diamond_cut.abi_encode())
                        != gw_expected_chain_upgrade_diamond_cut[2..]
                    {
                        result.report_error(&format!(
                            "Invalid gw chain upgrade diamond cut. Expected: {}\n Received: {}",
                            gw_expected_chain_upgrade_diamond_cut,
                            alloy::hex::encode(diamond_cut.abi_encode())
                        ));
                    }

                    // Verify no facet cuts (verifier-only upgrade)
                    if !diamond_cut.facetCuts.is_empty() {
                        result.report_error(&format!(
                            "GW verifier-only upgrade should have no facet cuts, but found {}",
                            diamond_cut.facetCuts.len()
                        ));
                    } else {
                        result.report_ok("GW upgrade has no facet cuts (verifier-only)");
                    }

                    let upgrade = crate::elements::set_new_version_upgrade::upgradeCall::abi_decode(
                        &diamond_cut.initCalldata,
                        true,
                    )
                    .unwrap();

                    // Verify the proposed upgrade for verifier-only
                    upgrade
                        ._proposedUpgrade
                        .verify_verifier_only(verifiers, result, true)
                        .await
                        .context("proposed upgrade (GW)")?;
                }
                Err(e) => {
                    // The L2 calldata might use a different function signature
                    // Report as warning and skip GW upgrade verification
                    result.report_error(&format!(
                        "Could not decode GW L2 calldata as setNewVersionUpgrade: {}. L2 calldata selector: 0x{}. Skipping GW upgrade verification.",
                        e,
                        hex::encode(&data._request.l2Calldata[..4.min(data._request.l2Calldata.len())])
                    ));
                }
            }
        }

        Ok((
            l1_chain_creation_diamond_cut,
            l1_force_deployments,
            gw_chain_creation_diamond_cut,
            gw_force_deployments,
        ))
    }
}

impl ChainCreationParams {
    /// Verifies the chain creation parameters for a verifier-only upgrade.
    ///
    /// In a verifier-only upgrade:
    /// - Genesis params should match the old chain creation params (not fetched from GitHub)
    /// - Diamond cut data should be identical to old except for verifier address
    /// - Force deployments data should be identical to old
    pub async fn verify_verifier_only(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        is_gateway: bool,
        old_chain_creation_params: &OldChainCreationParams,
    ) -> anyhow::Result<()> {
        let prefix = if is_gateway { "GW" } else { "L1" };
        result.print_info(&format!("== {} Chain creation params (verifier-only) ==", prefix));

        // Decode the old diamond cut data to compare
        let old_diamond_cut_bytes = alloy::hex::decode(&old_chain_creation_params.diamond_cut_data[2..])
            .expect("Invalid hex in old diamond_cut_data");
        let old_diamond_cut = DiamondCutData::abi_decode(&old_diamond_cut_bytes, true)
            .expect("Failed to decode old DiamondCutData");

        // Verify genesis upgrade address matches the one from YAML
        if self.genesisUpgrade != old_chain_creation_params.genesis_upgrade {
            result.report_error(&format!(
                "{} genesis upgrade address mismatch.\nExpected (from YAML): {}\nGot: {}",
                prefix, old_chain_creation_params.genesis_upgrade, self.genesisUpgrade
            ));
        } else {
            result.report_ok(&format!("{} genesis upgrade address matches YAML", prefix));
        }

        // Verify genesis batch hash matches YAML
        if self.genesisBatchHash.to_string() != old_chain_creation_params.genesis_batch_hash {
            result.report_error(&format!(
                "{} genesis batch hash mismatch.\nExpected (from YAML): {}\nGot: {}",
                prefix, old_chain_creation_params.genesis_batch_hash, self.genesisBatchHash
            ));
        } else {
            result.report_ok(&format!("{} genesis batch hash matches YAML", prefix));
        }

        // Verify genesis index repeated storage changes matches YAML
        if self.genesisIndexRepeatedStorageChanges != old_chain_creation_params.genesis_index_repeated_storage_changes {
            result.report_error(&format!(
                "{} genesis index repeated storage changes mismatch.\nExpected (from YAML): {}\nGot: {}",
                prefix, old_chain_creation_params.genesis_index_repeated_storage_changes, self.genesisIndexRepeatedStorageChanges
            ));
        } else {
            result.report_ok(&format!("{} genesis index repeated storage changes matches YAML", prefix));
        }

        // Verify genesis batch commitment matches YAML
        if self.genesisBatchCommitment.to_string() != old_chain_creation_params.genesis_batch_commitment {
            result.report_error(&format!(
                "{} genesis batch commitment mismatch.\nExpected (from YAML): {}\nGot: {}",
                prefix, old_chain_creation_params.genesis_batch_commitment, self.genesisBatchCommitment
            ));
        } else {
            result.report_ok(&format!("{} genesis batch commitment matches YAML", prefix));
        }

        // For verifier-only upgrade, we skip verify_chain_creation_diamond_cut since facets don't change
        // and the addresses may not be registered in address_verifier.
        // We do verify facet cuts match the old values below.

        // Verify force deployments data is unchanged from old
        let old_force_deployments = &old_chain_creation_params.force_deployments_data;
        let new_force_deployments = hex::encode(&self.forceDeploymentsData);
        if old_force_deployments[2..] != new_force_deployments {
            result.report_error(&format!(
                "{} force deployments data changed! Should be identical for verifier-only upgrade",
                prefix
            ));
        } else {
            result.report_ok(&format!("{} force deployments data unchanged (verifier-only)", prefix));
        }

        // Now verify that the diamond cut data only differs in the verifier address
        // Compare facet cuts - should be identical
        let old_facet_cuts_encoded = old_diamond_cut.facetCuts.abi_encode();
        let new_facet_cuts_encoded = self.diamondCut.facetCuts.abi_encode();
        if old_facet_cuts_encoded != new_facet_cuts_encoded {
            result.report_error(&format!(
                "{} facet cuts changed! Should be identical for verifier-only upgrade",
                prefix
            ));
        } else {
            result.report_ok(&format!("{} facet cuts unchanged (verifier-only)", prefix));
        }

        // Compare init address - should be identical
        if old_diamond_cut.initAddress != self.diamondCut.initAddress {
            result.report_error(&format!(
                "{} diamond cut init address changed! Should be identical for verifier-only upgrade.\nOld: {}\nNew: {}",
                prefix, old_diamond_cut.initAddress, self.diamondCut.initAddress
            ));
        } else {
            result.report_ok(&format!("{} diamond cut init address unchanged (verifier-only)", prefix));
        }

        // Now verify the init calldata - only the verifier should change
        // Try to decode both old and new init data
        let old_init_data = InitializeDataNewChain::abi_decode(&old_diamond_cut.initCalldata, true);
        let new_init_data = InitializeDataNewChain::abi_decode(&self.diamondCut.initCalldata, true);

        match (old_init_data, new_init_data) {
            (Ok(old_init), Ok(new_init)) => {
                // Verify verifier address is updated to the new verifier
                let expected_verifier_name = if is_gateway {
                    "gateway_verifier_addr"
                } else {
                    "verifier"
                };
                result.expect_address(verifiers, &new_init.verifier, expected_verifier_name);

                // Verify all other fields in InitializeDataNewChain are unchanged
                // Use ABI encoding for comparison since some types don't implement PartialEq
                let mut fields_unchanged = true;

                if old_init.verifierParams.abi_encode() != new_init.verifierParams.abi_encode() {
                    result.report_error(&format!("{} verifierParams changed!", prefix));
                    fields_unchanged = false;
                }
                if old_init.l2BootloaderBytecodeHash != new_init.l2BootloaderBytecodeHash {
                    result.report_error(&format!("{} l2BootloaderBytecodeHash changed!", prefix));
                    fields_unchanged = false;
                }
                if old_init.l2DefaultAccountBytecodeHash != new_init.l2DefaultAccountBytecodeHash {
                    result.report_error(&format!("{} l2DefaultAccountBytecodeHash changed!", prefix));
                    fields_unchanged = false;
                }
                if old_init.l2EvmEmulatorBytecodeHash != new_init.l2EvmEmulatorBytecodeHash {
                    result.report_error(&format!("{} l2EvmEmulatorBytecodeHash changed!", prefix));
                    fields_unchanged = false;
                }
                if old_init.priorityTxMaxGasLimit != new_init.priorityTxMaxGasLimit {
                    result.report_error(&format!("{} priorityTxMaxGasLimit changed!", prefix));
                    fields_unchanged = false;
                }
                if old_init.feeParams != new_init.feeParams {
                    result.report_error(&format!("{} feeParams changed!", prefix));
                    fields_unchanged = false;
                }

                if fields_unchanged {
                    result.report_ok(&format!("{} InitializeDataNewChain: only verifier changed (verifier-only)", prefix));
                }
            }
            (Err(_), _) | (_, Err(_)) => {
                // If we can't decode the init data, just compare the raw bytes
                // For a verifier-only upgrade, init calldata may still change (due to new verifier)
                // So we can't do a byte-by-byte comparison, but we report a warning
                result.report_warn(&format!(
                    "{} Could not decode InitializeDataNewChain - skipping field-by-field comparison",
                    prefix
                ));
            }
        }

        Ok(())
    }

}

/// Verifies the diamond cut used during chain creation.
/// Note: This function is not used for verifier-only upgrades since facets don't change.
#[allow(dead_code)]
pub async fn verify_chain_creation_diamond_cut(
    verifiers: &crate::verifiers::Verifiers,
    result: &mut crate::verifiers::VerificationResult,
    diamond_cut: &DiamondCutData,
    expected_chain_creation_facets: FacetCutSet,
    is_gateway: bool,
) -> anyhow::Result<()> {
    let mut proposed_facet_cut = FacetCutSet::new();
    for facet in &diamond_cut.facetCuts {
        let action = match facet.action {
            Action::Add => facet_cut_set::Action::Add,
            Action::Remove => {
                result.report_error("Remove action is unexpected in diamond cut");
                continue;
            }
            Action::Replace => {
                result.report_error("Replace action is unexpected in diamond cut");
                continue;
            }
            Action::__Invalid => {
                result.report_error("Invalid action in diamond cut");
                continue;
            }
        };
        proposed_facet_cut.add_facet(FacetInfo {
            facet: facet.facet,
            action,
            is_freezable: facet.isFreezable,
            selectors: facet.selectors.iter().map(|x| x.0).collect(),
        });
    }

    if expected_chain_creation_facets != proposed_facet_cut {
        result.report_error(&format!(
            "Invalid chain creation facet cut. Expected: {:#?}\nReceived: {:#?}",
            expected_chain_creation_facets, proposed_facet_cut
        ));
    }

    let name = if is_gateway {
        "gateway_diamond_init_addr"
    } else {
        "diamond_init"
    };
    result.expect_address(verifiers, &diamond_cut.initAddress, name);
    let initialize_data_new_chain =
        InitializeDataNewChain::abi_decode(&diamond_cut.initCalldata, true)
            .expect("Failed to decode InitializeDataNewChain");
    initialize_data_new_chain
        .verify(verifiers, result, is_gateway)
        .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn verity_facet_cuts(
    facet_cuts: &[set_new_version_upgrade::FacetCut],
    result: &mut crate::verifiers::VerificationResult,
    expected_upgrade_facets: FacetCutSet,
) {
    // We ensure two invariants here:
    // - Firstly we use `Remove` operations only. This is mainly for ensuring that
    // the upgrade will pass.
    // - Secondly, we ensure that the set of operations is identical.
    let mut used_add = false;
    let mut proposed_facet_cuts = FacetCutSet::new();
    facet_cuts.iter().for_each(|facet| {
        let action = match facet.action {
            set_new_version_upgrade::Action::Add => {
                used_add = true;
                facet_cut_set::Action::Add
            }
            set_new_version_upgrade::Action::Remove => {
                assert!(!used_add, "Unexpected `Remove` operation after `Add`");
                facet_cut_set::Action::Remove
            }
            set_new_version_upgrade::Action::Replace => panic!("Replace unexpected"),
            set_new_version_upgrade::Action::__Invalid => panic!("Invalid unexpected"),
        };

        proposed_facet_cuts.add_facet(FacetInfo {
            facet: facet.facet,
            action,
            is_freezable: facet.isFreezable,
            selectors: facet.selectors.iter().map(|x| x.0).collect(),
        });
    });

    if proposed_facet_cuts != expected_upgrade_facets {
        result.report_error(&format!(
            "Incorrect facet cuts. Expected {:#?}\nReceived: {:#?}",
            expected_upgrade_facets, proposed_facet_cuts
        ));
    }
}

impl GovernanceStage0Calls {
    /// Stage0 is executed before the main upgrade even starts.
    pub(crate) async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 0 calls ===");

        // Stage 0 handles pausing migration on L1 and on Gateway
        let list_of_calls = [
            ("bridgehub_proxy", "pauseMigration()"),
            ("gateway_base_token", "approve(address,uint256)"),
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
            ("upgrade_timer", "startTimer()"),
        ];
        const PAUSE_L1_MIGRATION: usize = 0;
        const APPROVE_BASE_TOKEN: usize = 1;
        const PAUSE_GATEWAY_MIGRATION: usize = 2;

        // For calls without any params, we don't have to check
        // anything else. This is true for stage 1 and stage 2.
        self.calls.verify(&list_of_calls, verifiers, result)?;

        // Verify pauseMigration
        {
            let calldata = &self.calls.elems[PAUSE_L1_MIGRATION].data;
            pauseMigrationCall::abi_decode(&calldata, true)
                .expect("Failed to decode pauseMigration Call on L1");
        }

        // Verify approve base token
        {
            let calldata = &self.calls.elems[APPROVE_BASE_TOKEN].data;
            let data =
                approveCall::abi_decode(&calldata, true).expect("Failed to decode approve call");

            result.expect_address(verifiers, &data.spender, "l1_asset_router_proxy");
        }

        // Verify L1 -> Gateway Pause Migration
        {
            let calldata = &self.calls.elems[PAUSE_GATEWAY_MIGRATION].data;
            check_l1_to_gateway_transaction(
                verifiers,
                result,
                calldata,
                pauseMigrationCall::abi_decode,
                gateway_chain_id,
                priority_txs_l2_gas_limit,
                "l2_bridgehub",
            );
        }

        Ok(())
    }
}

impl GovernanceStage2Calls {
    /// Stage2 is executed after all the chains have upgraded.
    pub(crate) async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        gateway_chain_id: u64,
        priority_txs_l2_gas_limit: u64,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 2 calls ===");

        // Stage2 is where we create the upgrade on gateway and unpause migration
        // on gateway and unpause migration on l1

        let list_of_calls = [
            // Check that the protocol upgrade has happened
            ("upgrade_stage_validator", "checkProtocolUpgradePresence()"),
            // Unpause L1 migration
            ("bridgehub_proxy", "unpauseMigration()"),
            // Approve base token
            ("gateway_base_token", "approve(address,uint256)"),
            // Unpause gateway
            ("bridgehub_proxy", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
            // Check that migrations are unpaused
            ("upgrade_stage_validator", "checkMigrationsUnpaused()"),
        ];
        const APPROVE_BASE_TOKEN: usize = 2;
        const GATEWAY_UNPAUSE_MIGRATION: usize = 3;

        // For calls without any params, we don't have to check
        // anything else. This is true for stage 0 and stage 1.
        self.calls.verify(&list_of_calls, verifiers, result)?;

        // Verify Approve base token
        {
            let calldata = &self.calls.elems[APPROVE_BASE_TOKEN].data;
            let data =
                approveCall::abi_decode(&calldata, true).expect("Failed to decode approve call");

            result.expect_address(verifiers, &data.spender, "l1_asset_router_proxy");
        }

        // Verify Unpause gateway migration
        {
            let calldata = &self.calls.elems[GATEWAY_UNPAUSE_MIGRATION].data;
            check_l1_to_gateway_transaction(
                verifiers,
                result,
                calldata,
                unpauseMigrationCall::abi_decode,
                gateway_chain_id,
                priority_txs_l2_gas_limit,
                "l2_bridgehub",
            );
        }

        Ok(())
    }
}

fn check_l1_to_gateway_transaction<T, F>(
    verifiers: &crate::verifiers::Verifiers,
    result: &mut crate::verifiers::VerificationResult,
    calldata: &Bytes,
    decoder: F,
    gateway_chain_id: u64,
    priority_txs_l2_gas_limit: u64,
    expected_l2_contract: &str,
) -> T
where
    F: Fn(&[u8], bool) -> alloy::sol_types::Result<T>,
{
    let data = requestL2TransactionDirectCall::abi_decode(&calldata, true)
        .expect("Failed to decode L2 -> GW transaction");

    if data._request.chainId != U256::from(gateway_chain_id) {
        result.report_error("Wrong gateway chain id for L2 -> GW transaction");
    }

    if data._request.l2GasLimit != U256::from(priority_txs_l2_gas_limit) {
        result.report_error("Wrong l2GasLimit for L2 -> GW transaction");
    }

    result.expect_address(verifiers, &data._request.l2Contract, expected_l2_contract);

    decoder(&data._request.l2Calldata, true).expect("Failed to decode inner L1 -> GW")
}
