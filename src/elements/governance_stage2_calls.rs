use crate::{
    elements::initialize_data_new_chain::InitializeDataNewChain, get_expected_old_protocol_version, utils::{compute_selector, facet_cut_set::{self, FacetCutSet, FacetInfo}}, verifiers::Verifiers
};
use alloy::{
    hex, primitives::U256, sol,
    sol_types::{SolCall, SolValue},
};
use super::{
    call_list::{Call, CallList},
    fixed_force_deployment::FixedForceDeploymentsData,
    protocol_version::ProtocolVersion,
};

pub struct GovernanceStage2Calls {
    pub calls: CallList,
}

sol! {
    function upgrade(address proxy, address implementation) {
    }

    function upgradeAndCall(address proxy, address implementation, bytes data) {
    }

    function setAddresses(address _assetRouter, address _l1CtmDeployer, address _messageRoot) {}

    function setL1NativeTokenVault(address _l1NativeTokenVault);
    function setL1AssetRouter(address _l1AssetRouter);

    function setValidatorTimelock(address addr) {
    }

    function singleAddressArgument(address addr) {
    }

    function setProtocolVersionDeadline(uint256 protocolVersion, uint256 newDeadline) {
    }

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

    function setChainCreationParams(ChainCreationParams calldata _chainCreationParams)  {
    }

    /// @notice Façet structure compatible with the EIP-2535 diamond loupe
    /// @param addr The address of the facet contract
    /// @param selectors The NON-sorted array with selectors associated with facet
    struct Facet {
        address addr;
        bytes4[] selectors;
    }

    function facets() external view returns (Facet[] memory result);
}

impl GovernanceStage2Calls {
    /// Verifies an upgrade call by decoding its data and comparing the proxy and implementation addresses.
    pub fn verify_upgrade_call(
        &self,
        verifiers: &Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        call: &Call,
        proxy_address: &str,
        implementation_address: &str,
        call_payload: Option<&str>,
    ) -> anyhow::Result<()> {
        let data = &call.data;
        let (proxy, implementation) = if let Some(expected_payload) = call_payload {
            let decoded = upgradeAndCallCall::abi_decode(data, true)
                .expect("Failed to decode upgradeAndCall call");
            let expected_data = hex::decode(expected_payload)
                .expect("Failed to decode expected call payload from hex");
            if decoded.data != expected_data {
                result.report_error(&format!(
                    "Expected upgrade call data to be {:x?}, but got {:x?}",
                    expected_data, decoded.data
                ));
            }
            (decoded.proxy, decoded.implementation)
        } else {
            let decoded = upgradeCall::abi_decode(data, true)
                .expect("Failed to decode upgrade call");
            (decoded.proxy, decoded.implementation)
        };

        if result.expect_address(verifiers, &proxy, proxy_address)
            && result.expect_address(verifiers, &implementation, implementation_address)
        {
            result.report_ok(&format!(
                "Upgrade call for {} ({}) to {} ({})",
                proxy, proxy_address, implementation, implementation_address
            ));
        }
        Ok(())
    }

    /// Verifies all the governance stage 2 calls.
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        expected_chain_creation_facets: FacetCutSet,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 2 calls ===");

        let list_of_calls = [
            ("transparent_proxy_admin", "upgrade(address,address)"),
            ("transparent_proxy_admin", "upgradeAndCall(address,address,bytes)"),
            ("transparent_proxy_admin", "upgrade(address,address)"),
            ("transparent_proxy_admin", "upgrade(address,address)"),
            (
                "state_transition_manager",
                "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
            ),
            ("bridgehub_proxy", "setAddresses(address,address,address)"),
            ("old_shared_bridge_proxy", "setL1NativeTokenVault(address)"),
            ("old_shared_bridge_proxy", "setL1AssetRouter(address)"),
            ("state_transition_manager", "setProtocolVersionDeadline(uint256,uint256)"),
            ("upgrade_timer", "checkDeadline()"),
            (
                "protocol_upgrade_handler_transparent_proxy_admin",
                "upgradeAndCall(address,address,bytes)",
            ),
        ];

        self.calls.verify(&list_of_calls, verifiers, result)?;

        // Verify each upgrade call.
        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[0],
            "state_transition_manager",
            "state_transition_implementation_addr",
            None,
        )?;

        // Compute the selector once so that its lifetime is extended.
        let init_v2_selector = compute_selector("initializeV2()");
        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[1],
            "bridgehub_proxy",
            "bridgehub_implementation_addr",
            Some(init_v2_selector.as_str()),
        )?;

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[2],
            "old_shared_bridge_proxy",
            "l1_nullifier_implementation_addr",
            None,
        )?;

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[3],
            "legacy_erc20_bridge_proxy",
            "erc20_bridge_implementation_addr",
            None,
        )?;

        // Verify setChainCreationParams call.
        {
            let decoded = setChainCreationParamsCall::abi_decode(&self.calls.elems[4].data, true)
                .expect("Failed to decode setChainCreationParams call");
            decoded
                ._chainCreationParams
                .verify(verifiers, result, expected_chain_creation_facets)
                .await?;
        }

        // Verify setAddresses call.
        {
            let decoded = setAddressesCall::abi_decode(&self.calls.elems[5].data, true)
                .expect("Failed to decode setAddresses call");
            result.expect_address(verifiers, &decoded._assetRouter, "l1_asset_router_proxy");
            result.expect_address(verifiers, &decoded._l1CtmDeployer, "ctm_deployment_tracker");
            result.expect_address(verifiers, &decoded._messageRoot, "l1_message_root");
        }

        // Verify setL1NativeTokenVault call.
        {
            let decoded = setL1NativeTokenVaultCall::abi_decode(&self.calls.elems[6].data, true)
                .expect("Failed to decode setL1NativeTokenVault call");
            result.expect_address(verifiers, &decoded._l1NativeTokenVault, "native_token_vault");
        }

        // Verify setL1AssetRouter call.
        {
            let decoded = setL1AssetRouterCall::abi_decode(&self.calls.elems[7].data, true)
                .expect("Failed to decode setL1AssetRouter call");
            result.expect_address(verifiers, &decoded._l1AssetRouter, "l1_asset_router_proxy");
        }

        // Verify setProtocolVersionDeadline call.
        {
            let decoded = setProtocolVersionDeadlineCall::abi_decode(&self.calls.elems[8].data, true)
                .expect("Failed to decode setProtocolVersionDeadline call");
            let pv = ProtocolVersion::from(decoded.protocolVersion);
            let expected_old = get_expected_old_protocol_version();

            if pv != expected_old {
                result.report_warn(&format!(
                    "Invalid protocol version: {} - expected {}",
                    pv, expected_old
                ));
            }

            if decoded.newDeadline != U256::ZERO {
                result.report_error(&format!(
                    "Expected deadline to be 0, but got {}",
                    decoded.newDeadline
                ));
            }
        }

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[10],
            "protocol_upgrade_handler_proxy",
            "new_protocol_upgrade_handler_impl",
            Some(""),
        )?;

        Ok(())
    }
}

impl ChainCreationParams {
    /// Verifies the chain creation parameters.
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        expected_chain_creation_facets: FacetCutSet,
    ) -> anyhow::Result<()> {
        result.print_info("== Chain creation params ==");
        let genesis_upgrade_name = verifiers
            .address_verifier
            .name_or_unknown(&self.genesisUpgrade);
        if genesis_upgrade_name != "genesis_upgrade_addr" {
            result.report_error(&format!(
                "Expected genesis upgrade address to be genesis_upgrade_addr, but got {}",
                genesis_upgrade_name
            ));
        }

        if self.genesisBatchHash.to_string() != verifiers.genesis_config.genesis_root {
            result.report_error(&format!(
                "Expected genesis batch hash to be {}, but got {}",
                verifiers.genesis_config.genesis_root, self.genesisBatchHash
            ));
        }

        if self.genesisIndexRepeatedStorageChanges != verifiers.genesis_config.genesis_rollup_leaf_index {
            result.report_error(&format!(
                "Expected genesis index repeated storage changes to be {}, but got {}",
                verifiers.genesis_config.genesis_rollup_leaf_index, self.genesisIndexRepeatedStorageChanges
            ));
        }

        if self.genesisBatchCommitment.to_string() != verifiers.genesis_config.genesis_batch_commitment {
            result.report_error(&format!(
                "Expected genesis batch commitment to be {}, but got {}",
                verifiers.genesis_config.genesis_batch_commitment, self.genesisBatchCommitment
            ));
        }

        verify_chain_creation_diamond_cut(
            verifiers,
            result,
            &self.diamondCut,
            expected_chain_creation_facets,
        )
        .await?;

        let fixed_force_deployments_data =
            FixedForceDeploymentsData::abi_decode(&self.forceDeploymentsData, true)
                .expect("Failed to decode FixedForceDeploymentsData");
        fixed_force_deployments_data.verify(verifiers, result).await?;

        Ok(())
    }
}

/// Verifies the diamond cut used during chain creation.
pub async fn verify_chain_creation_diamond_cut(
    verifiers: &crate::verifiers::Verifiers,
    result: &mut crate::verifiers::VerificationResult,
    diamond_cut: &DiamondCutData,
    expected_chain_creation_facets: FacetCutSet,
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
            selectors: facet.selectors.iter().map(|x| x.0).collect() 
        });
    }

    if expected_chain_creation_facets != proposed_facet_cut {
        result.report_error(&format!(
            "Invalid chain creation facet cut. Expected: {:#?}\nReceived: {:#?}",
            expected_chain_creation_facets, proposed_facet_cut
        ));
    }

    result.expect_address(verifiers, &diamond_cut.initAddress, "diamond_init");
    let initialize_data_new_chain = InitializeDataNewChain::abi_decode(&diamond_cut.initCalldata, true)
        .expect("Failed to decode InitializeDataNewChain");
    initialize_data_new_chain.verify(verifiers, result).await?;

    Ok(())
}
