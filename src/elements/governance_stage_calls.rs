use super::{
    call_list::{Call, CallList},
    deployed_addresses::DeployedAddresses,
    fixed_force_deployment::FixedForceDeploymentsData,
    set_new_version_upgrade::{self, setNewVersionUpgradeCall},
};
use crate::{
    elements::initialize_data_new_chain::InitializeDataNewChain,
    utils::facet_cut_set::{self, FacetCutSet, FacetInfo},
    verifiers::Verifiers,
};
use alloy::{
    hex,
    primitives::U256,
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::Context;

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
            let decoded =
                upgradeCall::abi_decode(data, true).expect("Failed to decode upgrade call");
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

    /// Verifies all the governance stage 1 calls.
    /// Returns a pair of expected diamond cut data as well as expected fixed force deployments data.
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        expected_chain_creation_facets: FacetCutSet,
        deployed_addresses: &DeployedAddresses,
        expected_upgrade_facets: FacetCutSet,
        expected_chain_upgrade_diamond_cut: &str,
    ) -> anyhow::Result<(String, String)> {
        result.print_info("== Gov stage 1 calls ===");

        // Stage1 is where most of the upgrade happens.
        // It usually consists of 3 parts:
        // * upgrading proxies (we deploy a new implementation and point existing proxy to it)
        // * upgrading chain creation parameters (telling the system how the new chains should look like)
        // * saving the information on how to upgrade existing chains (set new version upgrade)

        // Optionally for some upgrades we might have additional contract calls
        // (for example when we added a new type of bridge, we also included a call to bridgehub to set its address etc)

        let list_of_calls = [
            // Proxy upgrades
            ("transparent_proxy_admin", "upgrade(address,address)"),
            ("transparent_proxy_admin", "upgrade(address,address)"),
            ("transparent_proxy_admin", "upgrade(address,address)"),
            ("transparent_proxy_admin", "upgrade(address,address)"),
            ("transparent_proxy_admin", "upgrade(address,address)"),
            // index = 5
            (
                "state_transition_manager",
                "setChainCreationParams((address,bytes32,uint64,bytes32,((address,uint8,bool,bytes4[])[],address,bytes),bytes))",
            ),

            ("state_transition_manager",
            "setNewVersionUpgrade(((address,uint8,bool,bytes4[])[],address,bytes),uint256,uint256,uint256)"),
            ("rollup_da_manager", "updateDAPair(address,address,bool)")
        ];
        const SET_NEW_VERSION_INDEX: usize = 6;
        const SET_CHAIN_CREATION_INDEX: usize = 5;

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

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[1],
            "bridgehub_proxy",
            "bridgehub_implementation_addr",
            None,
        )?;

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[2],
            "l1_nullifier_proxy_addr",
            "l1_nullifier_implementation_addr",
            None,
        )?;

        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[3],
            "l1_asset_router_proxy",
            "l1_asset_router_implementation_addr",
            None,
        )?;
        self.verify_upgrade_call(
            verifiers,
            result,
            &self.calls.elems[4],
            "native_token_vault",
            "native_token_vault_implementation_addr",
            None,
        )?;

        // Verify setNewVersionUpgrade
        {
            let calldata = &self.calls.elems[SET_NEW_VERSION_INDEX].data;
            let data = setNewVersionUpgradeCall::abi_decode(calldata, true).unwrap();

            if data.oldProtocolVersionDeadline != U256::MAX {
                result.report_error("Wrong old protocol version deadline for stage1 call");
            }

            let diamond_cut = data.diamondCut;
            if alloy::hex::encode(diamond_cut.abi_encode())
                != expected_chain_upgrade_diamond_cut[2..]
            {
                result.report_error(&format!(
                    "Invalid chain upgrade diamond cut. Expected: {}\n Received: {}",
                    expected_chain_upgrade_diamond_cut,
                    alloy::hex::encode(diamond_cut.abi_encode())
                ));
            }

            // should match state_transiton.default_upgrade
            result.expect_address(verifiers, &diamond_cut.initAddress, "default_upgrade");

            verity_facet_cuts(&diamond_cut.facetCuts, result, expected_upgrade_facets).await;

            let upgrade = crate::elements::set_new_version_upgrade::upgradeCall::abi_decode(
                &diamond_cut.initCalldata,
                true,
            )
            .unwrap();

            upgrade
                ._proposedUpgrade
                .verify(
                    verifiers,
                    result,
                    deployed_addresses.l1_bytecodes_supplier_addr,
                )
                .await
                .context("proposed upgrade")?;
        }

        // Verify setChainCreationParams call.
        let (chain_creation_diamond_cut, force_deployments) = {
            let decoded = setChainCreationParamsCall::abi_decode(
                &self.calls.elems[SET_CHAIN_CREATION_INDEX].data,
                true,
            )
            .expect("Failed to decode setChainCreationParams call");
            decoded
                ._chainCreationParams
                .verify(verifiers, result, expected_chain_creation_facets)
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

        // Verify rollup_da_manager call
        let decoded = updateDAPairCall::abi_decode(&self.calls.elems[7].data, true).expect("Failed to decode updateDAPair call");
        if decoded.l1_da_addr != deployed_addresses.l1_rollup_da_manager {
            result.report_error(&format!(
                "Expected l1_da_addr to be {}, but got {}",
                deployed_addresses.l1_rollup_da_manager, decoded.l1_da_addr
            ));
        }

        if decoded.l2_da_addr != deployed_addresses.l2_rollup_da_manager {
            result.report_error(&format!(
                "Expected l2_da_addr to be {}, but got {}",
                deployed_addresses.l2_rollup_da_manager, decoded.l2_da_addr
            ));
        }

        Ok((chain_creation_diamond_cut, force_deployments))
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

        if self.genesisIndexRepeatedStorageChanges
            != verifiers.genesis_config.genesis_rollup_leaf_index
        {
            result.report_error(&format!(
                "Expected genesis index repeated storage changes to be {}, but got {}",
                verifiers.genesis_config.genesis_rollup_leaf_index,
                self.genesisIndexRepeatedStorageChanges
            ));
        }

        if self.genesisBatchCommitment.to_string()
            != verifiers.genesis_config.genesis_batch_commitment
        {
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

        if self.forceDeploymentsData.is_empty() {
            result.report_error("Force deployments data is empty");
        } else {
            let fixed_force_deployments_data =
                FixedForceDeploymentsData::abi_decode(&self.forceDeploymentsData, true)
                    .expect("Failed to decode FixedForceDeploymentsData");
            fixed_force_deployments_data
                .verify(verifiers, result)
                .await?;
        }

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
            selectors: facet.selectors.iter().map(|x| x.0).collect(),
        });
    }

    if expected_chain_creation_facets != proposed_facet_cut {
        result.report_error(&format!(
            "Invalid chain creation facet cut. Expected: {:#?}\nReceived: {:#?}",
            expected_chain_creation_facets, proposed_facet_cut
        ));
    }

    result.expect_address(verifiers, &diamond_cut.initAddress, "diamond_init");
    let initialize_data_new_chain =
        InitializeDataNewChain::abi_decode(&diamond_cut.initCalldata, true)
            .expect("Failed to decode InitializeDataNewChain");
    initialize_data_new_chain.verify(verifiers, result).await?;

    Ok(())
}

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
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 0 calls ===");

        let list_of_calls = [("bridgehub_proxy", "pauseMigration()")];
        // If this is just a single call without any params, we don't have to check
        // anything else.

        self.calls
            .verify(&list_of_calls, verifiers, result)
            .context("calls")?;
        Ok(())
    }
}
impl GovernanceStage2Calls {
    /// Stage2 is executed after all the chains have upgraded.
    pub(crate) async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Gov stage 2 calls ===");

        let list_of_calls = [("bridgehub_proxy", "unpauseMigration()")];
        // If this is just a single call without any params, we don't have to check
        // anything else.

        self.calls
            .verify(&list_of_calls, verifiers, result)
            .context("calls")?;
        Ok(())
    }
}
