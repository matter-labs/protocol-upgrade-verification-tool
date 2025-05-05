use alloy::primitives::{Address, FixedBytes, U256};
use anyhow::Context;
use call_list::CallList;
use gateway_state_transition::GatewayStateTransition;
use governance_stage_calls::{EcosystemAdminCalls, GovernanceCalls};
use initialize_data_new_chain::{FeeParams, PubdataPricingMode};
use protocol_version::ProtocolVersion;
use serde::Deserialize;

use crate::{
    get_expected_new_protocol_version, get_expected_old_protocol_version,
    utils::{address_from_short_hex, address_verifier::AddressVerifier, network_verifier::NetworkVerifier},
    verifiers::{VerificationResult, Verifiers},
    MAX_PRIORITY_TX_GAS_LIMIT,
};

pub mod call_list;
pub mod fixed_force_deployment;
pub mod force_deployment;
pub mod gateway_state_transition;
pub mod governance_stage_calls;
pub mod initialize_data_new_chain;
pub mod protocol_version;
pub mod set_new_version_upgrade;

#[derive(Debug, Deserialize)]
pub struct UpgradeOutput {
    pub(crate) diamond_cut_data: String,
    pub(crate) ecosystem_admin_calls_to_execute: String,
    pub(crate) governance_calls_to_execute: String,
    
    pub(crate) multicall3_addr: Address,
    pub(crate) relayed_sl_da_validator: Address,
    pub(crate) validium_da_validator: Address,

    pub(crate) gateway_state_transition: GatewayStateTransition,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ContractsConfig {
    diamond_cut_data: String,
    diamond_init_batch_overhead_l1_gas: u32,
    diamond_init_max_l2_gas_per_batch: u32,
    diamond_init_max_pubdata_per_batch: u32,
    diamond_init_minimal_l2_gas_price: u64,
    diamond_init_priority_tx_max_pubdata: u32,
    // todo: maybe convert to enum rightaway
    diamond_init_pubdata_pricing_mode: u32,
    force_deployments_data: String,
    l1_legacy_shared_bridge: Address,
    new_protocol_version: u64,
    old_protocol_version: u64,
    old_validator_timelock: Address,
    priority_tx_max_gas_limit: u32,
    recursion_circuits_set_vks_hash: FixedBytes<32>,
    recursion_leaf_level_vk_hash: FixedBytes<32>,
    recursion_node_level_vk_hash: FixedBytes<32>,
}

impl ContractsConfig {
    pub async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
        expected_diamond_cut_data: String,
        expected_force_deployments: String,
    ) {
        if expected_diamond_cut_data != self.diamond_cut_data[2..] {
            result.report_error(&format!(
                "Initial diamondcutdata mismatch.\nExpected: {}\nReceived: {}",
                expected_diamond_cut_data,
                &self.diamond_cut_data[2..]
            ));
        }

        let provided_fee_params = FeeParams {
            pubdataPricingMode: if self.diamond_init_pubdata_pricing_mode == 0 {
                PubdataPricingMode::Rollup
            } else {
                PubdataPricingMode::Validium
            },
            batchOverheadL1Gas: self.diamond_init_batch_overhead_l1_gas,
            maxPubdataPerBatch: self.diamond_init_max_pubdata_per_batch,
            maxL2GasPerBatch: self.diamond_init_max_l2_gas_per_batch,
            priorityTxMaxPubdata: self.diamond_init_priority_tx_max_pubdata,
            minimalL2GasPrice: self.diamond_init_minimal_l2_gas_price,
        };
        if provided_fee_params != verifiers.fee_param_verifier.fee_params {
            result.report_error(&format!(
                "Diamond init fee params mismatch.\nExpected: {:#?}\nReceived: {:#?}",
                verifiers.fee_param_verifier.fee_params, provided_fee_params
            ));
        }

        if expected_force_deployments != self.force_deployments_data[2..] {
            result.report_error(&format!(
                "Fixed force deployment data mismatch.\nExpected: {}\nReceived: {}",
                expected_force_deployments,
                &self.force_deployments_data[2..]
            ));
        }

        result.expect_address(
            verifiers,
            &self.l1_legacy_shared_bridge,
            "l1_asset_router_proxy",
        );

        let provided_new_protocol_version =
            ProtocolVersion::from(U256::from(self.new_protocol_version));
        if provided_new_protocol_version != get_expected_new_protocol_version() {
            result.report_error(&format!(
                "Invalid protocol version provided.\nExpected: {}\nReceived: {}",
                get_expected_new_protocol_version(),
                provided_new_protocol_version
            ));
        }

        let provided_old_protocol_version =
            ProtocolVersion::from(U256::from(self.old_protocol_version));
        if provided_old_protocol_version != get_expected_old_protocol_version() {
            result.report_error(&format!(
                "Invalid protocol version provided.\nExpected: {}\nReceived: {}",
                get_expected_old_protocol_version(),
                provided_old_protocol_version
            ));
        }

        result.expect_address(
            verifiers,
            &self.old_validator_timelock,
            "old_validator_timelock",
        );

        if self.priority_tx_max_gas_limit != MAX_PRIORITY_TX_GAS_LIMIT {
            result.report_error(&format!(
                "Invalid priority tx max gas limit.\nExpected: {}\nReceived: {}",
                MAX_PRIORITY_TX_GAS_LIMIT, self.priority_tx_max_gas_limit
            ));
        }

        if self.recursion_circuits_set_vks_hash != [0u8; 32]
            || self.recursion_leaf_level_vk_hash != [0u8; 32]
            || self.recursion_node_level_vk_hash != [0u8; 32]
        {
            result.report_error("Verifier params must be empty.");
        }
    }
}

impl UpgradeOutput {
    pub async fn add_to_verifier(&self, address_verifier: &mut AddressVerifier, network_verifier: &NetworkVerifier, bridgehub_addr: Address) {
        address_verifier.add_address(self.multicall3_addr, "multicall3_addr");
        address_verifier.add_address(self.relayed_sl_da_validator, "relayed_sl_da_validator");
        address_verifier.add_address(self.validium_da_validator, "validium_da_validator");
        self.gateway_state_transition.add_to_verifier(address_verifier, network_verifier, bridgehub_addr).await;
    }

    pub async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Config verification ==");
        
        let provider_chain_id = verifiers.network_verifier.get_era_chain_id();

        // Check that addresses actually contain correct bytecodes.
        self.gateway_state_transition
            .verify(verifiers, result)
            .await
            .context("checking deployed addresses")?;
        // let (facets_to_remove, facets_to_add) = self
        //     .deployed_addresses
        //     .get_expected_facet_cuts(verifiers, result)
        //     .await
        //     .context("checking facets")?;

        // result
        //     .expect_deployed_bytecode(verifiers, &create2_factory_addr, "Create2Factory")
        //     .await;

        let ecosystem_admin_calls = EcosystemAdminCalls {
            calls: CallList::parse(&self.ecosystem_admin_calls_to_execute),
        };

        ecosystem_admin_calls.verify(verifiers, result).await.context("ecosystem_admin_calls")?;

        let governance_calls = GovernanceCalls {
            calls: CallList::parse(&self.governance_calls_to_execute),
        };

        // let expected_upgrade_facets = facets_to_remove.merge(facets_to_add.clone()).clone();

        governance_calls
            .verify(
                verifiers,
                result,
            )
            .await
            .context("governance_calls")?;

        Ok(())
    }
}
