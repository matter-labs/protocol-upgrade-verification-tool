use alloy::hex::FromHex;
use alloy::primitives::{Address, FixedBytes, U256};
use anyhow::Context;
use call_list::CallList;
use deployed_addresses::DeployedAddresses;
use governance_stage_calls::{GovernanceStage0Calls, GovernanceStage1Calls, GovernanceStage2Calls};
use initialize_data_new_chain::{FeeParams, PubdataPricingMode};
use protocol_version::ProtocolVersion;
use serde::Deserialize;

use crate::{
    get_expected_new_protocol_version, get_expected_old_protocol_version,
    utils::address_verifier::AddressVerifier,
    verifiers::{VerificationResult, Verifiers},
    MAX_PRIORITY_TX_GAS_LIMIT,
};

pub mod call_list;
pub mod deployed_addresses;
pub mod fixed_force_deployment;
pub mod force_deployment;
pub mod governance_stage_calls;
pub mod initialize_data_new_chain;
pub mod protocol_version;
pub mod set_new_version_upgrade;

#[derive(Debug, Deserialize)]
pub struct UpgradeOutput {
    pub(crate) chain_upgrade_diamond_cut: String,
    pub(crate) create2_factory_addr: Address,
    pub(crate) create2_factory_salt: FixedBytes<32>,
    pub(crate) deployer_addr: Address,
    pub(crate) era_chain_id: u64,

    pub(crate) governance_calls: GovernanceCalls,

    pub(crate) l1_chain_id: u64,

    pub(crate) gateway_chain_id: u64,

    #[serde(default)]
    pub(crate) protocol_upgrade_handler_proxy_address: Option<Address>,

    pub(crate) contracts_config: ContractsConfig,
    pub(crate) deployed_addresses: DeployedAddresses,

    pub(crate) transactions: Vec<String>,

    pub(crate) gateway: Gateway,

    #[allow(dead_code)]
    pub(crate) max_expected_l1_gas_price: u64,
    pub(crate) priority_txs_l2_gas_limit: u64,

    /// Old chain creation params for L1 and Gateway (used to verify only verifier changed)
    pub(crate) old_chain_creation_params: OldChainCreationParamsWrapper,
}

/// Wrapper for old chain creation params containing both L1 and Gateway params.
#[derive(Debug, Deserialize, Clone)]
pub struct OldChainCreationParamsWrapper {
    /// Old chain creation params for L1
    pub l1: OldChainCreationParams,
    /// Old chain creation params for Gateway
    pub gateway: OldChainCreationParams,
}

/// Represents the old chain creation params that are currently on-chain.
/// These are used to verify that only the verifier address changes in a verifier-only upgrade.
#[derive(Debug, Deserialize, Clone)]
pub struct OldChainCreationParams {
    /// The ABI-encoded DiamondCutData (hex string with 0x prefix)
    pub diamond_cut_data: String,
    /// The force deployments data (hex string with 0x prefix)
    pub force_deployments_data: String,
    /// Genesis batch commitment (hex string with 0x prefix)
    pub genesis_batch_commitment: String,
    /// Genesis batch hash (hex string with 0x prefix)
    pub genesis_batch_hash: String,
    /// Genesis index for repeated storage changes
    pub genesis_index_repeated_storage_changes: u64,
    /// Genesis upgrade address (hex string with 0x prefix)
    pub genesis_upgrade: Address,
}

#[derive(Debug, Deserialize)]
pub struct GovernanceCalls {
    pub(crate) stage0_calls: String,
    pub(crate) stage1_calls: String,
    pub(crate) stage2_calls: String,
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize)]
pub(crate) struct Gateway {
    pub diamond_cut_data: String,
    pub upgrade_cut_data: String,
    pub gateway_state_transition: GatewayStateTransition,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GatewayStateTransition {
    pub admin_facet_addr: Address,
    pub chain_type_manager_implementation_addr: Address,
    pub chain_type_manager_proxy: Address,
    pub diamond_init_addr: Address,
    pub executor_facet_addr: Address,
    pub genesis_upgrade_addr: Address,
    pub default_upgrade_addr: Address,
    pub getters_facet_addr: Address,
    pub mailbox_facet_addr: Address,
    pub verifier_addr: Address,
    pub verifier_fflonk_addr: Address,
    pub verifier_plonk_addr: Address,
    pub rollup_da_manager: Address,
    pub rollup_l2_da_validator: Address,
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

/// Constants used for storedBatchZero calculation
const EMPTY_STRING_KECCAK: FixedBytes<32> = FixedBytes::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]); // keccak256("")

const DEFAULT_L2_LOGS_TREE_ROOT_HASH: FixedBytes<32> = FixedBytes::ZERO;

impl OldChainCreationParams {
    /// Computes the keccak256 hash of the diamond cut data
    pub fn compute_cut_hash(&self) -> FixedBytes<32> {
        use alloy::primitives::keccak256;
        let data = alloy::hex::decode(&self.diamond_cut_data[2..])
            .expect("Invalid hex in diamond_cut_data");
        keccak256(&data)
    }

    /// Computes the keccak256 hash of the force deployments data (ABI-encoded as bytes)
    pub fn compute_force_deployment_hash(&self) -> FixedBytes<32> {
        use alloy::primitives::keccak256;
        use alloy::sol_types::SolValue;

        let data = alloy::hex::decode(&self.force_deployments_data[2..])
            .expect("Invalid hex in force_deployments_data");
        // The hash is computed as keccak256(abi.encode(forceDeploymentsData))
        let encoded = data.abi_encode();
        keccak256(&encoded)
    }

    /// Computes the storedBatchZero hash from genesis params
    /// This is calculated as keccak256(abi.encode(StoredBatchInfo))
    pub fn compute_stored_batch_zero(&self) -> FixedBytes<32> {
        use alloy::primitives::keccak256;
        use alloy::sol_types::SolValue;

        // Parse genesis params from hex strings
        let genesis_batch_hash = FixedBytes::<32>::from_hex(&self.genesis_batch_hash)
            .expect("Invalid hex in genesis_batch_hash");
        let genesis_batch_commitment = FixedBytes::<32>::from_hex(&self.genesis_batch_commitment)
            .expect("Invalid hex in genesis_batch_commitment");

        // StoredBatchInfo struct encoding:
        // uint64 batchNumber = 0
        // bytes32 batchHash = genesis_batch_hash
        // uint64 indexRepeatedStorageChanges = genesis_index_repeated_storage_changes
        // uint256 numberOfLayer1Txs = 0
        // bytes32 priorityOperationsHash = EMPTY_STRING_KECCAK
        // bytes32 dependencyRootsRollingHash = bytes32(0)
        // bytes32 l2LogsTreeRoot = DEFAULT_L2_LOGS_TREE_ROOT_HASH
        // uint256 timestamp = 0
        // bytes32 commitment = genesis_batch_commitment
        let stored_batch_info = (
            0u64,                                             // batchNumber
            genesis_batch_hash,                               // batchHash
            self.genesis_index_repeated_storage_changes,      // indexRepeatedStorageChanges (u64)
            U256::ZERO,                                       // numberOfLayer1Txs
            EMPTY_STRING_KECCAK,                              // priorityOperationsHash
            FixedBytes::<32>::ZERO,                           // dependencyRootsRollingHash
            DEFAULT_L2_LOGS_TREE_ROOT_HASH,                   // l2LogsTreeRoot
            U256::ZERO,                                       // timestamp
            genesis_batch_commitment,                         // commitment
        );

        let encoded = stored_batch_info.abi_encode();
        keccak256(&encoded)
    }
}

impl UpgradeOutput {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        self.deployed_addresses.add_to_verifier(address_verifier);
    }

    /// Verifies that the old chain creation params from YAML match the on-chain state
    async fn verify_old_chain_creation_params_match_onchain(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Verifying old chain creation params match on-chain state ==");

        // Verify L1 old chain creation params
        let (l1_onchain_cut_hash, l1_onchain_force_hash, l1_onchain_stored_batch_zero) = verifiers
            .network_verifier
            .get_l1_ctm_chain_creation_hashes(verifiers.bridgehub_address)
            .await;

        let l1_computed_cut_hash = self.old_chain_creation_params.l1.compute_cut_hash();
        let l1_computed_force_hash = self.old_chain_creation_params.l1.compute_force_deployment_hash();
        let l1_computed_stored_batch_zero = self.old_chain_creation_params.l1.compute_stored_batch_zero();

        if l1_onchain_cut_hash == l1_computed_cut_hash {
            result.report_ok("L1 old diamond cut hash matches on-chain");
        } else {
            result.report_error(&format!(
                "L1 old diamond cut hash mismatch.\nOn-chain: {}\nComputed from YAML: {}",
                l1_onchain_cut_hash, l1_computed_cut_hash
            ));
        }

        if l1_onchain_force_hash == l1_computed_force_hash {
            result.report_ok("L1 old force deployment hash matches on-chain");
        } else {
            result.report_error(&format!(
                "L1 old force deployment hash mismatch.\nOn-chain: {}\nComputed from YAML: {}",
                l1_onchain_force_hash, l1_computed_force_hash
            ));
        }

        if l1_onchain_stored_batch_zero == l1_computed_stored_batch_zero {
            result.report_ok("L1 old storedBatchZero matches on-chain");
        } else {
            result.report_error(&format!(
                "L1 old storedBatchZero mismatch.\nOn-chain: {}\nComputed from YAML: {}",
                l1_onchain_stored_batch_zero, l1_computed_stored_batch_zero
            ));
        }

        // Verify Gateway old chain creation params
        let gw_ctm_proxy = self.gateway.gateway_state_transition.chain_type_manager_proxy;
        let (gw_onchain_cut_hash, gw_onchain_force_hash, gw_onchain_stored_batch_zero) = verifiers
            .network_verifier
            .get_gw_ctm_chain_creation_hashes(gw_ctm_proxy)
            .await;

        let gw_computed_cut_hash = self.old_chain_creation_params.gateway.compute_cut_hash();
        let gw_computed_force_hash = self.old_chain_creation_params.gateway.compute_force_deployment_hash();
        let gw_computed_stored_batch_zero = self.old_chain_creation_params.gateway.compute_stored_batch_zero();

        if gw_onchain_cut_hash == gw_computed_cut_hash {
            result.report_ok("GW old diamond cut hash matches on-chain");
        } else {
            result.report_error(&format!(
                "GW old diamond cut hash mismatch.\nOn-chain: {}\nComputed from YAML: {}",
                gw_onchain_cut_hash, gw_computed_cut_hash
            ));
        }

        if gw_onchain_force_hash == gw_computed_force_hash {
            result.report_ok("GW old force deployment hash matches on-chain");
        } else {
            result.report_error(&format!(
                "GW old force deployment hash mismatch.\nOn-chain: {}\nComputed from YAML: {}",
                gw_onchain_force_hash, gw_computed_force_hash
            ));
        }

        if gw_onchain_stored_batch_zero == gw_computed_stored_batch_zero {
            result.report_ok("GW old storedBatchZero matches on-chain");
        } else {
            result.report_error(&format!(
                "GW old storedBatchZero mismatch.\nOn-chain: {}\nComputed from YAML: {}",
                gw_onchain_stored_batch_zero, gw_computed_stored_batch_zero
            ));
        }

        Ok(())
    }

    pub async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Config verification (Verifier-Only Upgrade) ==");

        let provider_chain_id = verifiers.network_verifier.get_era_chain_id();
        if provider_chain_id == self.era_chain_id {
            result.report_ok("Chain id");
        } else {
            result.report_error(&format!(
                "chain id mismatch: {} vs {} ",
                self.era_chain_id, provider_chain_id
            ));
        }

        if self.l1_chain_id == verifiers.network_verifier.get_l1_chain_id() {
            result.report_ok("L1 chain id");
        } else {
            result.report_error(&format!(
                "L1 chain id mismatch: {} vs {} ",
                self.l1_chain_id,
                verifiers.network_verifier.get_l1_chain_id()
            ));
        }

        // Verify old chain creation params from YAML match on-chain state
        self.verify_old_chain_creation_params_match_onchain(verifiers, result)
            .await
            .context("verifying old chain creation params")?;

        // For verifier-only upgrade, we only verify the verifier-related deployed addresses
        self.deployed_addresses
            .verify_verifier_only(self, verifiers, result)
            .await
            .context("checking deployed addresses (verifier-only)")?;

        result
            .expect_deployed_bytecode(verifiers, &self.create2_factory_addr, "Create2Factory")
            .await;

        let stage0 = GovernanceStage0Calls {
            calls: CallList::parse(&self.governance_calls.stage0_calls),
        };

        stage0
            .verify(
                verifiers,
                result,
                self.gateway_chain_id,
                self.priority_txs_l2_gas_limit,
            )
            .await
            .context("stage0")?;

        let stage1 = GovernanceStage1Calls {
            calls: CallList::parse(&self.governance_calls.stage1_calls),
        };

        // For verifier-only upgrade, Stage 1 is simplified:
        // - No proxy upgrades
        // - No DA pair updates
        // - No Gateway CTM upgrade
        // - Only verifier address changes in chain creation params and version upgrade
        let (
            l1_expected_chain_creation_data,
            l1_expected_force_deployments,
            gw_expected_chain_creation_data,
            gw_expected_force_deployments,
        ) = stage1
            .verify(
                verifiers,
                result,
                self.gateway_chain_id,
                self.priority_txs_l2_gas_limit,
                &self.deployed_addresses,
                &self.chain_upgrade_diamond_cut,
                &self.gateway.upgrade_cut_data,
                &self.old_chain_creation_params.l1,
                &self.old_chain_creation_params.gateway,
            )
            .await
            .context("stage1")?;

        let stage2 = GovernanceStage2Calls {
            calls: CallList::parse(&self.governance_calls.stage2_calls),
        };

        stage2
            .verify(
                verifiers,
                result,
                self.gateway_chain_id,
                self.priority_txs_l2_gas_limit,
            )
            .await
            .context("stage2")?;

        self.contracts_config
            .verify(
                verifiers,
                result,
                l1_expected_chain_creation_data,
                l1_expected_force_deployments,
            )
            .await;

        let mut config = self.contracts_config.clone();
        config.diamond_cut_data = self.gateway.diamond_cut_data.clone();

        config
            .verify(
                verifiers,
                result,
                gw_expected_chain_creation_data,
                gw_expected_force_deployments,
            )
            .await;

        Ok(())
    }
}
