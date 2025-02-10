use alloy::primitives::{Address, FixedBytes};
use call_list::CallList;
use deployed_addresses::DeployedAddresses;
use governance_stage1_calls::GovernanceStage1Calls;
use governance_stage2_calls::GovernanceStage2Calls;
use serde::Deserialize;

use crate::{utils::address_verifier::AddressVerifier, verifiers::{VerificationResult, Verifiers}};

pub mod call_list;
pub mod deployed_addresses;
pub mod fixed_force_deployment;
pub mod force_deployment;
pub mod governance_stage1_calls;
pub mod governance_stage2_calls;
pub mod initialize_data_new_chain;
pub mod post_upgrade_calldata;
pub mod protocol_version;
pub mod set_new_version_upgrade;


#[derive(Debug, Deserialize)]
pub struct UpgradeOutput {
    // TODO: potentially verify this array.
    // It does not affect the upgrade, but it could be cross-checked for correctness.
    pub(crate) chain_upgrade_diamond_cut: String,
    pub(crate) create2_factory_addr: Address,
    pub(crate) create2_factory_salt: FixedBytes<32>,
    pub(crate) deployer_addr: Address,
    pub(crate) era_chain_id: u64,
    pub(crate) governance_stage1_calls: String,
    pub(crate) governance_stage2_calls: String,
    pub(crate) l1_chain_id: u64,

    pub(crate) protocol_upgrade_handler_proxy_address: Address,
    pub(crate) protocol_upgrade_handler_impl_address: Address,

    pub(crate) contracts_config: ContractsConfig,
    pub(crate) deployed_addresses: DeployedAddresses,

    pub(crate) transactions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ContractsConfig {
    expected_rollup_l2_da_validator: Address,
    // TODO: double check the correctness of the rest of the fields.
    // These do not impact the correctness of the upgrade, but could assist to ensure no errors
    // for chain operations.
}


impl UpgradeOutput {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        self.deployed_addresses.add_to_verifier(address_verifier);
    }

    pub async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Config verification ==");

        let provider_chain_id = verifiers.network_verifier.get_era_chain_id();
        if provider_chain_id == self.era_chain_id {
            result.report_ok("Chain id");
        } else {
            result.report_error(&format!(
                "chain id mismatch: {} vs {} ",
                self.era_chain_id, provider_chain_id
            ));
        }

        // Check that addresses actually contain correct bytecodes.
        self.deployed_addresses
            .verify(self, verifiers, result)
            .await?;
        let (facets_to_remove, facets_to_add) = self
            .deployed_addresses
            .get_expected_facet_cuts(verifiers)
            .await?;

        result
            .expect_deployed_bytecode(verifiers, &self.create2_factory_addr, "Create2Factory")
            .await;

        let stage1 = GovernanceStage1Calls {
            calls: CallList::parse(&self.governance_stage1_calls),
        };

        stage1
            .verify(
                &self.deployed_addresses,
                verifiers,
                result,
                facets_to_remove.merge(facets_to_add.clone()),
            )
            .await?;

        let stage2 = GovernanceStage2Calls {
            calls: CallList::parse(&self.governance_stage2_calls),
        };
        stage2.verify(verifiers, result, facets_to_add).await?;

        Ok(())
    }
}
