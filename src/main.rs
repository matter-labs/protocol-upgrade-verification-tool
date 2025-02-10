use alloy::{
    hex::{FromHex, ToHexExt},
    primitives::{Address, FixedBytes},
};
use serde::Deserialize;
use std::{fmt::Debug, fs, str::FromStr};
use utils::{address_verifier::AddressVerifier, apply_l2_to_l1_alias};
use verifiers::{VerificationResult, Verifiers};

mod elements;
mod utils;
mod verifiers;
use clap::Parser;
use elements::{
    call_list::CallList, deployed_addresses::DeployedAddresses,
    governance_stage1_calls::GovernanceStage1Calls, governance_stage2_calls::GovernanceStage2Calls,
    post_upgrade_calldata::compute_expected_address_for_file, protocol_version::ProtocolVersion,
};

const DEFAULT_CONTRACTS_COMMIT: &str = "6badcb8a9b6114c6dd10d3b172a96812250604b0";
const DEFAULT_ERA_COMMIT: &str = "99c3905a9e92416e76d37b0858da7f6c7e123e0b";

pub(crate) const EXPECTED_NEW_PROTOCOL_VERSION_STR: &str = "0.26.0";
pub(crate) const EXPECTED_OLD_PROTOCOL_VERSION_STR: &str = "0.25.0";
pub(crate) const MAX_NUMBER_OF_ZK_CHAINS: u32 = 100;

pub(crate) fn get_expected_new_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_NEW_PROTOCOL_VERSION_STR).unwrap()
}

pub(crate) fn get_expected_old_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_OLD_PROTOCOL_VERSION_STR).unwrap()
}

#[derive(Debug, Deserialize)]
pub struct UpgradeOutput {
    // TODO: potentially verify this array.
    // It does not affect the upgrade, but it could be cross-checked for correctness.
    chain_upgrade_diamond_cut: String,
    create2_factory_addr: Address,
    create2_factory_salt: FixedBytes<32>,
    deployer_addr: Address,
    pub(crate) era_chain_id: u64,
    governance_stage1_calls: String,
    governance_stage2_calls: String,
    pub(crate) l1_chain_id: u64,

    protocol_upgrade_handler_proxy_address: Address,
    protocol_upgrade_handler_impl_address: Address,

    contracts_config: ContractsConfig,
    deployed_addresses: DeployedAddresses,

    transactions: Vec<String>,
}

impl UpgradeOutput {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        self.deployed_addresses.add_to_verifier(address_verifier);
    }
}

impl UpgradeOutput {
    async fn verify(
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

#[derive(Debug, Deserialize)]
struct ContractsConfig {
    expected_rollup_l2_da_validator: Address,
    // TODO: double check the correctness of the rest of the fields.
    // These do not impact the correctness of the upgrade, but could assist to ensure no errors
    // for chain operations.
}

pub fn address_eq(address: &Address, addr_string: &str) -> bool {
    address.encode_hex()
        == addr_string
            .strip_prefix("0x")
            .unwrap_or(addr_string)
            .to_ascii_lowercase()
}

#[derive(Debug, Parser)]
struct Args {
    // ecosystem_yaml file (gateway_ecosystem_upgrade_output.yaml - from zksync_era/configs)
    #[clap(short, long)]
    ecosystem_yaml: String,

    // Commit from zksync-era repository (used for genesis verification)
    #[clap(long, default_value = DEFAULT_ERA_COMMIT)]
    era_commit: String,

    // Commit from era-contracts - used for bytecode verification
    #[clap(long, default_value = DEFAULT_CONTRACTS_COMMIT)]
    contracts_commit: String,

    // L1 address
    #[clap(long)]
    l1_rpc: String,

    // If L2 RPC is not available, you can provide l2 chain id instead.
    #[clap(long)]
    era_chain_id: u64,

    // If set - then will expect testnet contracts to be deployed (like TestnetVerifier).
    #[clap(long)]
    testnet_contracts: bool,

    // fixme: can it be an address rightaway?
    #[clap(long)]
    bridgehub_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    env_logger::init();

    // Read the YAML file
    let yaml_content = fs::read_to_string(args.ecosystem_yaml)?;

    // Parse the YAML content
    let config: UpgradeOutput = serde_yaml::from_str(&yaml_content)?;

    let verifiers = Verifiers::new(
        args.testnet_contracts,
        args.bridgehub_address.clone(),
        &args.era_commit,
        &args.contracts_commit,
        args.l1_rpc,
        args.era_chain_id,
        &config
    )
    .await;

    let mut result = VerificationResult::default();

    let r = config.verify(&verifiers, &mut result).await;

    println!("{}", result);
    r.unwrap();

    Ok(())
}
