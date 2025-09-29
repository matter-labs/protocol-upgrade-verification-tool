use std::{fmt::Debug, fs, str::FromStr};
use utils::display_upgrade_data::encode_upgrade_data;
use verifiers::{VerificationResult, Verifiers};

mod elements;
mod utils;
mod verifiers;
use clap::Parser;
use elements::{protocol_version::ProtocolVersion, UpgradeOutput};

use crate::utils::v28_upgrade_comparator::V28UpgradeComparator;

// Current top of release-v28 branch
const DEFAULT_CONTRACTS_COMMIT: &str = "6754d814334d885574d0a2238449ec64a5ec6100";
// Current commit on top of main
const DEFAULT_ERA_COMMIT: &str = "b7aeab64ce5c915233a773542ef64e79bf3893ee";

pub(crate) const EXPECTED_NEW_PROTOCOL_VERSION_STR: &str = "0.28.1";
pub(crate) const EXPECTED_OLD_PROTOCOL_VERSION_STR: &str = "0.28.0";
pub(crate) const MAX_NUMBER_OF_ZK_CHAINS: u32 = 100;
pub(crate) const MAX_PRIORITY_TX_GAS_LIMIT: u32 = 72_000_000;

pub(crate) fn get_expected_new_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_NEW_PROTOCOL_VERSION_STR).unwrap()
}

pub(crate) fn get_expected_old_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_OLD_PROTOCOL_VERSION_STR).unwrap()
}

#[derive(Debug, Parser)]
struct Args {
    // ecosystem_yaml file (gateway_ecosystem_upgrade_output.yaml - from zksync_era/configs)
    #[clap(short, long)]
    ecosystem_yaml: String,

    #[clap(long)]
    v28_ecosystem_yaml: String,

    // Commit from zksync-era repository (used for genesis verification)
    #[clap(long, default_value = DEFAULT_ERA_COMMIT)]
    era_commit: String,

    // Commit from era-contracts - used for bytecode verification
    #[clap(long, default_value = DEFAULT_CONTRACTS_COMMIT)]
    contracts_commit: String,

    #[clap(long)]
    display_upgrade_data: Option<bool>,

    // L1 address
    #[clap(long)]
    l1_rpc: String,

    // GW RPC
    #[clap(long)]
    gw_rpc: String,

    // If L2 RPC is not available, you can provide l2 chain id instead.
    #[clap(long)]
    era_chain_id: u64,

    // If set - then will expect testnet contracts to be deployed (like TestnetVerifier).
    #[clap(long)]
    testnet_contracts: bool,

    #[clap(long)]
    display_previous_data: Option<bool>,

    // fixme: can it be an address rightaway?
    #[clap(long)]
    bridgehub_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    env_logger::init();

    // The upgrade should be a small patch of v28, so we can compare the input to the provided one.
    let v28_upgrade_config = {
        let yaml_content = fs::read_to_string(&args.v28_ecosystem_yaml)?;
        serde_yaml::from_str::<UpgradeOutput>(&yaml_content)?
    };

    // Read the YAML file
    let yaml_content = fs::read_to_string(args.ecosystem_yaml)?;

    // Parse the YAML content
    let config: UpgradeOutput = serde_yaml::from_str(&yaml_content)?;

    let mut verifiers = Verifiers::new(
        args.testnet_contracts,
        args.bridgehub_address.clone(),
        &args.era_commit,
        &args.contracts_commit,
        args.l1_rpc,
        args.gw_rpc,
        args.era_chain_id,
        config.gateway_chain_id,
        &config,
    )
    .await;
    let mut result = VerificationResult::default();

    let comparator =
        V28UpgradeComparator::new(&mut result, v28_upgrade_config, config.gateway_chain_id);

    if args.display_previous_data.unwrap_or_default() {
        comparator.display_encoded_previous_data();
        return Ok(());
    }

    let gw_chain_id = verifiers.network_verifier.gateway_chain_id;
    let r = comparator
        .verify(
            &config,
            &mut verifiers,
            &mut result,
            gw_chain_id,
            config.priority_txs_l2_gas_limit,
        )
        .await;

    println!("{}", result);

    r.unwrap();

    if args.display_upgrade_data.unwrap_or_default() {
        println!(
            "Stage0 encoded upgrade data = {}",
            encode_upgrade_data(&config.governance_calls.governance_stage0_calls)
        );

        println!(
            "Stage1 encoded upgrade data = {}",
            encode_upgrade_data(&config.governance_calls.governance_stage1_calls)
        );
        println!(
            "Stage2 encoded upgrade data = {}",
            encode_upgrade_data(&config.governance_calls.governance_stage2_calls)
        );
    }

    Ok(())
}
