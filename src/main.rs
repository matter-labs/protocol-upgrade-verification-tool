use std::{fmt::Debug, fs, str::FromStr};
use utils::display_upgrade_data::encode_upgrade_data;
use verifiers::{VerificationResult, Verifiers};

mod elements;
mod utils;
mod verifiers;
use clap::Parser;
use elements::{protocol_version::ProtocolVersion, UpgradeOutput};

// Current top of release-27 branch
const DEFAULT_CONTRACTS_COMMIT: &str = "f6c41ebc5cc0c031a72342d2ca4431954574a114";
// Current commit after v27 merge to main branch (PR 3713)
const DEFAULT_ERA_COMMIT: &str = "9cbacb86634f00cfabb55f94a73b5c564c74bf36";

pub(crate) const EXPECTED_NEW_PROTOCOL_VERSION_STR: &str = "0.27.0";
pub(crate) const EXPECTED_OLD_PROTOCOL_VERSION_STR: &str = "0.26.0";
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

    // If L2 RPC is not available, you can provide l2 chain id instead.
    #[clap(long)]
    era_chain_id: u64,

    // If set - then will expect testnet contracts to be deployed (like TestnetVerifier).
    #[clap(long)]
    testnet_contracts: bool,

    // fixme: can it be an address rightaway?
    #[clap(long)]
    bridgehub_address: String,

    // Gateway Chain Id
    #[clap(long)]
    gw_rpc: String,
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
        args.gw_rpc,
        args.era_chain_id,
        &config,
    )
    .await;

    let mut result = VerificationResult::default();

    let r = config.verify(
        &verifiers, 
        &mut result,
    ).await;

    println!("{}", result);
    r.unwrap();

    if args.display_upgrade_data.unwrap_or_default() {
        println!(
            "Ecosystem Admin encoded upgrade data = {}",
            encode_upgrade_data(&config.ecosystem_admin_calls_to_execute)
        );

        println!(
            "Governance Calls encoded upgrade data = {}",
            encode_upgrade_data(&config.governance_calls_to_execute)
        );
    }

    Ok(())
}
