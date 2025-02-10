use alloy::{
    hex::{FromHex, ToHexExt},
    primitives::{Address, FixedBytes},
};
use serde::Deserialize;
use std::{fmt::Debug, fs, str::FromStr};
use verifiers::{VerificationResult, Verifiers};
use utils::{address_verifier::AddressVerifier, apply_l2_to_l1_alias};

mod elements;
mod verifiers;
mod utils;
use clap::Parser;
use elements::{
    call_list::CallList, deployed_addresses::DeployedAddresses, governance_stage1_calls::GovernanceStage1Calls, governance_stage2_calls::GovernanceStage2Calls, post_upgrade_calldata::compute_expected_address_for_file, protocol_version::ProtocolVersion
};

const DEFAULT_CONTRACTS_COMMIT: &str = "6badcb8a9b6114c6dd10d3b172a96812250604b0";
const DEFAULT_ERA_COMMIT: &str = "99c3905a9e92416e76d37b0858da7f6c7e123e0b";

pub(crate) const EXPECTED_NEW_PROTOCOL_VERSION_STR: &'static str = "0.26.0";
pub(crate) const EXPECTED_OLD_PROTOCOL_VERSION_STR: &'static str = "0.25.0";
pub(crate) const MAX_NUMBER_OF_ZK_CHAINS: u32 = 100;

pub(crate) fn get_expected_new_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_NEW_PROTOCOL_VERSION_STR).unwrap()
}

pub(crate) fn get_expected_old_protocol_version() -> ProtocolVersion {
    ProtocolVersion::from_str(EXPECTED_OLD_PROTOCOL_VERSION_STR).unwrap()
}

#[derive(Debug, Deserialize)]
struct UpgradeOutput {
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

        let provider_chain_id = verifiers.network_verifier.get_era_chain_id().await;
        if provider_chain_id == self.era_chain_id {
            result.report_ok("Chain id");
        } else {
            result.report_error(&format!(
                "chain id mismatch: {} vs {} ",
                self.era_chain_id, provider_chain_id
            ));
        }

        // Check that addresses actually contain correct bytecodes.
        self.deployed_addresses.verify(&self, verifiers, result).await?;
        let (facets_to_remove, facets_to_add) = self.deployed_addresses.get_expected_facet_cuts(verifiers).await?;

        result
            .expect_deployed_bytecode(verifiers, &self.create2_factory_addr, "Create2Factory")
            .await;

        let stage1 = GovernanceStage1Calls {
            calls: CallList::parse(&self.governance_stage1_calls),
        };

        stage1.verify(&self.deployed_addresses, verifiers, result, facets_to_remove.merge(facets_to_add.clone())).await?;

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
            .unwrap_or(&addr_string)
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

    // fixme: idiomatically all initialization should happen in `new` function, not in `main`
    let mut verifiers = Verifiers::new(
        args.testnet_contracts, 
        args.bridgehub_address.clone(),
        &args.era_commit,
        &args.contracts_commit,
        args.l1_rpc,
        args.era_chain_id
    ).await;

    println!(
        "Adding {} transactions from create2",
        config.transactions.len()
    );

    for transaction in &config.transactions {
        if let Some((address, contract, constructor_param)) = verifiers
            .network_verifier
            .check_create2_deploy(
                &transaction,
                &config.create2_factory_addr,
                &config.create2_factory_salt,
                &verifiers
                .bytecode_verifier
            )
            .await
        {
            verifiers
                .network_verifier
                .create2_constructor_params
                .insert(address, constructor_param)
                .map(|_| {
                    panic!("Duplicate deployment for {:#?}", address);
                });

            verifiers
                .network_verifier.create2_known_bytecodes.insert(address, contract.clone())
                .map(|_| {
                    panic!("Duplicate deployment for {:#?}", address);
                });
        }
    }

    // some constants -- TODO: verify
    verifiers.bytecode_verifier.insert_evm_deployed_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989",
        )
        .unwrap(),
        "Create2Factory".to_string(),
    );

    verifiers.bytecode_verifier.insert_evm_deployed_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "0x1d8a3e7186b2285da5ef3ccf4c63a672e91873f2ffdec522a241f72bfcab11c5",
        )
        .unwrap(),
        "TransparentProxyAdmin".to_string(),
    );

    // Hash of the proxy admin used for stage proofs
    // https://sepolia.etherscan.io/address/0x93AEeE8d98fB0873F8fF595fDd534A1f288786D2
    verifiers.bytecode_verifier.insert_evm_deployed_bytecode_hash(
        FixedBytes::<32>::from_hex(
            "1e651120773914ac75c42598ceac4da0dc3e21709d438937f742ecf916ac30ae",
        )
        .unwrap(),
        "TransparentProxyAdmin".to_string(),
    );

    // let protocol_upgrade_handler_proxy_address = Address::from_str(&config.protocol_upgrade_handler_proxy_address).unwrap();

    let mut result = VerificationResult::default();

    verifiers.address_verifier.add_address(config.protocol_upgrade_handler_impl_address, "new_protocol_upgrade_handler_impl");
    verifiers.address_verifier.add_address(config.protocol_upgrade_handler_proxy_address, "protocol_upgrade_handler_proxy");
    verifiers.address_verifier.add_address(apply_l2_to_l1_alias(config.protocol_upgrade_handler_proxy_address), "aliased_protocol_upgrade_handler_proxy");
    verifiers.address_verifier.add_address(compute_expected_address_for_file(
        &verifiers,
        "l1-contracts/L2SharedBridgeLegacy",
    ),"l2_shared_bridge_legacy_impl");
    verifiers.address_verifier.add_address(compute_expected_address_for_file(
        &verifiers,
        "l1-contracts/BridgedStandardERC20",
    ),"erc20_bridged_standard");

    config.add_to_verifier(&mut verifiers.address_verifier);
    verifiers.address_verifier.add_address(verifiers.network_verifier.get_proxy_admin(config.protocol_upgrade_handler_proxy_address).await, "protocol_upgrade_handler_transparent_proxy_admin");
    verifiers
        .append_addresses()
        .await
        .unwrap();

    let r = config.verify(&verifiers, &mut result).await;

    println!("{}", result);
    r.unwrap();

    Ok(())
}
