use alloy::{
    hex::FromHex,
    primitives::{Address, FixedBytes},
};
use colored::Colorize;
use serde::Deserialize;
use std::fmt::Display;
use std::panic::Location;

use crate::utils::{
    address_verifier::AddressVerifier, bytecode_verifier::BytecodeVerifier,
    get_contents_from_github, network_verifier::NetworkVerifier,
    selector_verifier::SelectorVerifier,
};

#[derive(Default)]
pub struct Verifiers {
    pub selector_verifier: SelectorVerifier,
    pub address_verifier: AddressVerifier,
    pub bytecode_verifier: BytecodeVerifier,
    pub network_verifier: NetworkVerifier,
    pub genesis_config: Option<GenesisConfig>,
}

#[derive(Debug, Deserialize)]
pub struct GenesisConfig {
    pub genesis_root: String,
    pub genesis_rollup_leaf_index: u64,
    pub genesis_batch_commitment: String,
}

impl GenesisConfig {
    pub async fn init_from_github(commit: &str) -> Self {
        println!("init from github {}", commit);
        let data = get_contents_from_github(
            commit,
            "matter-labs/zksync-era",
            "etc/env/file_based/genesis.yaml",
        )
        .await;

        serde_yaml::from_str(&data).unwrap()
    }
}

#[derive(Default)]
pub struct VerificationResult {
    pub result: String,
    pub warnings: u64,
    pub errors: u64,
}

impl VerificationResult {
    pub fn print_info(&self, info: &str) {
        println!("{}", info);
    }
    pub fn report_ok(&self, info: &str) {
        println!("{} {}", "[OK]: ".green(), info);
    }

    pub fn report_warn(&mut self, warn: &str) {
        self.warnings += 1;
        println!("{} {}", "[WARN]:".yellow(), warn);
    }
    pub fn report_error(&mut self, error: &str) {
        self.errors += 1;
        println!("{} {}", "[ERROR]:".red(), error);
    }

    #[track_caller]
    pub fn expect_address(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected: &str,
    ) -> bool {
        let address = verifiers.address_verifier.name_or_unknown(address);
        if address != expected {
            self.report_error(&format!(
                "Expected address {}, got {} at {}",
                expected,
                address,
                Location::caller()
            ));
            false
        } else {
            true
        }
    }

    #[track_caller]
    pub fn expect_bytecode(
        &mut self,
        verifiers: &Verifiers,
        bytecode_hash: &FixedBytes<32>,
        expected: &str,
    ) {
        match verifiers
            .bytecode_verifier
            .bytecode_hash_to_file(bytecode_hash)
        {
            Some(file_name) => {
                if file_name != expected {
                    self.report_error(&format!(
                        "Expected bytecode {}, got {} at {}",
                        expected,
                        file_name,
                        Location::caller()
                    ));
                }
            }
            None => {
                self.report_warn(&format!(
                    "Cannot verify bytecode hash: {} - expected {}",
                    bytecode_hash, expected
                ));
            }
        }
    }

    pub async fn expect_deployed_bytecode(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected_file: &str,
    ) {
        self.expect_deployed_bytecode_internal(verifiers, address, expected_file, false)
            .await;
    }

    pub async fn expect_deployed_bytecode_internal(
        &mut self,
        verifiers: &Verifiers,
        address: &Address,
        expected_file: &str,
        report_ok: bool,
    ) -> bool {
        let bytecode_hash = verifiers
            .network_verifier
            .get_bytecode_hash_at(address)
            .await;
        match bytecode_hash {
            Some(bytecode_hash) => {
                if bytecode_hash == FixedBytes::ZERO {
                    self.report_warn(&format!(
                        "Bytecode hash at {} is zero - expected code {} at {}",
                        address,
                        expected_file,
                        Location::caller()
                    ));
                    return false;
                } else {
                    let original_file = verifiers
                        .bytecode_verifier
                        .bytecode_hash_to_file(&bytecode_hash);
                    match original_file {
                        Some(file) => {
                            if file == expected_file {
                                if report_ok {
                                    self.report_ok(&format!("{} at {}", expected_file, address));
                                }
                                true
                            } else {
                                self.report_error(&format!(
                                    "Bytecode from wrong file: Expected {} got {} at {}",
                                    expected_file,
                                    file,
                                    Location::caller()
                                ));
                                false
                            }
                        }
                        None => {
                            self.report_warn(&format!(
                                "Unknown bytecode hash at address {} - {} - expected {} at {}",
                                address,
                                bytecode_hash,
                                expected_file,
                                Location::caller()
                            ));
                            false
                        }
                    }
                }
            }
            None => {
                self.report_warn(&format!(
                    "No RPC connection - Cannot check bytecode for {} at {}",
                    expected_file, address
                ));
                false
            }
        }
    }

    pub async fn expect_deployed_proxy_with_bytecode(
        &mut self,
        verifiers: &crate::traits::Verifiers,
        address: &Address,
        expected_file: &str,
    ) {
        // Check that this is really a proxy
        let is_proxy_deployed = self
            .expect_deployed_bytecode_internal(
                verifiers,
                address,
                "TransparentUpgradeableProxy",
                false,
            )
            .await;
        if is_proxy_deployed {
            let transparent_proxy_key = FixedBytes::from_hex(
                "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            )
            .unwrap();
            let implementation_address = verifiers
                .network_verifier
                .storage_at(address, &transparent_proxy_key)
                .await;

            let implementation_address = implementation_address.unwrap();

            let aa = Address::from_slice(&implementation_address.as_slice()[12..]);

            self.expect_deployed_bytecode(verifiers, &aa, expected_file)
                .await;
        }
    }
}

impl Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors > 0 {
            let res = "ERROR".red();
            write!(
                f,
                "{} errors: {} - result: {}",
                res, self.errors, self.result
            )
        } else {
            if self.warnings == 0 {
                let res = "OK".green();
                write!(f, "{} - result: {}", res, self.result)
            } else {
                let res = "WARN".yellow();
                write!(
                    f,
                    "{} warnings: {} - result: {}",
                    res, self.warnings, self.result
                )
            }
        }
    }
}

pub trait Verify {
    async fn verify(
        &self,
        verifiers: &Verifiers,
        result: &mut VerificationResult,
    ) -> anyhow::Result<()>;
}
