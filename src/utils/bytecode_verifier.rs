use alloy::hex;
use alloy::primitives::{keccak256, Bytes, FixedBytes};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::{compute_hash_with_arguments, get_contents_from_github};

pub struct BytecodeVerifier {
    /// Maps init bytecode hash to the corresponding file name.
    init_bytecode_file_by_hash: HashMap<FixedBytes<32>, String>,
    /// Maps deployed bytecode hash to the corresponding file name.
    deployed_bytecode_file_by_hash: HashMap<FixedBytes<32>, String>,
    /// Maps zk bytecode hash to the corresponding file name.
    zk_bytecode_file_by_hash: HashMap<FixedBytes<32>, String>,
    /// Maps a contract’s file name to its zk bytecode hash.
    bytecode_file_to_zkhash: HashMap<String, FixedBytes<32>>,
}

impl BytecodeVerifier {
    /// Tries to parse `maybe_bytecode` as init code by testing 0 to 9 arguments.
    ///
    /// On success, returns a tuple of the contract file name and the extra argument
    /// bytes appended at the end of the bytecode.
    pub fn try_parse_bytecode(&self, maybe_bytecode: &[u8]) -> Option<(String, Vec<u8>)> {
        // We do not know how many extra 32-byte arguments there are,
        // so we try all values from 0 to 9.
        for i in 0..10 {
            // Skip if there isn’t even enough data for i arguments.
            if maybe_bytecode.len() < 32 * i {
                continue;
            }

            if let Some(hash) =
                compute_hash_with_arguments(&Bytes::copy_from_slice(maybe_bytecode), i)
            {
                if let Some(file_name) = self.evm_init_bytecode_hash_to_file(&hash) {
                    let args_start = maybe_bytecode.len() - 32 * i;
                    return Some((file_name.clone(), maybe_bytecode[args_start..].to_vec()));
                }
            }
        }
        None
    }

    /// Returns the create2 and transfer bytecode.
    ///
    /// This function decodes a hard-coded hex string and cross-checks its hash against
    /// an expected mapping.
    fn get_create2_and_transfer_bytecode(&self) -> Vec<u8> {
        const HEX: &str = "60a060405234801561000f575f80fd5b506040516102c03803806102c083398101604081905261002e9161012e565b5f828451602086015ff590506001600160a01b0381166100945760405162461bcd60e51b815260206004820152601960248201527f437265617465323a204661696c6564206f6e206465706c6f7900000000000000604482015260640160405180910390fd5b60405163f2fde38b60e01b81526001600160a01b03838116600483015282169063f2fde38b906024015f604051808303815f87803b1580156100d4575f80fd5b505af11580156100e6573d5f803e3d5ffd5b505050506001600160a01b031660805250610209915050565b634e487b7160e01b5f52604160045260245ffd5b80516001600160a01b0381168114610129575f80fd5b919050565b5f805f60608486031215610140575f80fd5b83516001600160401b0380821115610156575f80fd5b818601915086601f830112610169575f80fd5b81518181111561017b5761017b6100ff565b604051601f8201601f19908116603f011681019083821181831017156101a3576101a36100ff565b816040528281526020935089848487010111156101be575f80fd5b5f91505b828210156101df57848201840151818301850152908301906101c2565b5f848483010152809750505050808601519350505061020060408501610113565b90509250925092565b60805160a261021e5f395f602e015260a25ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c80638efc30f914602a575b5f80fd5b60507f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b03909116815260200160405180910390f3fea2646970667358221220fd100d8cba14d94be3a7e02be2024b2005374d099be5d61a3beb1aa4690ab94064736f6c63430008180033";

        let bytecode =
            hex::decode(HEX).expect("Invalid hex encoding for create2 and transfer bytecode");

        // Cross-check the resulting bytecode hash against the expected file name.
        let hash = keccak256(&bytecode);
        let expected_file = "l1-contracts/Create2AndTransfer";
        let actual_file = self
            .evm_init_bytecode_hash_to_file(&hash)
            .expect("Missing mapping for create2 and transfer bytecode");
        assert_eq!(
            actual_file, expected_file,
            "Bytecode file mismatch for create2 and transfer"
        );

        bytecode
    }

    /// Checks whether the provided `slice` starts with the create2 and transfer bytecode.
    ///
    /// If so, returns the remainder of the slice (after the prefix).
    pub fn is_create2_and_transfer_bytecode_prefix<'a>(
        &self,
        slice: &'a [u8],
    ) -> Option<&'a [u8]> {
        let prefix = self.get_create2_and_transfer_bytecode();
        if slice.len() < prefix.len() {
            return None;
        }
        if &slice[..prefix.len()] == prefix.as_slice() {
            Some(&slice[prefix.len()..])
        } else {
            None
        }
    }

    /// Returns the file name corresponding to the given init bytecode hash.
    pub fn evm_init_bytecode_hash_to_file(&self, bytecode_hash: &FixedBytes<32>) -> Option<&String> {
        self.init_bytecode_file_by_hash.get(bytecode_hash)
    }

    /// Returns the file name corresponding to the given deployed bytecode hash.
    pub fn evm_deployed_bytecode_hash_to_file(&self, bytecode_hash: &FixedBytes<32>) -> Option<&String> {
        self.deployed_bytecode_file_by_hash.get(bytecode_hash)
    }

    /// Returns the file name corresponding to the given zk bytecode hash.
    pub fn zk_bytecode_hash_to_file(&self, bytecode_hash: &FixedBytes<32>) -> Option<&String> {
        self.zk_bytecode_file_by_hash.get(bytecode_hash)
    }

    /// Returns the zk bytecode hash that corresponds to the file
    pub fn file_to_zk_bytecode_hash(&self, file: &str) -> Option<&FixedBytes<32>> {
        self.bytecode_file_to_zkhash.get(file)
    }

    /// Inserts an entry for the given deployed bytecode hash and file name.
    pub fn insert_evm_deployed_bytecode_hash(&mut self, bytecode_hash: FixedBytes<32>, file: String) {
        self.deployed_bytecode_file_by_hash.insert(bytecode_hash, file);
    }

    /// Initializes the verifier from contract hashes obtained from GitHub.
    pub async fn init_from_github(commit: &str) -> Self {
        let mut init_bytecode_file_by_hash = HashMap::new();
        let mut deployed_bytecode_file_by_hash = HashMap::new();
        let mut bytecode_file_to_zkhash = HashMap::new();
        let mut zk_bytecode_file_by_hash = HashMap::new();

        let contract_hashes = ContractHashes::init_from_github(commit).await;
        for contract in contract_hashes.hashes {
            if let Some(ref hash) = contract.evm_bytecode_hash {
                let decoded = hex::decode(hash)
                    .unwrap_or_else(|_| panic!("Invalid hex in evm_bytecode_hash for {}", contract.contract_name));
                let bytecode_hash = FixedBytes::try_from(decoded.as_slice())
                    .expect("Invalid length for FixedBytes (evm_bytecode_hash)");
                init_bytecode_file_by_hash
                    .insert(bytecode_hash, contract.contract_name.clone());
            }

            if let Some(ref hash) = contract.evm_deployed_bytecode_hash {
                let decoded = hex::decode(hash)
                    .unwrap_or_else(|_| panic!("Invalid hex in evm_deployed_bytecode_hash for {}", contract.contract_name));
                let bytecode_hash = FixedBytes::try_from(decoded.as_slice())
                    .expect("Invalid length for FixedBytes (evm_deployed_bytecode_hash)");
                deployed_bytecode_file_by_hash
                    .insert(bytecode_hash, contract.contract_name.clone());
            }

            if let Some(ref hash) = contract.zk_bytecode_hash {
                let decoded = hex::decode(hash)
                    .unwrap_or_else(|_| panic!("Invalid hex in zk_bytecode_hash for {}", contract.contract_name));
                let bytecode_hash = FixedBytes::try_from(decoded.as_slice())
                    .expect("Invalid length for FixedBytes (zk_bytecode_hash)");
                bytecode_file_to_zkhash
                    .insert(contract.contract_name.clone(), bytecode_hash.clone());
                zk_bytecode_file_by_hash
                    .insert(bytecode_hash, contract.contract_name);
            }
        }

        Self {
            init_bytecode_file_by_hash,
            deployed_bytecode_file_by_hash,
            zk_bytecode_file_by_hash,
            bytecode_file_to_zkhash
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractHash {
    #[serde(rename = "contractName")]
    pub contract_name: String,
    #[serde(rename = "evmBytecodeHash")]
    pub evm_bytecode_hash: Option<String>,
    #[serde(rename = "evmDeployedBytecodeHash")]
    pub evm_deployed_bytecode_hash: Option<String>,
    #[serde(rename = "zkBytecodeHash")]
    pub zk_bytecode_hash: Option<String>,
}

#[derive(Debug)]
pub struct ContractHashes {
    pub hashes: Vec<ContractHash>,
}

impl ContractHashes {
    /// Initializes the contract hashes by fetching and parsing the JSON from GitHub.
    pub async fn init_from_github(commit: &str) -> Self {
        let contents = Self::get_contents(commit).await;
        Self {
            hashes: serde_json::from_str(&contents)
                .expect("Failed to parse AllContractsHashes.json from GitHub"),
        }
    }

    async fn get_contents(commit: &str) -> String {
        get_contents_from_github(
            commit,
            "matter-labs/era-contracts",
            "AllContractsHashes.json",
        )
        .await
    }
}
