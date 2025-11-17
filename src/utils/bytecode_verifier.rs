use alloy::hex::{self, FromHex};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use alloy::sol_types::SolValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use alloy::sol;

use super::{
    address_from_short_hex, compute_create2_address_zk, compute_hash_with_arguments,
    get_contents_from_github,
};

sol! {
    #[derive(Debug, PartialEq, Eq, Hash)]
    struct ZKsyncOSBytecodeInfo {
        bytes32 evmDeployedBytecodeBlakeHash;
        uint256 zkSyncOSBytecodeLength;
        bytes32 evmDeployedBytecodeHash;
    }

    struct ZKSyncOSSystemProxyUpgradeBytecodeInfo {
        bytes implementationBytecodeInfo;
        bytes systemProxyBytecodeInfo;
    }
}

impl ZKsyncOSBytecodeInfo {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let decoded: ZKsyncOSBytecodeInfo = <ZKsyncOSBytecodeInfo as SolValue>::abi_decode(bytes, true)?;
        Ok(decoded)
    }
}

impl ZKSyncOSSystemProxyUpgradeBytecodeInfo {
    pub fn from_encoded_tuple(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut offset = [0u8; 32];
        offset[31] = 0x20; // offset to the data starts at byte 32 

        let mut new_encoded = vec![];
        new_encoded.extend_from_slice(&offset); // offset
        new_encoded.extend_from_slice(bytes);

        // When encoding a struct (unlike a tuple), Solidity prepends 32 bytes indicating the offset to the data.
        let decoded: ZKSyncOSSystemProxyUpgradeBytecodeInfo = <ZKSyncOSSystemProxyUpgradeBytecodeInfo as SolValue>::abi_decode(&new_encoded, true)?;
        Ok(decoded)
    }
}

pub struct BytecodeVerifier {
    /// Maps init bytecode hash to the corresponding file name.
    init_bytecode_file_by_hash: HashMap<FixedBytes<32>, String>,
    /// Maps deployed bytecode hash to the corresponding file name.
    deployed_bytecode_file_by_hash: HashMap<FixedBytes<32>, String>,
    /// Maps zk bytecode hash to the corresponding file name.
    zk_bytecode_file_by_hash: HashMap<FixedBytes<32>, String>,
    /// Maps a contract’s file name to its zk bytecode hash.
    bytecode_file_to_zkhash: HashMap<String, FixedBytes<32>>,
    /// Maps a contract’s file name to its zksync os bytecode info
    bytecode_file_to_zksync_os_info: HashMap<String, ZKsyncOSBytecodeInfo>,
    /// Maps a contract’s file name to its zksync os bytecode info
    deployed_bytecode_file_by_zksync_os_info: HashMap<ZKsyncOSBytecodeInfo, String>,

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
        const HEX: &str = "60a060405234801561000f575f5ffd5b506040516102ba3803806102ba83398101604081905261002e9161012e565b5f828451602086015ff590506001600160a01b0381166100945760405162461bcd60e51b815260206004820152601960248201527f437265617465323a204661696c6564206f6e206465706c6f7900000000000000604482015260640160405180910390fd5b60405163f2fde38b60e01b81526001600160a01b03838116600483015282169063f2fde38b906024015f604051808303815f87803b1580156100d4575f5ffd5b505af11580156100e6573d5f5f3e3d5ffd5b505050506001600160a01b0316608052506101f6915050565b634e487b7160e01b5f52604160045260245ffd5b80516001600160a01b0381168114610129575f5ffd5b919050565b5f5f5f60608486031215610140575f5ffd5b83516001600160401b03811115610155575f5ffd5b8401601f81018613610165575f5ffd5b80516001600160401b0381111561017e5761017e6100ff565b604051601f8201601f19908116603f011681016001600160401b03811182821017156101ac576101ac6100ff565b6040528181528282016020018810156101c3575f5ffd5b8160208401602083015e5f60209282018301529086015190945092506101ed905060408501610113565b90509250925092565b60805160af61020b5f395f602e015260af5ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c80638efc30f914602a575b5f5ffd5b60507f000000000000000000000000000000000000000000000000000000000000000081565b60405173ffffffffffffffffffffffffffffffffffffffff909116815260200160405180910390f3fea26469706673582212204790878030b8f9899988ec7ff21f52b7357315e02259a95c70257f5fd432c08b64736f6c634300081c0033";
        let bytecode =
            hex::decode(HEX).expect("Invalid hex encoding for create2 and transfer bytecode");

        // Cross-check the resulting bytecode hash against the expected file name.
        let hash = keccak256(&bytecode);
        let expected_file = "l1-contracts/Create2AndTransfer";
        let actual_file = self
            .evm_init_bytecode_hash_to_file(&hash)
            .expect("Missing mapping for create2 and transfer bytecode");
        // If this fails, then you have to update the 'HEX' from above - by taking it from the l1-contracts/out/Create2AndTransfer.sol directory.
        // Take 'bytecode.object' value.
        assert_eq!(
            actual_file, expected_file,
            "Bytecode file mismatch for create2 and transfer"
        );

        bytecode
    }

    /// Checks whether the provided `slice` starts with the create2 and transfer bytecode.
    ///
    /// If so, returns the remainder of the slice (after the prefix).
    pub fn is_create2_and_transfer_bytecode_prefix<'a>(&self, slice: &'a [u8]) -> Option<&'a [u8]> {
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
    pub fn evm_init_bytecode_hash_to_file(
        &self,
        bytecode_hash: &FixedBytes<32>,
    ) -> Option<&String> {
        self.init_bytecode_file_by_hash.get(bytecode_hash)
    }

    /// Returns the file name corresponding to the given deployed bytecode hash.
    pub fn evm_deployed_bytecode_hash_to_file(
        &self,
        bytecode_hash: &FixedBytes<32>,
    ) -> Option<&String> {
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

    /// Returns the file name corresponding to the given zk bytecode hash.
    pub fn zksync_os_bytecode_info_to_file(&self, bytecode_info: &ZKsyncOSBytecodeInfo) -> Option<&String> {
        self.deployed_bytecode_file_by_zksync_os_info.get(bytecode_info)
    }

    /// Returns the zk bytecode hash that corresponds to the file
    pub fn file_to_zksync_os_bytecode_info(&self, file: &str) -> Option<&ZKsyncOSBytecodeInfo> {
        self.bytecode_file_to_zksync_os_info.get(file)
    }


    /// Inserts an entry for the given deployed bytecode hash and file name.
    pub fn insert_evm_deployed_bytecode_hash(
        &mut self,
        bytecode_hash: FixedBytes<32>,
        file: String,
    ) {
        self.deployed_bytecode_file_by_hash
            .insert(bytecode_hash, file);
    }

    pub(crate) fn compute_expected_address_for_file(&self, file: &str) -> Address {
        let code = self
            .file_to_zk_bytecode_hash(file)
            .unwrap_or_else(|| panic!("Bytecode not found for file: {}", file));
        compute_create2_address_zk(
            // Create2Factory address
            address_from_short_hex("10000"),
            FixedBytes::ZERO,
            *code,
            keccak256([]),
        )
    }

    /// Initializes the verifier from contract hashes obtained from GitHub.
    pub async fn init_from_github(commit: &str) -> Self {
        let mut init_bytecode_file_by_hash = HashMap::new();
        let mut deployed_bytecode_file_by_hash = HashMap::new();
        let mut bytecode_file_to_zkhash = HashMap::new();
        let mut zk_bytecode_file_by_hash = HashMap::new();
        let mut bytecode_file_to_zksync_os_info = HashMap::new();
        let mut deployed_bytecode_file_by_zksync_os_info = HashMap::new();

        let contract_hashes = ContractHashes::init_from_github(commit).await;
        for contract in contract_hashes.hashes {

            if let Some(ref evm_info) = contract.evm_bytecode_info {
                init_bytecode_file_by_hash
                    .insert(evm_info.bytecode_hash, contract.contract_name.clone());

                deployed_bytecode_file_by_hash
                    .insert(evm_info.deployed_bytecode_hash, contract.contract_name.clone());

                
                let info = ZKsyncOSBytecodeInfo {
                    evmDeployedBytecodeBlakeHash: evm_info.deployed_blake_hash,
                    zkSyncOSBytecodeLength: U256::from(evm_info.deployed_length),
                    evmDeployedBytecodeHash: evm_info.deployed_bytecode_hash,
                };

                bytecode_file_to_zksync_os_info.insert(contract.contract_name.clone(), info.clone());
                deployed_bytecode_file_by_zksync_os_info.insert(info.clone(), contract.contract_name.clone());
            }

            if let Some(ref zk_info) = contract.zk_bytecode_info {
                bytecode_file_to_zkhash.insert(
                    contract.contract_name.clone(),
                    zk_info.zk_bytecode_hash,
                );
                zk_bytecode_file_by_hash
                    .insert(zk_info.zk_bytecode_hash, contract.contract_name.clone());
            }
        }

        // Create2Factory
        deployed_bytecode_file_by_hash.insert(
            FixedBytes::<32>::from_hex(
                "0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989",
            )
            .unwrap(),
            "Create2Factory".to_string(),
        );
        // TransparentProxyAdmin
        deployed_bytecode_file_by_hash.insert(
            FixedBytes::<32>::from_hex(
                "0x1d8a3e7186b2285da5ef3ccf4c63a672e91873f2ffdec522a241f72bfcab11c5",
            )
            .unwrap(),
            "TransparentProxyAdmin".to_string(),
        );
        // Hash of the proxy admin used for stage proofs
        // https://sepolia.etherscan.io/address/0x93AEeE8d98fB0873F8fF595fDd534A1f288786D2
        deployed_bytecode_file_by_hash.insert(
            FixedBytes::<32>::from_hex(
                "1e651120773914ac75c42598ceac4da0dc3e21709d438937f742ecf916ac30ae",
            )
            .unwrap(),
            "TransparentProxyAdmin".to_string(),
        );

        Self {
            init_bytecode_file_by_hash,
            deployed_bytecode_file_by_hash,
            zk_bytecode_file_by_hash,
            bytecode_file_to_zkhash,
            bytecode_file_to_zksync_os_info,
            deployed_bytecode_file_by_zksync_os_info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractHashRaw {
    #[serde(rename = "contractName")]
    pub contract_name: String,
    #[serde(rename = "evmBytecodeHash")]
    pub evm_bytecode_hash: Option<String>,
    #[serde(rename = "evmDeployedBytecodeHash")]
    pub evm_deployed_bytecode_hash: Option<String>,
    #[serde(rename = "zkBytecodeHash")]
    pub zk_bytecode_hash: Option<String>,
    #[serde(rename = "evmDeployedBytecodeBlakeHash")]
    pub evm_deployed_bytecode_blake_hash: Option<String>,
    #[serde(rename = "evmDeployedBytecodeLength")]
    pub evm_deployed_bytecode_length: Option<u64>,
}

#[derive(Debug)]
pub struct EvmBytecodeInfo {
    pub bytecode_hash: FixedBytes<32>,
    pub deployed_bytecode_hash: FixedBytes<32>,
    pub deployed_blake_hash: FixedBytes<32>,
    pub deployed_length: u64,
}

#[derive(Debug)]
pub struct ZKBytecodeInfo {
    pub zk_bytecode_hash: FixedBytes<32>,
}

#[derive(Debug)]
pub struct ContractHash {
    pub contract_name: String,
    pub evm_bytecode_info: Option<EvmBytecodeInfo>,
    pub zk_bytecode_info: Option<ZKBytecodeInfo>,
}

impl From<ContractHashRaw> for ContractHash {
    fn from(raw: ContractHashRaw) -> Self {
        let evm_bytecode_info = if let (Some(evm_hash), Some(deployed_hash), Some(blake_hash), Some(length)) = (
            raw.evm_bytecode_hash,
            raw.evm_deployed_bytecode_hash,
            raw.evm_deployed_bytecode_blake_hash,
            raw.evm_deployed_bytecode_length,
        ) {
            let decoded_evm_hash = hex::decode(evm_hash).expect("Invalid hex in evm_bytecode_hash");
            let decoded_deployed_hash =
                hex::decode(deployed_hash).expect("Invalid hex in evm_deployed_bytecode_hash");
            let decoded_blake_hash =
                hex::decode(blake_hash).expect("Invalid hex in evm_deployed_bytecode_blake_hash");

            Some(EvmBytecodeInfo {
                bytecode_hash: FixedBytes::try_from(decoded_evm_hash.as_slice())
                    .expect("Invalid length for FixedBytes (evm_bytecode_hash)"),
                deployed_bytecode_hash: FixedBytes::try_from(decoded_deployed_hash.as_slice())
                    .expect("Invalid length for FixedBytes (evm_deployed_bytecode_hash)"),
                deployed_blake_hash: FixedBytes::try_from(decoded_blake_hash.as_slice())
                    .expect("Invalid length for FixedBytes (evm_deployed_bytecode_blake_hash)"),
                deployed_length: length,
            })
        } else {
            None
        };

        let zk_bytecode_info = if let Some(zk_hash) = raw.zk_bytecode_hash {
            let decoded = hex::decode(zk_hash).expect("Invalid hex in zk_bytecode_hash");
            Some(ZKBytecodeInfo {
                zk_bytecode_hash: FixedBytes::try_from(decoded.as_slice())
                    .expect("Invalid length for FixedBytes (zk_bytecode_hash)"),
            })
        } else {
            None
        };

        Self {
            contract_name: raw.contract_name,
            evm_bytecode_info,
            zk_bytecode_info,
        }
    }
}

#[derive(Debug)]
pub struct ContractHashes {
    pub hashes: Vec<ContractHash>,
}

impl ContractHashes {
    /// Initializes the contract hashes by fetching and parsing the JSON from GitHub.
    pub async fn init_from_github(commit: &str) -> Self {
        let contents = Self::get_contents(commit).await;

        let raw_hashes: Vec<ContractHashRaw> =
            serde_json::from_str(&contents).expect("Failed to parse AllContractsHashes.json from GitHub");

        Self {
                    hashes: raw_hashes.into_iter().map(ContractHash::from).collect(),
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
