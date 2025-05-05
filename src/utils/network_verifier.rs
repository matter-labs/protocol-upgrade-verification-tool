use alloy::consensus::Transaction;
use alloy::hex::FromHex;
use alloy::primitives::{keccak256, Address, FixedBytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::transports::http::Http;
use reqwest::Client;
use std::collections::HashMap;

use crate::UpgradeOutput;

use super::bytecode_verifier::BytecodeVerifier;
use super::compute_create2_address_evm;

sol! {
    #[sol(rpc)]
    contract Bridgehub {
        address public sharedBridge;
        address public admin;
        address public owner;
        mapping(uint256 _chainId => address) public chainTypeManager;
        function getHyperchain(uint256 _chainId) external view returns (address chainAddress);
        function getAllZKChainChainIDs() external view returns (uint256[] memory);
        function assetRouter() external view returns (address);
        function getZKChain(uint256 _chainId) external view returns (address chainAddress);
    }

    #[sol(rpc)]
    contract L1AssetRouter {
        function legacyBridge() public returns (address);
        function L1_WETH_TOKEN() public returns (address);
        function L1_NULLIFIER() public returns (address);

        function nativeTokenVault() public returns (address);
    }

    #[sol(rpc)]
    contract ChainTypeManager {
        function getHyperchain(uint256 _chainId) public view returns (address);
        address public validatorTimelock;
    }

    function create2AndTransferParams(bytes memory bytecode, bytes32 salt, address owner);
}

const EIP1967_PROXY_ADMIN_SLOT: &str =
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

#[derive(Debug)]
pub struct BridgehubInfo {
    pub shared_bridge: Address,
    pub legacy_bridge: Address,
    pub stm_address: Address,
    pub transparent_proxy_admin: Address,
    pub l1_weth_token_address: Address,
    pub ecosystem_admin: Address,
    pub bridgehub_addr: Address,
    pub validator_timelock: Address,
    pub era_address: Address,
    pub native_token_vault: Address,
    pub l1_nullifier: Address,
    pub l1_asset_router_proxy_addr: Address,
}

pub struct NetworkVerifier {
    pub l1_provider: RootProvider<Http<Client>>,
    pub l2_chain_id: u64,
    pub l1_chain_id: u64,

    // todo: maybe merge into one struct.
    pub create2_known_bytecodes: HashMap<Address, String>,
    pub create2_constructor_params: HashMap<Address, Vec<u8>>,
}

impl NetworkVerifier {
    pub async fn new(
        l1_rpc: String,
        l2_chain_id: u64,
        bytecode_verifier: &BytecodeVerifier,
        config: &UpgradeOutput,
    ) -> Self {
        let l1_provider = ProviderBuilder::new().on_http(l1_rpc.parse().unwrap());

        Self {
            l1_chain_id: l1_provider.get_chain_id().await.unwrap(),
            l1_provider,
            l2_chain_id,
            create2_constructor_params: HashMap::default(),
            create2_known_bytecodes: HashMap::default(),
        }
    }

    pub fn get_era_chain_id(&self) -> u64 {
        self.l2_chain_id
    }

    pub fn get_l1_chain_id(&self) -> u64 {
        self.l1_chain_id
    }

    pub async fn get_bytecode_hash_at(&self, address: &Address) -> FixedBytes<32> {
        let code = self.l1_provider.get_code_at(*address).await.unwrap();
        if code.len() == 0 {
            // If address has no bytecode - we return formal 0s.
            FixedBytes::ZERO
        } else {
            keccak256(&code)
        }
    }

    pub async fn get_chain_diamond_proxy(&self, stm_addr: Address, era_chain_id: u64) -> Address {
        let ctm = ChainTypeManager::new(stm_addr, self.l1_provider.clone());

        ctm.getHyperchain(U256::from(era_chain_id))
            .call()
            .await
            .unwrap()
            ._0
    }

    pub async fn storage_at(&self, address: &Address, key: &FixedBytes<32>) -> FixedBytes<32> {
        let storage = self
            .l1_provider
            .get_storage_at(*address, U256::from_be_bytes(key.0))
            .await
            .unwrap();

        FixedBytes::from_slice(&storage.to_be_bytes_vec())
    }

    pub async fn get_storage_at(&self, address: &Address, key: u8) -> FixedBytes<32> {
        let storage = self
            .l1_provider
            .get_storage_at(*address, U256::from(key))
            .await
            .unwrap();

        FixedBytes::from_slice(&storage.to_be_bytes_vec())
    }

    pub fn get_l1_provider(&self) -> RootProvider<Http<Client>> {
        self.l1_provider.clone()
    }

    pub async fn get_proxy_admin(&self, addr: Address) -> Address {
        let addr_as_bytes = self
            .storage_at(
                &addr,
                &FixedBytes::<32>::from_hex(EIP1967_PROXY_ADMIN_SLOT).unwrap(),
            )
            .await;
        Address::from_slice(&addr_as_bytes[12..])
    }

    pub async fn get_bridgehub_info(&self, bridgehub_addr: Address) -> BridgehubInfo {
        let bridgehub = Bridgehub::new(bridgehub_addr, self.get_l1_provider());

        let shared_bridge_address = bridgehub.sharedBridge().call().await.unwrap().sharedBridge;

        let shared_bridge = L1AssetRouter::new(shared_bridge_address, self.get_l1_provider());

        let era_chain_id = self.get_era_chain_id();

        let stm_address = bridgehub
            .chainTypeManager(era_chain_id.try_into().unwrap())
            .call()
            .await
            .unwrap()
            ._0;
        let chain_type_manager = ChainTypeManager::new(stm_address, self.get_l1_provider());
        let era_address = chain_type_manager
            .getHyperchain(U256::from(era_chain_id))
            .call()
            .await
            .unwrap()
            ._0;
        let validator_timelock = chain_type_manager
            .validatorTimelock()
            .call()
            .await
            .unwrap()
            .validatorTimelock;

        let ecosystem_admin = bridgehub.admin().call().await.unwrap().admin;

        let transparent_proxy_admin = self.get_proxy_admin(bridgehub_addr).await;

        let legacy_bridge = shared_bridge.legacyBridge().call().await.unwrap()._0;
        let l1_weth_token_address = shared_bridge.L1_WETH_TOKEN().call().await.unwrap()._0;

        let native_token_vault = shared_bridge.nativeTokenVault().call().await.unwrap()._0;
        let l1_nullifier = shared_bridge.L1_NULLIFIER().call().await.unwrap()._0;

        let l1_asset_router_proxy_addr = bridgehub.assetRouter().call().await.unwrap()._0;

        BridgehubInfo {
            shared_bridge: shared_bridge_address,
            legacy_bridge,
            stm_address,
            transparent_proxy_admin,
            l1_weth_token_address,
            ecosystem_admin,
            bridgehub_addr,
            validator_timelock,
            era_address,
            native_token_vault,
            l1_nullifier,
            l1_asset_router_proxy_addr,
        }
    }
}

/// Fetches the `transaction` and tries to parse it as a CREATE2 deployment
/// transaction.
/// If successful, it returns a tuple of three items: the address of the deployed contract,
/// the path to the contract and its constructor params.
async fn check_create2_deploy(
    l1_provider: RootProvider<Http<Client>>,
    transaction: &str,
    expected_create2_address: &Address,
    expected_create2_salt: &FixedBytes<32>,
    bytecode_verifier: &BytecodeVerifier,
) -> Option<(Address, String, Vec<u8>)> {
    let tx_hash: TxHash = transaction.parse().unwrap();

    let tx = l1_provider
        .get_transaction_by_hash(tx_hash)
        .await
        .unwrap()
        .unwrap();

    if tx.to() != Some(*expected_create2_address) {
        return None;
    }

    // There are two types of CREATE2 deployments that were used:
    // - Usual, using CREATE2Factory directly.
    // - By using the `Create2AndTransfer` contract.
    // We will try both here.

    let salt = &tx.input()[0..32];
    if salt != expected_create2_salt.as_slice() {
        println!("Salt mismatch: {:?} != {:?}", salt, expected_create2_salt);
        return None;
    }

    if let Some((name, params)) = bytecode_verifier.try_parse_bytecode(&tx.input()[32..]) {
        let addr = compute_create2_address_evm(
            tx.to().unwrap(),
            FixedBytes::<32>::from_slice(salt),
            keccak256(&tx.input()[32..]),
        );
        return Some((addr, name, params));
    };

    let bytecode_input = &tx.input()[32..];

    // Okay, this may be the `Create2AndTransfer` method.
    if let Some(create2_and_transfer_input) =
        bytecode_verifier.is_create2_and_transfer_bytecode_prefix(bytecode_input)
    {
        let x = create2AndTransferParamsCall::abi_decode_raw(create2_and_transfer_input, false)
            .unwrap();
        if salt != x.salt.as_slice() {
            println!("Salt mismatch: {:?} != {:?}", salt, x.salt);
            return None;
        }
        // We do not need to cross check `owner` here, it will be cross checked against whatever owner is currently set
        // to the final contracts.
        // We do still need to check the input to find out potential constructor param
        let (name, params) = bytecode_verifier.try_parse_bytecode(&x.bytecode)?;
        let salt = FixedBytes::<32>::from_slice(salt);
        let create2_and_transfer_addr =
            compute_create2_address_evm(tx.to().unwrap(), salt, keccak256(&tx.input()[32..]));

        let contract_addr =
            compute_create2_address_evm(create2_and_transfer_addr, salt, keccak256(&x.bytecode));

        return Some((contract_addr, name, params));
    }

    None
}
