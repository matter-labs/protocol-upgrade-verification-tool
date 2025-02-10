use std::ops::Add;

use alloy::consensus::Transaction;
use alloy::hex::FromHex;
use alloy::primitives::map::HashMap;
use alloy::primitives::{keccak256, Address, FixedBytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::transports::http::Http;
use alloy::sol;
use alloy::sol_types::SolCall;
use reqwest::Client;

use super::bytecode_verifier::BytecodeVerifier;
use super::compute_create2_address_evm;

sol! {
    #[sol(rpc)]
    contract Bridgehub {
        address public sharedBridge;
        address public admin;
        address public owner;
        mapping(uint256 _chainId => address) public stateTransitionManager;
        function getHyperchain(uint256 _chainId) external view returns (address chainAddress);
    }

    #[sol(rpc)]
    contract L1SharedBridge {
        function legacyBridge() public returns (address);
        function L1_WETH_TOKEN() public returns (address);
    }
    
    #[sol(rpc)]
    contract ChainTypeManager {
        function getHyperchain(uint256 _chainId) public view returns (address);
    }

    function create2AndTransferParams(bytes memory bytecode, bytes32 salt, address owner);
}

const EIP1967_PROXY_ADMIN_SLOT: &str = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

#[derive(Debug)]
pub struct BridgehubInfo {
    pub shared_bridge: Address,
    pub legacy_bridge: Address,
    pub stm_address: Address,
    pub transparent_proxy_admin: Address,
    pub l1_weth_token_address: Address,
    pub ecosystem_admin: Address,
    pub bridgehub_addr: Address,
    pub era_address: Address
}

pub struct NetworkVerifier {
    pub l1_rpc: String,
    pub l2_chain_id: u64,

    // todo: maybe merge into one struct.
    pub create2_known_bytecodes: HashMap<Address, String>,
    pub create2_constructor_params: HashMap<Address, Vec<u8>>,
}

impl NetworkVerifier {
    pub fn new(l1_rpc: String, l2_chain_id: u64) -> Self {
        Self {
            l1_rpc,
            l2_chain_id,
            create2_constructor_params: Default::default(),
            create2_known_bytecodes: Default::default()
        }
    }

    pub async fn get_era_chain_id(&self) -> u64 {
        self.l2_chain_id
    }

    pub async fn get_l1_chain_id(&self) -> u64 {
        let provider = ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap());
        let chain_id = provider.get_chain_id().await.unwrap();
        chain_id
    }

    pub async fn get_bytecode_hash_at(&self, address: &Address) -> FixedBytes<32> {
        let provider = ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap());
        let code = provider.get_code_at(address.clone()).await.unwrap();
        if code.len() == 0 {
            // If address has no bytecode - we return formal 0s.
            FixedBytes::ZERO
        } else {
            keccak256(&code)
        }
    }

    pub async fn get_chain_diamond_proxy(&self, stm_addr: Address, era_chain_id: u64) -> Address {
        let provider = self.get_l1_provider();

        let ctm = ChainTypeManager::new(
            stm_addr,
            provider
        );
        let address = ctm.getHyperchain(U256::from(era_chain_id)).call().await.unwrap()._0;

        address
    }   

    pub async fn storage_at(
        &self,
        address: &Address,
        key: &FixedBytes<32>,
    ) -> FixedBytes<32> {
        let provider = ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap());

        let storage = provider
            .get_storage_at(address.clone(), U256::from_be_bytes(key.0))
            .await
            .unwrap();

        FixedBytes::from_slice(&storage.to_be_bytes_vec())
    }

    pub async fn get_storage_at(&self, address: &Address, key: u8) -> FixedBytes<32> {
        let provider = ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap());

        let storage = provider
            .get_storage_at(address.clone(), U256::from(key))
            .await
            .unwrap();

        FixedBytes::from_slice(&storage.to_be_bytes_vec())
    }

    pub fn get_l1_provider(&self) -> RootProvider<Http<Client>> {
        ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap())
    }

    pub async fn get_proxy_admin(&self, addr: Address) -> Address {
        let addr_as_bytes = self.storage_at(&addr, &FixedBytes::<32>::from_hex(EIP1967_PROXY_ADMIN_SLOT).unwrap()).await;
        Address::from_slice(&addr_as_bytes[12..])
    }

    pub async fn get_bridgehub_info(&self, bridgehub_addr: Address) -> BridgehubInfo {
        let provider = ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap());

        let bridgehub = Bridgehub::new(bridgehub_addr, provider.clone());

        let shared_bridge_address = bridgehub.sharedBridge().call().await.unwrap().sharedBridge;

        let shared_bridge = L1SharedBridge::new(shared_bridge_address, provider.clone());

        let era_chain_id = self.get_era_chain_id().await;

        let stm_address = 
                bridgehub
                    .stateTransitionManager(era_chain_id.try_into().unwrap())
                    .call()
                    .await
                    .unwrap()
                    ._0;
        let chain_type_manager = ChainTypeManager::new(stm_address, provider.clone());
        let era_address = chain_type_manager.getHyperchain(U256::from(era_chain_id)).call().await.unwrap()._0;

        let ecosystem_admin = bridgehub.admin().call().await.unwrap().admin;

        let transparent_proxy_admin = self.get_proxy_admin(bridgehub_addr).await;

        let legacy_bridge = shared_bridge.legacyBridge().call().await.unwrap()._0;
        let l1_weth_token_address = shared_bridge.L1_WETH_TOKEN().call().await.unwrap()._0;

        BridgehubInfo {
            shared_bridge: shared_bridge_address,
            legacy_bridge,
            stm_address,
            transparent_proxy_admin,
            l1_weth_token_address,
            ecosystem_admin,
            bridgehub_addr,
            era_address
        }
    }

    /// Fetches the `transaction` and tries to parse it as a CREATE2 deployment 
    /// transaction.
    /// If successful, it returns a tuple of three items: the address of the deployed contract,
    /// the path to the contract and its constructor params.
    pub async fn check_create2_deploy(
        &self,
        transaction: &str,
        expected_create2_address: &Address,
        expected_create2_salt: &FixedBytes<32>,
        bytecode_verifier: &BytecodeVerifier
    ) -> Option<(Address, String, Vec<u8>)> {
        let tx_hash: TxHash = transaction.parse().unwrap();
        let provider = ProviderBuilder::new().on_http(self.l1_rpc.parse().unwrap());

        let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await
            .unwrap()
            .unwrap();

        if tx.to() != Some(expected_create2_address.clone()) {
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
            let addr= compute_create2_address_evm(tx.to().unwrap(), FixedBytes::<32>::from_slice(salt), keccak256(&tx.input()[32..]));
            return Some((addr, name, params));
        };

        let bytecode_input = &tx.input()[32..];

        // Okay, this may be the `Create2AndTransfer` method.
        if let Some(create2_and_transfer_input) = bytecode_verifier.is_create2_and_transfer_bytecode_prefix(bytecode_input) {
            let x = create2AndTransferParamsCall::abi_decode_raw(create2_and_transfer_input, false).unwrap();
            if salt != x.salt.as_slice() {
                println!("Salt mismatch: {:?} != {:?}", salt, x.salt);
                return None;
            }
            // We do not need to cross check `owner` here, it will be cross checked against whatever owner is currently set 
            // to the final contracts.
            // We do still need to check the input to find out potential constructor param
            let (name, params) = bytecode_verifier.try_parse_bytecode(&x.bytecode)?;
            let salt = FixedBytes::<32>::from_slice(salt);
            let create2_and_transfer_addr = compute_create2_address_evm(tx.to().unwrap(), salt, keccak256(&tx.input()[32..]));
            
            let contract_addr = compute_create2_address_evm(create2_and_transfer_addr, salt, keccak256(&x.bytecode));

            return Some((contract_addr, name, params));
        }   

        None
    }
}
