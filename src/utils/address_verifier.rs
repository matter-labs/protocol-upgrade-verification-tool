use alloy::primitives::{map::HashMap, Address};

use crate::UpgradeOutput;

use super::{
    apply_l2_to_l1_alias, bytecode_verifier::BytecodeVerifier, network_verifier::{self, NetworkVerifier},
};

pub struct AddressVerifier {
    pub address_to_name: HashMap<Address, String>,
    pub name_to_address: HashMap<String, Address>,
}

impl AddressVerifier {
    pub async fn new(
        _bridgehub_addr: Address,
        network_verifier: &NetworkVerifier,
        _bytecode_verifier: &BytecodeVerifier,
        config: &UpgradeOutput,
        bridgehub_addr: Address,
    ) -> Self {
        let mut result = Self {
            address_to_name: Default::default(),
            name_to_address: Default::default(),
        };

        // Firstly, we initialize some constant addresses from the config.

        result.add_address(Address::ZERO, "zero");


        config.add_to_verifier(&mut result, &network_verifier, bridgehub_addr).await;

        result
    }

    pub fn reverse_lookup(&self, address: &Address) -> Option<&String> {
        self.address_to_name.get(address)
    }

    pub fn name_or_unknown(&self, address: &Address) -> String {
        match self.address_to_name.get(address) {
            Some(name) => name.clone(),
            None => format!("Unknown {}", address),
        }
    }

    pub fn add_address(&mut self, address: Address, name: &str) {
        self.name_to_address.insert(name.to_string(), address);
        self.address_to_name.insert(address, name.to_string());
    }
}
