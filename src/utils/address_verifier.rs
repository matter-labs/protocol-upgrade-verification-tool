use alloy::primitives::{map::HashMap, Address};

pub enum FixedAddresses {
    _Bootloader = 0x8001,
    _NonceHolder = 0x8003,
    DeployerSystemContract = 0x8006,
    ForceDeployer = 0x8007,
}

#[derive(Default)]
pub struct AddressVerifier {
    pub address_to_name: HashMap<Address, String>,
    pub name_to_address: HashMap<String, Address>,
}

impl AddressVerifier {
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
        // TODO: accept that this should be empty.
        self.name_to_address.insert(name.to_string(), address);
        self.address_to_name.insert(address, name.to_string());
    }
}
