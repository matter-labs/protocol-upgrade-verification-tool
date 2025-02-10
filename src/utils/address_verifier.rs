use alloy::primitives::{map::HashMap, Address};

use crate::UpgradeOutput;

use super::{
    apply_l2_to_l1_alias, bytecode_verifier::BytecodeVerifier, network_verifier::NetworkVerifier,
};

pub struct AddressVerifier {
    pub address_to_name: HashMap<Address, String>,
    pub name_to_address: HashMap<String, Address>,
}

impl AddressVerifier {
    pub async fn new(
        bridgehub_addr: Address,
        network_verifier: &NetworkVerifier,
        bytecode_verifier: &BytecodeVerifier,
        config: &UpgradeOutput,
    ) -> Self {
        let mut result = Self {
            address_to_name: Default::default(),
            name_to_address: Default::default(),
        };

        // Firstly, we initialize some constant addresses from the config.
        result.add_address(
            config.protocol_upgrade_handler_impl_address,
            "new_protocol_upgrade_handler_impl",
        );
        result.add_address(
            config.protocol_upgrade_handler_proxy_address,
            "protocol_upgrade_handler_proxy",
        );
        result.add_address(
            apply_l2_to_l1_alias(config.protocol_upgrade_handler_proxy_address),
            "aliased_protocol_upgrade_handler_proxy",
        );
        result.add_address(
            bytecode_verifier
                .compute_expected_address_for_file("l1-contracts/L2SharedBridgeLegacy"),
            "l2_shared_bridge_legacy_impl",
        );
        result.add_address(
            bytecode_verifier
                .compute_expected_address_for_file("l1-contracts/BridgedStandardERC20"),
            "erc20_bridged_standard",
        );
        result.add_address(
            bytecode_verifier.compute_expected_address_for_file("l2-contracts/RollupL2DAValidator"),
            "rollup_l2_da_validator",
        );
        result.add_address(
            bytecode_verifier
                .compute_expected_address_for_file("l2-contracts/ValidiumL2DAValidator"),
            "validium_l2_da_validator",
        );

        config.add_to_verifier(&mut result);
        result.add_address(
            network_verifier
                .get_proxy_admin(config.protocol_upgrade_handler_proxy_address)
                .await,
            "protocol_upgrade_handler_transparent_proxy_admin",
        );

        // Now, we append the bridgehub info
        let info = network_verifier.get_bridgehub_info(bridgehub_addr).await;

        result.add_address(bridgehub_addr, "bridgehub_proxy");
        result.add_address(info.stm_address, "state_transition_manager");
        result.add_address(info.transparent_proxy_admin, "transparent_proxy_admin");
        result.add_address(info.shared_bridge, "old_shared_bridge_proxy");
        result.add_address(info.legacy_bridge, "legacy_erc20_bridge_proxy");
        result.add_address(info.validator_timelock, "old_validator_timelock");

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
