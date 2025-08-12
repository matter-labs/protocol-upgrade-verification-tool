use std::fmt::Display;

use alloy::{
    hex,
    primitives::{Address, Bytes, U256},
    sol,
};

use crate::utils::address_from_short_hex;

const L2_GENESIS_UPGRADE_ADDR: u32 = 0x10001;

sol! {
    #[derive(Debug, Hash, Eq, PartialEq)]
    struct ForceDeployment {
        bytes32 bytecodeHash;
        address newAddress;
        bool callConstructor;
        uint256 value;
        bytes input;
    }

    #[derive(Debug)]
    struct ForceDeployAndUpgradeInput {
        ForceDeployment[] _forceDeployments;
        address _delegateTo;
        bytes _calldata;
    }

    function forceDeployAndUpgrade(
        ForceDeployment[] _forceDeployments,
        address _delegateTo,
        bytes _calldata
    ) external payable;

    interface IL2V29Upgrade {
        function upgrade(address _aliasedGovernance, bytes32 _bridgedEthAssetId) external;
    }
}

impl Display for ForceDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Force deploy: {} to {}",
            self.bytecodeHash, self.newAddress
        )
    }
}

pub fn expected_force_deployments() -> Vec<(String, Address, bool)> {
    vec![
        (
            "system-contracts/EmptyContract".into(),
            address_from_short_hex("0"),
            false,
        ),
        ("Ecrecover".into(), address_from_short_hex("1"), false),
        ("SHA256".into(), address_from_short_hex("2"), false),
        ("Identity".into(), address_from_short_hex("4"), false),
        ("EcAdd".into(), address_from_short_hex("6"), false),
        ("EcMul".into(), address_from_short_hex("7"), false),
        ("EcPairing".into(), address_from_short_hex("8"), false),
        ("Modexp".into(), address_from_short_hex("5"), false),
        // Note: deploy `EmptyContract` into the bootloader address.
        (
            "system-contracts/EmptyContract".into(),
            address_from_short_hex("8001"),
            false,
        ),
        (
            "system-contracts/AccountCodeStorage".into(),
            address_from_short_hex("8002"),
            false,
        ),
        (
            "system-contracts/NonceHolder".into(),
            address_from_short_hex("8003"),
            false,
        ),
        (
            "system-contracts/KnownCodesStorage".into(),
            address_from_short_hex("8004"),
            false,
        ),
        (
            "system-contracts/ImmutableSimulator".into(),
            address_from_short_hex("8005"),
            false,
        ),
        (
            "system-contracts/ContractDeployer".into(),
            address_from_short_hex("8006"),
            false,
        ),
        // We deploy nothing to the 8007 address.
        (
            "system-contracts/L1Messenger".into(),
            address_from_short_hex("8008"),
            false,
        ),
        (
            "system-contracts/MsgValueSimulator".into(),
            address_from_short_hex("8009"),
            false,
        ),
        (
            "system-contracts/L2BaseToken".into(),
            address_from_short_hex("800a"),
            false,
        ),
        (
            "system-contracts/SystemContext".into(),
            address_from_short_hex("800b"),
            false,
        ),
        (
            "system-contracts/BootloaderUtilities".into(),
            address_from_short_hex("800c"),
            false,
        ),
        ("EventWriter".into(), address_from_short_hex("800d"), false),
        (
            "system-contracts/Compressor".into(),
            address_from_short_hex("800e"),
            false,
        ),
        (
            "system-contracts/ComplexUpgrader".into(),
            address_from_short_hex("800f"),
            false,
        ),
        ("Keccak256".into(), address_from_short_hex("8010"), false),
        ("CodeOracle".into(), address_from_short_hex("8012"), false),
        (
            "EvmGasManager".into(),
            address_from_short_hex("8013"),
            false,
        ),
        (
            "system-contracts/EvmPredeploysManager".into(),
            address_from_short_hex("8014"),
            false,
        ),
        (
            "system-contracts/EvmHashesStorage".into(),
            address_from_short_hex("8015"),
            false,
        ),
        ("P256Verify".into(), address_from_short_hex("100"), false),
        (
            "system-contracts/PubdataChunkPublisher".into(),
            address_from_short_hex("8011"),
            false,
        ),
        (
            "system-contracts/Create2Factory".into(),
            address_from_short_hex("10000"),
            false,
        ),
        (
            "system-contracts/SloadContract".into(),
            address_from_short_hex("10006"),
            false,
        ),
        (
            "system-contracts/L2InteropRootStorage".into(),
            address_from_short_hex("10008"),
            false,
        ),
        (
            "l1-contracts/Bridgehub".into(),
            address_from_short_hex("10002"),
            false,
        ),
        (
            "l1-contracts/L2AssetRouter".into(),
            address_from_short_hex("10003"),
            false,
        ),
        (
            "l1-contracts/L2NativeTokenVault".into(),
            address_from_short_hex("10004"),
            false,
        ),
        (
            "l1-contracts/MessageRoot".into(),
            address_from_short_hex("10005"),
            false,
        ),
        (
            "l1-contracts/L2WrappedBaseToken".into(),
            address_from_short_hex("10007"),
            false,
        ),
        (
            "l1-contracts/L2MessageVerification".into(),
            address_from_short_hex("10009"),
            false,
        ),
        (
            "l1-contracts/ChainAssetHandler".into(),
            address_from_short_hex("1000a"),
            true,
        ),
        (
            "system-contracts/L2V29Upgrade".into(),
            address_from_short_hex("10001"),
            false,
        ),
    ]
}

pub fn verify_force_deployments_and_upgrade(
    complex_upgrade_call: &forceDeployAndUpgradeCall,
    upgrade_calldata: IL2V29Upgrade::upgradeCall,
    expected_deployments: &[(String, Address, bool)],
    verifiers: &crate::verifiers::Verifiers,
    result: &mut crate::verifiers::VerificationResult,
    expected_governance: Address,
    expected_asset_id: [u8; 32],
    l1_chain_id: u64,
    owner_address: Address,
) -> anyhow::Result<()> {
    if complex_upgrade_call._forceDeployments.len() != expected_deployments.len() {
        result.report_error(&format!(
            "Expected {} force deployments, got {}",
            expected_deployments.len(),
            complex_upgrade_call._forceDeployments.len()
        ));
    }

    for (force_deployment, (contract, expected_address, expected_constructor)) in
        complex_upgrade_call
            ._forceDeployments
            .iter()
            .zip(expected_deployments.iter())
    {
        if &force_deployment.newAddress != expected_address {
            result.report_error(&format!(
                "Expected force deployment for {} to be at {}, got {}",
                contract, expected_address, force_deployment.newAddress
            ));
            continue;
        }

        // Address is as expected, so check the bytecode and constructor.
        result.expect_zk_bytecode(verifiers, &force_deployment.bytecodeHash, &contract);

        if &force_deployment.callConstructor != expected_constructor {
            result.report_error(&format!(
                "Expected force deployment for {} to have constructor {}, got {}",
                contract, expected_constructor, force_deployment.callConstructor
            ));
        }
        if force_deployment.value != U256::ZERO {
            result.report_error(&format!(
                "Force deployment for {} should not have value",
                contract
            ));
        }
        if !force_deployment.input.is_empty() {
            if contract != "l1-contracts/ChainAssetHandler" {
                result.report_error(&format!(
                    "Force deployment for {} should not have input",
                    contract
                ));
            } else {
                let encoded_chain_asset_handler_input = encode_chain_asset_handler_input(
                    U256::from(l1_chain_id),
                    owner_address,
                    address_from_short_hex("10002"),
                    address_from_short_hex("10003"),
                    address_from_short_hex("10005"),
                );
                let encoded_chain_asset_handler_input_bytes =
                    Bytes::from(encoded_chain_asset_handler_input.to_vec());

                if force_deployment.input != encoded_chain_asset_handler_input_bytes {
                    result.report_error(&format!(
                        "Expected for chain asset handler is {} but received {}.",
                        encoded_chain_asset_handler_input, force_deployment.input
                    ));
                }
            }
        }
    }

    // Check for extra deployments beyond expected count
    if complex_upgrade_call._forceDeployments.len() > expected_deployments.len() {
        let extra_start = expected_deployments.len();
        for extra in &complex_upgrade_call._forceDeployments[extra_start..] {
            result.report_error(&format!(
                "Extra force deployment found at address {} with bytecode hash {}",
                extra.newAddress,
                hex::encode(&extra.bytecodeHash)
            ));
        }
    }

    result.report_ok("Force deployments verified");

    if complex_upgrade_call._delegateTo != convert_u32_to_address(L2_GENESIS_UPGRADE_ADDR) {
        result.report_error(&format!(
            "Expected delegate_to to be L2_GENESIS_UPGRADE_ADDR, got {}",
            complex_upgrade_call._delegateTo
        ));
    }

    if upgrade_calldata._aliasedGovernance != expected_governance {
        result.report_error(&format!(
            "Unexpected aliased governance: expected {}, got {}",
            expected_governance, upgrade_calldata._aliasedGovernance
        ));
    }

    if upgrade_calldata._bridgedEthAssetId != expected_asset_id {
        result.report_error(&format!(
            "Unexpected bridgedEthAssetId: expected {:?}, got {:?}",
            expected_asset_id, upgrade_calldata._bridgedEthAssetId
        ));
    }

    Ok(())
}

fn convert_u32_to_address(val: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[16..20].copy_from_slice(&val.to_be_bytes());
    Address::from_slice(&bytes)
}

fn encode_chain_asset_handler_input(
    chain_id: U256,
    owner: Address,
    bridgehub: Address,
    asset_router: Address,
    message_root: Address,
) -> Bytes {
    let mut encoded = Vec::with_capacity(160);

    encoded.extend_from_slice(&chain_id.to_be_bytes::<32>());

    fn pad_address(addr: &Address) -> [u8; 32] {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(addr.as_slice());
        padded
    }

    encoded.extend_from_slice(&pad_address(&owner));
    encoded.extend_from_slice(&pad_address(&bridgehub));
    encoded.extend_from_slice(&pad_address(&asset_router));
    encoded.extend_from_slice(&pad_address(&message_root));

    Bytes::from(encoded)
}
