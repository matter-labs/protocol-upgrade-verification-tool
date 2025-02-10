use alloy::{
    dyn_abi::SolType,
    hex::FromHex,
    primitives::{keccak256, Address, Bytes, FixedBytes, U256},
    sol,
};

use crate::utils::compute_create2_address_zk;
use super::{fixed_force_deployment::FixedForceDeploymentsData, force_deployment::ForceDeployment};

sol! {
    #[derive(Debug)]
    struct GatewayUpgradeEncodedInput {
        ForceDeployment[] forceDeployments;
        uint256 l2GatewayUpgradePosition;
        bytes fixedForceDeploymentsData;
        address ctmDeployer;
        address oldValidatorTimelock;
        address newValidatorTimelock;
        address wrappedBaseTokenStore;
    }
}

/// Contains the post-upgrade calldata.
pub struct PostUpgradeCalldata {
    pub gateway_upgrade_encoded_input: GatewayUpgradeEncodedInput,
}

/// Verifies that the provided force deployments match the expected parameters.
fn verify_force_deployments(
    force_deployments: &[ForceDeployment],
    expected_deployments: &[(&str, Address, bool)],
    verifiers: &crate::verifiers::Verifiers,
    result: &mut crate::verifiers::VerificationResult,
) -> anyhow::Result<()> {
    if force_deployments.len() != expected_deployments.len() {
        result.report_error(&format!(
            "Expected {} force deployments, got {}",
            expected_deployments.len(),
            force_deployments.len()
        ));
    }

    for (force_deployment, &(contract, expected_address, expected_constructor)) in
        force_deployments.iter().zip(expected_deployments.iter())
    {
        if force_deployment.newAddress != expected_address {
            result.report_error(&format!(
                "Expected force deployment for {} to be at {}, got {}",
                contract, expected_address, force_deployment.newAddress
            ));
            continue;
        } 

        // Address is as expected, so check the bytecode and constructor.
        result.expect_zk_bytecode(verifiers, &force_deployment.bytecodeHash, contract);

        if force_deployment.callConstructor != expected_constructor {
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
            result.report_error(&format!(
                "Force deployment for {} should not have input",
                contract
            ));
        }
    }

    result.report_ok("Force deployments verified");
    Ok(())
}

/// Converts a short hex string to an [Address] by left-padding it to 40 hex digits.
fn address_from_short_hex(hex: &str) -> Address {
    let padded_hex = format!("{:0>40}", hex);
    Address::from_hex(&format!("0x{}", padded_hex))
        .expect("Invalid hex address provided")
}

/// Computes the expected address for the file by reading its code hash and computing the create2 address.
pub(crate) fn compute_expected_address_for_file(
    verifiers: &crate::verifiers::Verifiers,
    file: &str,
) -> Address {
    let code = verifiers
        .bytecode_verifier
        .file_to_zk_bytecode_hash(file)
        .unwrap_or_else(|| panic!("Bytecode not found for file: {}", file));
    compute_create2_address_zk(
        // Create2Factory address
        address_from_short_hex("10000"),
        FixedBytes::ZERO,
        code.clone(),
        keccak256(&[]),
    )
}

impl PostUpgradeCalldata {
    /// Parses the provided ABI-encoded data into a [PostUpgradeCalldata].
    pub fn parse(data: &Bytes) -> anyhow::Result<Self> {
        let gateway_upgrade_encoded_input = GatewayUpgradeEncodedInput::abi_decode(data, true)
            .map_err(|e| anyhow::anyhow!("Failed to decode GatewayUpgradeEncodedInput: {:?}", e))?;
        Ok(Self {
            gateway_upgrade_encoded_input,
        })
    }

    /// Verifies the inner fields of the calldata.
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        // TODO: verify old timelock
        // TODO: verify gateway deployment position (what is this??)

        verify_force_deployments(
            &self.gateway_upgrade_encoded_input.forceDeployments,
            &[
                ("system-contracts/EmptyContract", address_from_short_hex("0"), false),
                ("Ecrecover.yul", address_from_short_hex("1"), false),
                ("SHA256.yul", address_from_short_hex("2"), false),
                ("EcAdd.yul", address_from_short_hex("6"), false),
                ("EcMul.yul", address_from_short_hex("7"), false),
                ("EcPairing.yul", address_from_short_hex("8"), false),
                // Note: deploy `EmptyContract` into the bootloader address.
                ("system-contracts/EmptyContract", address_from_short_hex("8001"), false),
                ("system-contracts/AccountCodeStorage", address_from_short_hex("8002"), false),
                ("system-contracts/NonceHolder", address_from_short_hex("8003"), false),
                ("system-contracts/KnownCodesStorage", address_from_short_hex("8004"), false),
                ("system-contracts/ImmutableSimulator", address_from_short_hex("8005"), false),
                ("system-contracts/ContractDeployer", address_from_short_hex("8006"), false),
                // We deploy nothing to the 8007 address.
                ("system-contracts/L1Messenger", address_from_short_hex("8008"), false),
                ("system-contracts/MsgValueSimulator", address_from_short_hex("8009"), false),
                ("system-contracts/L2BaseToken", address_from_short_hex("800a"), false),
                ("system-contracts/SystemContext", address_from_short_hex("800b"), false),
                ("system-contracts/BootloaderUtilities", address_from_short_hex("800c"), false),
                ("EventWriter.yul", address_from_short_hex("800d"), false),
                ("system-contracts/Compressor", address_from_short_hex("800e"), false),
                ("system-contracts/ComplexUpgrader", address_from_short_hex("800f"), false),
                ("Keccak256.yul", address_from_short_hex("8010"), false),
                ("CodeOracle.yul", address_from_short_hex("8012"), false),
                ("P256Verify.yul", address_from_short_hex("100"), false),
                ("system-contracts/PubdataChunkPublisher", address_from_short_hex("8011"), false),
                ("system-contracts/Create2Factory", address_from_short_hex("10000"), false),
                ("system-contracts/L2GenesisUpgrade", address_from_short_hex("10001"), false),
                ("system-contracts/SloadContract", address_from_short_hex("10006"), false),
                ("l1-contracts/Bridgehub", address_from_short_hex("10002"), false),
                ("l1-contracts/L2AssetRouter", address_from_short_hex("10003"), false),
                ("l1-contracts/L2NativeTokenVault", address_from_short_hex("10004"), false),
                ("l1-contracts/MessageRoot", address_from_short_hex("10005"), false),
                ("l1-contracts/L2WrappedBaseToken", address_from_short_hex("10007"), false),
                // Force deployments specific to this upgrade.
                (
                    "l1-contracts/L2SharedBridgeLegacy",
                    compute_expected_address_for_file(verifiers, "l1-contracts/L2SharedBridgeLegacy"),
                    true,
                ),
                (
                    "l1-contracts/BridgedStandardERC20",
                    compute_expected_address_for_file(verifiers, "l1-contracts/BridgedStandardERC20"),
                    true,
                ),
                (
                    "l2-contracts/RollupL2DAValidator", // Rollup DA validator.
                    compute_expected_address_for_file(verifiers, "l2-contracts/RollupL2DAValidator"),
                    true,
                ),
                (
                    "l2-contracts/ValidiumL2DAValidator", // Validium DA validator.
                    compute_expected_address_for_file(verifiers, "l2-contracts/ValidiumL2DAValidator"),
                    true,
                ),
                // Deploy the gateway upgrader, run its constructor, then re-deploy the complex upgrader.
                (
                    "system-contracts/L2GatewayUpgrade",
                    address_from_short_hex("800f"),
                    true,
                ),
                (
                    "system-contracts/ComplexUpgrader",
                    address_from_short_hex("800f"),
                    false,
                ),
            ],
            verifiers,
            result,
        )?;

        result.expect_address(
            verifiers,
            &self.gateway_upgrade_encoded_input.ctmDeployer,
            "ctm_deployment_tracker",
        );
        result.expect_address(
            verifiers,
            &self.gateway_upgrade_encoded_input.wrappedBaseTokenStore,
            "l2_wrapped_base_token_store",
        );
        result.expect_address(
            verifiers,
            &self.gateway_upgrade_encoded_input.newValidatorTimelock,
            "validator_timelock",
        );

        let fixed_force_deployments_data = FixedForceDeploymentsData::abi_decode(
            &self.gateway_upgrade_encoded_input.fixedForceDeploymentsData,
            true,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to decode FixedForceDeploymentsData: {:?}",
                e
            )
        })?;

        fixed_force_deployments_data.verify(verifiers, result).await?;

        Ok(())
    }
}
