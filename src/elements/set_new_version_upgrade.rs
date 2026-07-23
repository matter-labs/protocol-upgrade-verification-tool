use std::collections::HashSet;

use alloy::{
    primitives::{Address, FixedBytes, U256},
    sol,
    sol_types::SolCall,
};
use anyhow::Context;

use crate::get_expected_new_protocol_version;

use super::{
    force_deployment::{
        expected_force_deployments, forceDeployOnAddressesCall, verify_force_deployments,
    },
    protocol_version::ProtocolVersion,
};

const DEPLOYER_SYSTEM_CONTRACT: u32 = 0x8006;
const FORCE_DEPLOYER_ADDRESS: u32 = 0x8007;

sol! {
    #[derive(Debug)]
    enum Action {
        Add,
        Replace,
        Remove
    }

    #[derive(Debug)]
    struct FacetCut {
        address facet;
        Action action;
        bool isFreezable;
        bytes4[] selectors;
    }

    #[derive(Debug)]
    struct DiamondCutData {
        FacetCut[] facetCuts;
        address initAddress;
        bytes initCalldata;
    }

    function setNewVersionUpgrade(
        DiamondCutData diamondCut,
        uint256 oldProtocolVersion,
        uint256 oldProtocolVersionDeadline,
        uint256 newProtocolVersion
    );

    #[derive(Debug)]
    struct VerifierParams {
        bytes32 recursionNodeLevelVkHash;
        bytes32 recursionLeafLevelVkHash;
        bytes32 recursionCircuitsSetVksHash;
    }

    #[derive(Debug)]
    struct L2CanonicalTransaction {
        uint256 txType;
        uint256 from;
        uint256 to;
        uint256 gasLimit;
        uint256 gasPerPubdataByteLimit;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        uint256 paymaster;
        uint256 nonce;
        uint256 value;
        // In the future, we might want to add some
        // new fields to the struct. The `txData` struct
        // is to be passed to account and any changes to its structure
        // would mean a breaking change to these accounts. To prevent this,
        // we should keep some fields as "reserved"
        // It is also recommended that their length is fixed, since
        // it would allow easier proof integration (in case we will need
        // some special circuit for preprocessing transactions)
        uint256[4] reserved;
        bytes data;
        bytes signature;
        uint256[] factoryDeps;
        bytes paymasterInput;
        // Reserved dynamic type for the future use-case. Using it should be avoided,
        // But it is still here, just in case we want to enable some additional functionality
        bytes reservedDynamic;
    }

    #[derive(Debug)]
    struct ProposedUpgrade {
        L2CanonicalTransaction l2ProtocolUpgradeTx;
        bytes32 bootloaderHash;
        bytes32 defaultAccountHash;
        bytes32 evmEmulatorHash;
        address verifier;
        VerifierParams verifierParams;
        bytes l1ContractsUpgradeCalldata;
        bytes postUpgradeCalldata;
        uint256 upgradeTimestamp;
        uint256 newProtocolVersion;
    }

    #[derive(Debug)]
    function upgrade(ProposedUpgrade calldata _proposedUpgrade);

    #[sol(rpc)]
    contract BytecodesSupplier {
        mapping(bytes32 bytecodeHash => uint256 blockNumber) public publishingBlock;
    }
}

impl upgradeCall {} // Placeholder implementation.

const EXPECTED_BYTECODES: [&str; 44] = [
    "Bootloader",
    "CodeOracle",
    "EcAdd",
    "EcMul",
    "EcPairing",
    "Modexp",
    "Ecrecover",
    "EventWriter",
    "Keccak256",
    "P256Verify",
    "SHA256",
    "EvmEmulator",
    "Identity",
    "EvmGasManager",
    "l1-contracts/BridgedStandardERC20",
    "l1-contracts/Bridgehub",
    "l1-contracts/L2AssetRouter",
    "l1-contracts/L2NativeTokenVault",
    "l1-contracts/L2SharedBridgeLegacy",
    "l1-contracts/L2WrappedBaseToken",
    "l1-contracts/MessageRoot",
    "l1-contracts/DiamondProxy",
    "l2-contracts/RollupL2DAValidator",
    "l2-contracts/ValidiumL2DAValidator",
    "system-contracts/AccountCodeStorage",
    "system-contracts/BootloaderUtilities",
    "system-contracts/ComplexUpgrader",
    "system-contracts/Compressor",
    "system-contracts/ContractDeployer",
    "system-contracts/Create2Factory",
    "system-contracts/DefaultAccount",
    "system-contracts/EmptyContract",
    "system-contracts/EvmPredeploysManager",
    "system-contracts/EvmHashesStorage",
    "system-contracts/ImmutableSimulator",
    "system-contracts/KnownCodesStorage",
    "system-contracts/L1Messenger",
    "system-contracts/L2BaseToken",
    "system-contracts/L2GenesisUpgrade",
    "system-contracts/MsgValueSimulator",
    "system-contracts/NonceHolder",
    "system-contracts/PubdataChunkPublisher",
    "system-contracts/SloadContract",
    "system-contracts/SystemContext",
];

impl ProposedUpgrade {
    /// Verifies a verifier-only upgrade's ProposedUpgrade structure.
    ///
    /// In a verifier-only upgrade:
    /// - bootloaderHash should be zero (not updated)
    /// - defaultAccountHash should be zero (not updated)
    /// - evmEmulatorHash should be zero (not updated)
    /// - verifier should be set to the new verifier address
    /// - verifierParams should be zero
    /// - l1ContractsUpgradeCalldata should be empty
    /// - postUpgradeCalldata should be empty
    /// - The L2 protocol upgrade transaction should have no factory deps and empty calldata
    pub async fn verify_verifier_only(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        is_gateway: bool,
    ) -> anyhow::Result<()> {
        result.print_info("== checking verifier-only upgrade ProposedUpgrade ===");

        let expected_version = get_expected_new_protocol_version();
        let initial_error_count = result.errors;

        // Verify the L2 protocol upgrade transaction for verifier-only
        let tx = &self.l2ProtocolUpgradeTx;

        // For verifier-only upgrade, the transaction should be no-op, i.e. 0.
        if tx.txType != U256::ZERO {
            result.report_warn(&format!(
                "txType is {} (expected 254 for PRIORITY_OP_TX_TYPE) - may be expected for verifier-only",
                tx.txType
            ));
        }
        // Nonce should match minor version, but this may differ for verifier-only upgrades
        if tx.nonce != U256::ZERO {
            result.report_warn(&format!(
                "Minor protocol version in tx.nonce mismatch: {} vs {} - may be expected for verifier-only",
                tx.nonce, expected_version.minor
            ));
        }
        if tx.value != U256::ZERO {
            result.report_error("Invalid value");
        }
        if tx.reserved != [U256::ZERO; 4] {
            result.report_error("Invalid reserved");
        }
        if !tx.signature.is_empty() {
            result.report_error("Invalid signature");
        }
        if !tx.paymasterInput.is_empty() {
            result.report_error("Invalid paymasterInput");
        }
        if !tx.reservedDynamic.is_empty() {
            result.report_error("Invalid reservedDynamic");
        }

        // For verifier-only upgrade, there should be no factory deps
        if !tx.factoryDeps.is_empty() {
            result.report_error(&format!(
                "Verifier-only upgrade should have no factory deps, but found {}",
                tx.factoryDeps.len()
            ));
        } else {
            result.report_ok("No factory deps (verifier-only)");
        }

        // Verify bytecode hashes are zero (not updating system contracts)
        let zero_hash: FixedBytes<32> = FixedBytes::ZERO;
        if self.bootloaderHash != zero_hash {
            result.report_error("bootloaderHash should be zero for verifier-only upgrade");
        } else {
            result.report_ok("bootloaderHash is zero (verifier-only)");
        }

        if self.defaultAccountHash != zero_hash {
            result.report_error("defaultAccountHash should be zero for verifier-only upgrade");
        } else {
            result.report_ok("defaultAccountHash is zero (verifier-only)");
        }

        if self.evmEmulatorHash != zero_hash {
            result.report_error("evmEmulatorHash should be zero for verifier-only upgrade");
        } else {
            result.report_ok("evmEmulatorHash is zero (verifier-only)");
        }

        // Verify verifier address
        let verifier_name = verifiers
            .address_verifier
            .address_to_name
            .get(&self.verifier)
            .cloned()
            .unwrap_or_else(|| format!("Unknown: {}", self.verifier));

        let expected_name = if is_gateway {
            "gateway_verifier_addr"
        } else {
            "verifier"
        };

        if verifier_name != expected_name {
            result.report_error(&format!(
                "Invalid verifier: {} (expected {})",
                verifier_name, expected_name
            ));
        } else {
            result.report_ok(&format!("Verifier address is correct: {}", expected_name));
        }

        // Verifier params should be zero
        if self.verifierParams.recursionNodeLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionLeafLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionCircuitsSetVksHash != [0u8; 32]
        {
            result.report_error("Verifier params must be zero for verifier-only upgrade");
        } else {
            result.report_ok("Verifier params are zero");
        }

        // l1ContractsUpgradeCalldata should be empty
        if !self.l1ContractsUpgradeCalldata.is_empty() {
            result.report_error("l1ContractsUpgradeCalldata should be empty for verifier-only upgrade");
        } else {
            result.report_ok("l1ContractsUpgradeCalldata is empty");
        }

        // postUpgradeCalldata should be empty
        if !self.postUpgradeCalldata.is_empty() {
            result.report_error("postUpgradeCalldata should be empty for verifier-only upgrade");
        } else {
            result.report_ok("postUpgradeCalldata is empty");
        }

        // upgradeTimestamp should be zero
        if self.upgradeTimestamp != U256::default() {
            result.report_error("upgradeTimestamp must be zero");
        }

        // Verify protocol version
        let protocol_version = ProtocolVersion::from(self.newProtocolVersion);
        if protocol_version != expected_version {
            result.report_error(&format!(
                "Invalid protocol version: {}. Expected: {}",
                protocol_version, expected_version
            ));
        } else {
            result.report_ok(&format!("Protocol version is correct: {}", expected_version));
        }

        if initial_error_count == result.errors {
            result.report_ok("Verifier-only ProposedUpgrade is correct");
        }

        Ok(())
    }

    pub async fn verify_transaction(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        expected_version: ProtocolVersion,
        bytecodes_supplier_addr: Address,
    ) -> anyhow::Result<()> {
        let tx = &self.l2ProtocolUpgradeTx;

        if tx.txType != U256::from(254) {
            result.report_error("Invalid txType");
        }
        if tx.from != U256::from(FORCE_DEPLOYER_ADDRESS) {
            result.report_error("Invalid from");
        }
        if tx.to != U256::from(DEPLOYER_SYSTEM_CONTRACT) {
            result.report_error("Invalid to");
        }
        if tx.gasLimit != U256::from(72_000_000) {
            result.report_error("Invalid gasLimit");
        }
        if tx.gasPerPubdataByteLimit != U256::from(800) {
            result.report_error("Invalid gasPerPubdataByteLimit");
        }
        if tx.maxFeePerGas != U256::ZERO {
            result.report_error("Invalid maxFeePerGas");
        }
        if tx.maxPriorityFeePerGas != U256::ZERO {
            result.report_error("Invalid maxPriorityFeePerGas");
        }
        if tx.paymaster != U256::ZERO {
            result.report_error("Invalid paymaster");
        }
        if tx.nonce != U256::from(expected_version.minor) {
            result.report_error(&format!(
                "Minor protocol version mismatch: {} vs {} ",
                tx.nonce, expected_version.minor
            ));
        }
        if tx.value != U256::ZERO {
            result.report_error("Invalid value");
        }
        if tx.reserved != [U256::ZERO; 4] {
            result.report_error("Invalid reserved");
        }
        if !tx.signature.is_empty() {
            result.report_error("Invalid signature");
        }
        if !tx.paymasterInput.is_empty() {
            result.report_error("Invalid paymasterInput");
        }
        if !tx.reservedDynamic.is_empty() {
            result.report_error("Invalid reservedDynamic");
        }

        let l1_provider = verifiers.network_verifier.get_l1_provider();
        let bytecodes_supplier = BytecodesSupplier::new(bytecodes_supplier_addr, l1_provider);

        let deps: Vec<FixedBytes<32>> = tx
            .factoryDeps
            .iter()
            .map(|dep| FixedBytes::<32>::from_slice(&dep.to_be_bytes::<32>()))
            .collect();

        let mut expected_bytecodes: HashSet<&str> = EXPECTED_BYTECODES.iter().copied().collect();

        for dep in deps {
            let file_name = match verifiers.bytecode_verifier.zk_bytecode_hash_to_file(&dep) {
                Some(file) => file,
                None => {
                    result.report_error(&format!(
                        "Invalid dependency in factory deps – cannot find file for hash: {:?}",
                        dep
                    ));
                    continue;
                }
            };

            if !expected_bytecodes.contains(file_name.as_str()) {
                result.report_error(&format!(
                    "Unexpected dependency in factory deps: {}",
                    file_name
                ));
                continue;
            }

            expected_bytecodes.remove(file_name.as_str());

            // Check that the dependency has been published.
            let publishing_info = bytecodes_supplier
                .publishingBlock(dep)
                .call()
                .await
                .map_err(|e| anyhow::anyhow!("Error calling publishingBlock: {:?}", e))?;
            if publishing_info.blockNumber == U256::ZERO {
                result.report_error(&format!("Unpublished bytecode for {}", file_name));
            }
        }
        if !expected_bytecodes.is_empty() {
            result.report_error(&format!(
                "Missing dependencies in factory deps: {:?}",
                expected_bytecodes
            ));
        }
        // Check calldata.
        let calldata = forceDeployOnAddressesCall::abi_decode(&tx.data, true).unwrap();
        let expected_deployments = expected_force_deployments();
        verify_force_deployments(
            &calldata._deployParams,
            &expected_deployments,
            verifiers,
            result,
        )?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bytecodes_supplier_addr: Address,
        is_gateway: bool,
    ) -> anyhow::Result<()> {
        result.print_info("== checking chain upgrade init calldata ===");

        let expected_version = get_expected_new_protocol_version();
        let initial_error_count = result.errors;

        self.verify_transaction(verifiers, result, expected_version, bytecodes_supplier_addr)
            .await
            .context("upgrade tx")?;

        result.expect_zk_bytecode(verifiers, &self.bootloaderHash, "Bootloader");
        result.expect_zk_bytecode(
            verifiers,
            &self.defaultAccountHash,
            "system-contracts/DefaultAccount",
        );
        result.expect_zk_bytecode(verifiers, &self.evmEmulatorHash, "EvmEmulator");

        let verifier_name = verifiers
            .address_verifier
            .address_to_name
            .get(&self.verifier)
            .cloned()
            .unwrap_or_else(|| format!("Unknown: {}", self.verifier));

        let name = if is_gateway {
            "gateway_verifier_addr"
        } else {
            "verifier"
        };

        if verifier_name != name {
            result.report_error(&format!("Invalid verifier: {}", verifier_name));
        }

        // Verifier params should be zero - as everything is hardcoded within the verifier contract itself.
        if self.verifierParams.recursionNodeLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionLeafLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionCircuitsSetVksHash != [0u8; 32]
        {
            result.report_error("Verifier params must be empty.");
        }

        if !self.l1ContractsUpgradeCalldata.is_empty() {
            result.report_error("l1ContractsUpgradeCalldata is not empty");
        }

        if self.postUpgradeCalldata.len() != 0 {
            result.report_error("Expected empty post upgrade calldata");
        }

        if self.upgradeTimestamp != U256::default() {
            result.report_error("Upgrade timestamp must be zero");
        }

        let protocol_version = ProtocolVersion::from(self.newProtocolVersion);
        if protocol_version != expected_version {
            result.report_error(&format!(
                "Invalid protocol version: {}. Expected: {}",
                protocol_version, expected_version
            ));
        }

        if initial_error_count == result.errors {
            result.report_ok("Proposed upgrade info is correct");
        }

        Ok(())
    }
}
