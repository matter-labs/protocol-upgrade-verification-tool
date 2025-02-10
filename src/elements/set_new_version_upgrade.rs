use std::collections::HashSet;

use alloy::{
    primitives::{Address, FixedBytes, U256},
    sol,
};

use crate::get_expected_new_protocol_version;

use super::{
    post_upgrade_calldata::PostUpgradeCalldata, protocol_version::ProtocolVersion,
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
        address verifier;
        VerifierParams verifierParams;
        bytes l1ContractsUpgradeCalldata;
        bytes postUpgradeCalldata;
        uint256 upgradeTimestamp;
        uint256 newProtocolVersion;
    }

    #[derive(Debug)]
    function upgrade(ProposedUpgrade calldata _proposedUpgrade) {
        // Implementation omitted.
    }

    #[sol(rpc)]
    contract BytecodesSupplier {
        mapping(bytes32 bytecodeHash => uint256 blockNumber) public publishingBlock;
    }
}

impl upgradeCall {} // Placeholder implementation.

const EXPECTED_BYTECODES: [&str; 41] = [
    "CodeOracle.yul",
    "EcAdd.yul",
    "EcMul.yul",
    "EcPairing.yul",
    "Ecrecover.yul",
    "EventWriter.yul",
    "Keccak256.yul",
    "P256Verify.yul",
    "SHA256.yul",
    "proved_batch.yul",
    "l1-contracts/BeaconProxy",
    "l1-contracts/BridgedStandardERC20",
    "l1-contracts/Bridgehub",
    "l1-contracts/L2AssetRouter",
    "l1-contracts/L2NativeTokenVault",
    "l1-contracts/L2SharedBridgeLegacy",
    "l1-contracts/L2WrappedBaseToken",
    "l1-contracts/MessageRoot",
    "l1-contracts/UpgradeableBeacon",
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
    "system-contracts/ImmutableSimulator",
    "system-contracts/KnownCodesStorage",
    "system-contracts/L1Messenger",
    "system-contracts/L2BaseToken",
    "system-contracts/L2GatewayUpgrade",
    "system-contracts/L2GenesisUpgrade",
    "system-contracts/MsgValueSimulator",
    "system-contracts/NonceHolder",
    "system-contracts/PubdataChunkPublisher",
    "system-contracts/SloadContract",
    "system-contracts/SystemContext",
    "system-contracts/TransparentUpgradeableProxy",
];

impl ProposedUpgrade {
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
            result.report_error("Minor protocol version mismatch");
        }
        if tx.value != U256::ZERO {
            result.report_error("Invalid value");
        }
        if tx.reserved != [U256::ZERO; 4] {
            result.report_error("Invalid reserved");
        }
        if !tx.data.is_empty() {
            result.report_error("Invalid data");
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

        let l1_provider = verifiers
            .network_verifier
            .get_l1_provider();
        let bytecodes_supplier = BytecodesSupplier::new(bytecodes_supplier_addr, l1_provider);

        let deps: Vec<FixedBytes<32>> = tx
            .factoryDeps
            .iter()
            .map(|dep| FixedBytes::<32>::from_slice(&dep.to_be_bytes::<32>()))
            .collect();

        // Use iter().copied() to initialize the HashSet.
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

        Ok(())
    }

    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bytecodes_supplier_addr: Address,
    ) -> anyhow::Result<()> {
        result.print_info("== checking chain upgrade init calldata ===");

        let expected_version = get_expected_new_protocol_version();
        let initial_error_count = result.errors;

        self.verify_transaction(verifiers, result, expected_version, bytecodes_supplier_addr)
            .await?;

        result.expect_zk_bytecode(verifiers, &self.bootloaderHash, "proved_batch.yul");
        result.expect_zk_bytecode(
            verifiers,
            &self.defaultAccountHash,
            "system-contracts/DefaultAccount",
        );

        let verifier_name = verifiers
            .address_verifier
            .address_to_name
            .get(&self.verifier)
            .cloned()
            .unwrap_or_else(|| format!("Unknown: {}", self.verifier));
        if verifier_name != "verifier" {
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

        let post_upgrade_calldata = PostUpgradeCalldata::parse(&self.postUpgradeCalldata)?;
        post_upgrade_calldata.verify(verifiers, result).await?;

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
        } else {
            anyhow::bail!(
                "{} errors found in the upgrade information",
                result.errors - initial_error_count
            );
        }

        Ok(())
    }
}
