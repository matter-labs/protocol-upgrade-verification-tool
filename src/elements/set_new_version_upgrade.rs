use std::collections::HashSet;

use alloy::{
    hex,
    primitives::{keccak256, Address, Bytes, FixedBytes, U256},
    sol,
    sol_types::{SolCall, SolType, SolValue},
};
use anyhow::Context;

use crate::{
    elements::force_deployment::IComplexUpgraderZKsyncOSV29, get_expected_new_protocol_version, utils::{address_from_short_hex, apply_l2_to_l1_alias}
};

use super::{
    force_deployment::{
        expected_force_deployments, forceDeployAndUpgradeCall,
        verify_force_deployments_and_upgrade, IL2V29Upgrade,
    },
    protocol_version::ProtocolVersion,
    V29,
};

const FORCE_DEPLOYER_ADDRESS: u32 = 0x8007;
const COMPLEX_UPGRADER_ADDRESS: u32 = 0x800F;

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

    struct AssetIdInput {
        uint256 chainId;
        address vaultAddr;
        address tokenAddr;
    }

    struct V29UpgradeParams {
        address[] oldValidatorTimelocks;
        address newValidatorTimelock;
    }

    function setUpgradeDiamondCut(DiamondCutData diamondCut, uint256 protocolVersion);
}

impl upgradeCall {} // Placeholder implementation.

const EXPECTED_BYTECODES: [&str; 48] = [
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
    "l1-contracts/L2MessageVerification",
    "l1-contracts/ChainAssetHandler",
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
    "system-contracts/L2V29Upgrade",
    "system-contracts/MsgValueSimulator",
    "system-contracts/NonceHolder",
    "system-contracts/ProxyAdmin",
    "system-contracts/PubdataChunkPublisher",
    "system-contracts/SloadContract",
    "system-contracts/SystemContext",
    "system-contracts/L2InteropRootStorage",
];

impl ProposedUpgrade {
    pub async fn verify_transaction(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        expected_version: ProtocolVersion,
        bytecodes_supplier_addr: Address,
        l1_chain_id: u64,
        owner_address: Address,
    ) -> anyhow::Result<()> {
        let tx = &self.l2ProtocolUpgradeTx;

        // not zksync os has different upgrade type
        if tx.txType != U256::from(126) {
            result.report_error("Invalid txType");
        }
        if tx.from != U256::from(FORCE_DEPLOYER_ADDRESS) {
            result.report_error("Invalid from");
        }
        if tx.to != U256::from(COMPLEX_UPGRADER_ADDRESS) {
            result.report_error(&format!("Invalid to: {:?}", tx.to));
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

        // let l1_provider = verifiers.network_verifier.get_l1_provider();
        // let bytecodes_supplier = BytecodesSupplier::new(bytecodes_supplier_addr, l1_provider);

        // let deps: Vec<FixedBytes<32>> = tx
        //     .factoryDeps
        //     .iter()
        //     .map(|dep| FixedBytes::<32>::from_slice(&dep.to_be_bytes::<32>()))
        //     .collect();

        // let mut expected_bytecodes: HashSet<&str> = EXPECTED_BYTECODES.iter().copied().collect();

        // for dep in deps {
        //     let file_name = match verifiers.bytecode_verifier.zk_bytecode_hash_to_file(&dep) {
        //         Some(file) => file,
        //         None => {
        //             result.report_error(&format!(
        //                 "Invalid dependency in factory deps – cannot find file for hash: {:?}",
        //                 dep
        //             ));
        //             continue;
        //         }
        //     };

        //     if !expected_bytecodes.contains(file_name.as_str()) {
        //         result.report_error(&format!(
        //             "Unexpected dependency in factory deps: {}",
        //             file_name
        //         ));
        //         continue;
        //     }

        //     expected_bytecodes.remove(file_name.as_str());

        //     // Check that the dependency has been published.
        //     let publishing_info = bytecodes_supplier
        //         .publishingBlock(dep)
        //         .call()
        //         .await
        //         .map_err(|e| anyhow::anyhow!("Error calling publishingBlock: {:?}", e))?;
        //     if publishing_info.blockNumber == U256::ZERO {
        //         result.report_error(&format!("Unpublished bytecode for {}", file_name));
        //     }
        // }
        // if !expected_bytecodes.is_empty() {
        //     result.report_error(&format!(
        //         "Missing dependencies in factory deps: {:?}",
        //         expected_bytecodes
        //     ));
        // }

        // Check calldata.
        let complex_upgrade_call = IComplexUpgraderZKsyncOSV29::forceDeployAndUpgradeUniversalCall::abi_decode(&tx.data, true).unwrap(); // TODO check if we need to verify complex upgrade?

        // FIXME: check the first call + address to delegate to.
        


        let Ok(upgrade_calldata) =
            IL2V29Upgrade::upgradeCall::abi_decode(complex_upgrade_call._calldata.as_ref(), true)
        else {
            result.report_error("Failed to decode delegate upgrade calldata");
            return Ok(());
        };

        let expected_governance = apply_l2_to_l1_alias(owner_address);
        let eth_token_address = address_from_short_hex("1");
        let expected_asset_id = encode_ntv_asset_id(l1_chain_id, eth_token_address);

        Ok(())
    }

    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bytecodes_supplier_addr: Address,
        l1_chain_id: u64,
        owner_address: Address,
        is_gateway: bool,
    ) -> anyhow::Result<()> {
        result.print_info("== checking chain upgrade init calldata ===");

        let expected_version = get_expected_new_protocol_version();
        let initial_error_count = result.errors;

        self.verify_transaction(
            verifiers,
            result,
            expected_version,
            bytecodes_supplier_addr,
            l1_chain_id,
            owner_address,
        )
        .await
        .context("upgrade tx")?;

        result.expected_zero_zk_bytecode(&self.bootloaderHash);
        result.expected_zero_zk_bytecode(
            &self.defaultAccountHash,
        );
        result.expected_zero_zk_bytecode(&self.evmEmulatorHash);

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

        if !self.postUpgradeCalldata.is_empty() {
            result.report_error("Expected post upgrade calldata to be empty");
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

fn encode_post_upgrade_calldata(
    old_validator_timelocks: Vec<Address>,
    new_validator_timelock: Address,
) -> Bytes {
    let params = V29UpgradeParams {
        oldValidatorTimelocks: old_validator_timelocks,
        newValidatorTimelock: new_validator_timelock,
    };

    Bytes::from(params.abi_encode())
}

fn encode_ntv_asset_id(chain_id: u64, token_address: Address) -> [u8; 32] {
    // L2 address of NTV is fixed
    let l2_native_token_vault_addr = address_from_short_hex("10004");

    let encoded = AssetIdInput {
        chainId: U256::from(chain_id),
        vaultAddr: l2_native_token_vault_addr,
        tokenAddr: token_address,
    }
    .abi_encode();

    keccak256(encoded).into()
}
