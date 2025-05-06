
use std::any;

use super::{
    call_list::{Call, CallList},
    fixed_force_deployment::FixedForceDeploymentsData,
    set_new_version_upgrade::{self, setNewVersionUpgradeCall},
};
use crate::{
    elements::{initialize_data_new_chain::InitializeDataNewChain, ContractsConfig},
    get_expected_new_protocol_version, get_expected_old_protocol_version,
    utils::{encode_asset_id, facet_cut_set::{self, FacetCutSet, FacetInfo}, fixed_bytes20_to_32},
    verifiers::Verifiers,
};
use alloy::{
    dyn_abi::abi, hex, primitives::{ruint::aliases::U256, Address, Bytes, Uint}, sol, sol_types::{SolCall, SolValue}
};
use anyhow::Context;


sol!{

    /// @notice The struct that describes whether users will be charged for pubdata for L1->L2 transactions.
    /// @param Rollup The users are charged for pubdata & it is priced based on the gas price on Ethereum.
    /// @param Validium The pubdata is considered free with regard to the L1 gas price.
    enum PubdataPricingMode {
        Rollup,
        Validium
    }

    /// @notice The fee params for L1->L2 transactions for the network.
    /// @param pubdataPricingMode How the users will charged for pubdata in L1->L2 transactions.
    /// @param batchOverheadL1Gas The amount of L1 gas required to process the batch (except for the calldata).
    /// @param maxPubdataPerBatch The maximal number of pubdata that can be emitted per batch.
    /// @param priorityTxMaxPubdata The maximal amount of pubdata a priority transaction is allowed to publish.
    /// It can be slightly less than maxPubdataPerBatch in order to have some margin for the bootloader execution.
    /// @param minimalL2GasPrice The minimal L2 gas price to be used by L1->L2 transactions. It should represent
    /// the price that a single unit of compute costs.
    struct FeeParams {
        PubdataPricingMode pubdataPricingMode;
        uint32 batchOverheadL1Gas;
        uint32 maxPubdataPerBatch;
        uint32 maxL2GasPerBatch;
        uint32 priorityTxMaxPubdata;
        uint64 minimalL2GasPrice;
    }

    struct VerifierParams {
        bytes32 recursionNodeLevelVkHash;
        bytes32 recursionLeafLevelVkHash;
        bytes32 recursionCircuitsSetVksHash;
    }
    
    /// @notice Configuration parameters for deploying the GatewayCTMDeployer contract.
    struct GatewayCTMDeployerConfig {
        /// @notice Address of the aliased governance contract.
        address aliasedGovernanceAddress;
        /// @notice Salt used for deterministic deployments via CREATE2.
        bytes32 salt;
        /// @notice Chain ID of the Era chain.
        uint256 eraChainId;
        /// @notice Chain ID of the L1 chain.
        uint256 l1ChainId;
        /// @notice Address of the Rollup L2 Data Availability Validator.
        address rollupL2DAValidatorAddress;
        /// @notice Flag indicating whether to use the testnet verifier.
        bool testnetVerifier;
        /// @notice Array of function selectors for the Admin facet.
        bytes4[] adminSelectors;
        /// @notice Array of function selectors for the Executor facet.
        bytes4[] executorSelectors;
        /// @notice Array of function selectors for the Mailbox facet.
        bytes4[] mailboxSelectors;
        /// @notice Array of function selectors for the Getters facet.
        bytes4[] gettersSelectors;
        /// @notice Parameters for the verifier contract.
        VerifierParams verifierParams;
        /// @notice Parameters related to fees.
        /// @dev They are mainly related to the L1->L2 transactions, fees for
        /// which are not processed on Gateway. However, we still need these
        /// values to deploy new chain's instances on Gateway.
        FeeParams feeParams;
        /// @notice Hash of the bootloader bytecode.
        bytes32 bootloaderHash;
        /// @notice Hash of the default account bytecode.
        bytes32 defaultAccountHash;
        /// @notice Hash of the EVM emulator bytecode.
        bytes32 evmEmulatorHash;
        /// @notice Maximum gas limit for priority transactions.
        uint256 priorityTxMaxGasLimit;
        /// @notice Root hash of the genesis state.
        bytes32 genesisRoot;
        /// @notice Leaf index in the genesis rollup.
        uint256 genesisRollupLeafIndex;
        /// @notice Commitment of the genesis batch.
        bytes32 genesisBatchCommitment;
        /// @notice Data for force deployments.
        bytes forceDeploymentsData;
        /// @notice The latest protocol version.
        uint256 protocolVersion;
    }
}

impl GatewayCTMDeployerConfig {
    pub fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        // TODO: verify all the fields provided here
        Ok(())
    }
}
