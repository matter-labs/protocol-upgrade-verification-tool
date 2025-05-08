use std::any;

use super::{
    call_list::{Call, CallList}, fixed_force_deployment::FixedForceDeploymentsData, gateway_state_transition::DualVerifier, set_new_version_upgrade::{self, setNewVersionUpgradeCall}
};
use crate::{
    elements::{initialize_data_new_chain::InitializeDataNewChain, ContractsConfig},
    get_expected_new_protocol_version, get_expected_old_protocol_version,
    utils::{
        compute_create2_factory_deployed_address_zk, encode_asset_id,
        facet_cut_set::{self, FacetCutSet, FacetInfo},
        fixed_bytes20_to_32,
    },
    verifiers::{VerificationResult, Verifiers},
};
use alloy::{
    dyn_abi::abi,
    hex,
    primitives::{keccak256, ruint::aliases::U256, Address, Bytes, FixedBytes, Uint},
    providers::Provider,
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::Context;

sol! {

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

    #[derive(Debug)]
    /// @notice Addresses of state transition related contracts.
    // solhint-disable-next-line gas-struct-packing
    struct StateTransitionContracts {
        /// @notice Address of the ChainTypeManager proxy contract.
        address chainTypeManagerProxy;
        /// @notice Address of the ChainTypeManager implementation contract.
        address chainTypeManagerImplementation;
        /// @notice Address of the Verifier contract.
        address verifier;
        /// @notice Address of the VerifierPlonk contract.
        address verifierPlonk;
        /// @notice Address of the VerifierFflonk contract.
        address verifierFflonk;
        /// @notice Address of the Admin facet contract.
        address adminFacet;
        /// @notice Address of the Mailbox facet contract.
        address mailboxFacet;
        /// @notice Address of the Executor facet contract.
        address executorFacet;
        /// @notice Address of the Getters facet contract.
        address gettersFacet;
        /// @notice Address of the DiamondInit contract.
        address diamondInit;
        /// @notice Address of the GenesisUpgrade contract.
        address genesisUpgrade;
        /// @notice Address of the ValidatorTimelock contract.
        address validatorTimelock;
        /// @notice Address of the ProxyAdmin for ChainTypeManager.
        address chainTypeManagerProxyAdmin;
        /// @notice Address of the ServerNotifier proxy contract.
        address serverNotifierProxy;
        /// @notice Address of the ServerNotifier implementation contract.
        address serverNotifierImplementation;
    }

    /// @notice Addresses of Data Availability (DA) related contracts.
    // solhint-disable-next-line gas-struct-packing
    #[derive(Debug)]
    struct DAContracts {
        /// @notice Address of the RollupDAManager contract.
        address rollupDAManager;
        /// @notice Address of the RelayedSLDAValidator contract.
        address relayedSLDAValidator;
        /// @notice Address of the ValidiumL1DAValidator contract.
        address validiumDAValidator;
    }

    #[derive(Debug)]
    /// @notice Collection of all deployed contracts by the GatewayCTMDeployer.
    struct DeployedContracts {
        /// @notice Address of the Multicall3 contract.
        address multicall3;
        /// @notice Struct containing state transition related contracts.
        StateTransitionContracts stateTransition;
        /// @notice Struct containing Data Availability related contracts.
        DAContracts daContracts;
        /// @notice Encoded data for the diamond cut operation.
        bytes diamondCutData;
    }

    #[sol(rpc)]
    contract GatewayCTMDeployer {
        /// @notice Returns deployed contracts.
        /// @dev Just using `public` mode for the `deployedContracts` field did not work
        /// due to internal issues during testing.
        /// @return contracts The struct with information about the deployed contracts.
        function getDeployedContracts() external view returns (DeployedContracts memory contracts) {
            contracts = deployedContracts;
        }
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

impl DeployedContracts {
    #[allow(clippy::too_many_lines)]
    pub fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        // ── top‑level ───────────────────────────────────────────────────────────
        // FIXME: this one is missing
        result.expect_address(verifiers, &self.multicall3, "multicall3_addr");

        // ── state‑transition contracts ─────────────────────────────────────────
        let st = &self.stateTransition;
        result.expect_address(
            verifiers,
            &st.chainTypeManagerProxy,
            "gateway_chain_type_manager_proxy_addr",
        );
        result.expect_address(
            verifiers,
            &st.chainTypeManagerImplementation,
            "gateway_chain_type_manager_implementation_addr",
        );
        result.expect_address(verifiers, &st.verifier, "gateway_verifier_addr");

        // Note, that we do not cross check verifierPlonk and Fflonk since these are in the constructor params of the Verifier
        // and so are implicitly checked already
        // FIXME: the below 2 are missing the output struct
        result.expect_address(verifiers, &st.verifierPlonk, "gateway_verifier_plonk_addr");
        result.expect_address(
            verifiers,
            &st.verifierFflonk,
            "gateway_verifier_fflonk_addr",
        );

        result.expect_address(verifiers, &st.adminFacet, "gateway_admin_facet_addr");
        result.expect_address(verifiers, &st.mailboxFacet, "gateway_mailbox_facet_addr");
        result.expect_address(verifiers, &st.executorFacet, "gateway_executor_facet_addr");
        result.expect_address(verifiers, &st.gettersFacet, "gateway_getters_facet_addr");
        result.expect_address(verifiers, &st.diamondInit, "gateway_diamond_init_addr");
        result.expect_address(
            verifiers,
            &st.genesisUpgrade,
            "gateway_genesis_upgrade_addr",
        );
        result.expect_address(
            verifiers,
            &st.validatorTimelock,
            "gateway_validator_timelock_addr",
        );

        // FIXME: the below 3 are missing
        result.expect_address(
            verifiers,
            &st.chainTypeManagerProxyAdmin,
            "gateway_chain_type_manager_proxy_admin_addr",
        );
        result.expect_address(
            verifiers,
            &st.serverNotifierProxy,
            "gateway_server_notifier",
        );
        result.expect_address(
            verifiers,
            &st.serverNotifierImplementation,
            "gateway_server_notifier_implementation_addr",
        );

        // ── data‑availability contracts ───────────────────────────────────────
        // all of the below are missing missing
        let da = &self.daContracts;
        result.expect_address(verifiers, &da.rollupDAManager, "gateway_rollup_da_manager");
        result.expect_address(
            verifiers,
            &da.relayedSLDAValidator,
            "relayed_sl_da_validator",
        );
        result.expect_address(
            verifiers,
            &da.validiumDAValidator,
            "validium_da_validator",
        );

        // NOTE: `diamondCutData` is raw bytes, not an address, so no check needed.

        Ok(())
    }
}

pub async fn verify_gateway_ctm_deployer(
    gateway_ctm_deployer_addr: Address,
    constructor_params: String,
    salt: FixedBytes<32>,
    verifiers: &Verifiers,
    result: &mut VerificationResult,
) -> anyhow::Result<()> {
    let gw_provider = verifiers.network_verifier.gw_provider.clone();

    // Firstly, let's double check that the code is expected.
    let gateway_ctm_deployer_bytecode = gw_provider.get_code_at(gateway_ctm_deployer_addr).await?;

    let constructor_params = hex::decode(&constructor_params).unwrap();

    let expected_address = compute_create2_factory_deployed_address_zk(
        salt,
        *verifiers
            .bytecode_verifier
            .file_to_zk_bytecode_hash("l1-contracts/GatewayCTMDeployer")
            .expect("Can not find l1-contracts/GatewayCTMDeployer"),
        keccak256(&constructor_params),
    );

    if expected_address != gateway_ctm_deployer_addr {
        result.report_error(&format!(
            "Unexpected address for GatewayCTMDeployer. Expected: {}, Found: {}",
            expected_address, gateway_ctm_deployer_addr
        ));
        return Ok(());
    }
    if gateway_ctm_deployer_bytecode.is_empty() {
        result.report_error(&format!("Bytecode at supposed GatewayCTMDeployer is empty"));
        return Ok(());
    }

    let config = GatewayCTMDeployerConfig::abi_decode(&constructor_params, true)?;

    config.verify(verifiers, result)?;

    let gateway_ctm_deployer_contract =
        GatewayCTMDeployer::new(gateway_ctm_deployer_addr, gw_provider.clone());
    let deployed_contracts = gateway_ctm_deployer_contract
        .getDeployedContracts()
        .call()
        .await?;

    deployed_contracts.contracts.verify(verifiers, result)?;

    Ok(())
}
