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

sol! {
    function setServerNotifier(address _serverNotifier) external;
}

pub struct EcosystemAdminCalls {
    pub calls: CallList,
}

pub struct GovernanceCalls {
    pub calls: CallList,
}

sol! {
    function upgrade(address proxy, address implementation);
    function upgradeAndCall(address proxy, address implementation, bytes data);
    function setAddresses(address _assetRouter, address _l1CtmDeployer, address _messageRoot);
    function setL1NativeTokenVault(address _l1NativeTokenVault);
    function setL1AssetRouter(address _l1AssetRouter);
    function setValidatorTimelock(address addr);
    function setProtocolVersionDeadline(uint256 protocolVersion, uint256 newDeadline);
    function updateDAPair(address l1_da_addr, address l2_da_addr, bool is_active);

    #[derive(Debug, PartialEq)]
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

    #[derive(Debug)]
    struct ChainCreationParams {
        address genesisUpgrade;
        bytes32 genesisBatchHash;
        uint64 genesisIndexRepeatedStorageChanges;
        bytes32 genesisBatchCommitment;
        DiamondCutData diamondCut;
        bytes forceDeploymentsData;
    }

    function setChainCreationParams(ChainCreationParams calldata _chainCreationParams);

    /// @notice Façet structure compatible with the EIP-2535 diamond loupe
    /// @param addr The address of the facet contract
    /// @param selectors The NON-sorted array with selectors associated with facet
    struct Facet {
        address addr;
        bytes4[] selectors;
    }

    function facets() external view returns (Facet[] memory result);

    function registerSettlementLayer(uint256 settlementLayerChainId, bool iaAllowed); 
    function approve(address toWhom, uint256 amount); 
    
    struct L2TransactionRequestDirectInput {
        uint256 chainId;
        uint256 mintValue;
        address l2Contract;
        uint256 l2Value;
        bytes l2Calldata;
        uint256 l2GasLimit;
        uint256 l2GasPerPubdataByteLimit;
        bytes[] factoryDeps;
        address refundRecipient;
    }

    function requestL2TransactionDirect(
        L2TransactionRequestDirectInput calldata _request
    ) external;

    function addChainTypeManager(address _chainTypeManager);
    
    function setAssetDeploymentTracker(
        bytes32 _assetRegistrationData,
        address _assetDeploymentTracker
    ) external;

    function registerCTMAssetOnL1(address _ctmAddress) external; 

    struct L2TransactionRequestTwoBridgesOuter {
        uint256 chainId;
        uint256 mintValue;
        uint256 l2Value;
        uint256 l2GasLimit;
        uint256 l2GasPerPubdataByteLimit;
        address refundRecipient;
        address secondBridgeAddress;
        uint256 secondBridgeValue;
        bytes secondBridgeCalldata;
    }

    function requestL2TransactionTwoBridges(
        L2TransactionRequestTwoBridgesOuter calldata _request
    ) external;

    struct SetAssetHandlerCounterpartData {
        bytes32 chainAssetId;
        address assetHandler;
    }

    struct CTMDeploymentTrackerSecondBridgeData {
        address l1CTMAddress;
        address gatewayCTMAddress;
    }

    function acceptOwnership() external;
}

const EXPECTED_L1_TO_L2_GAS_LIMIT: u64 = 72_000_000;
const EXPECTED_GAS_PER_PUBDATA: u64 = 800;

impl requestL2TransactionDirectCall {
    fn verify_basic_params(
        &self,
        result: &mut crate::verifiers::VerificationResult,
        expected_chain_id: U256,
        expected_refund_recipient: Address,
    ) {
        if self._request.chainId != expected_chain_id {
            result.report_error(&format!(
                "Invalid chainId for L1->L2 calls. Expected {}. Received: {}",
                expected_chain_id,
                self._request.chainId
            ));
        }

        if self._request.l2Value != U256::ZERO {
            result.report_error(&format!(
                "Invalid l2Value. Expected 0. Received: {}",
                self._request.l2Value
            ));
        }

        if self._request.l2GasLimit != U256::from(EXPECTED_L1_TO_L2_GAS_LIMIT) {
            result.report_error(&format!(
                "Invalid l2GasLimit. Expected {}. Received: {}",
                EXPECTED_L1_TO_L2_GAS_LIMIT, self._request.l2GasLimit
            ));
        }

        if self._request.l2GasPerPubdataByteLimit != U256::from(EXPECTED_GAS_PER_PUBDATA) {
            result.report_error(&format!(
                "Invalid l2GasPerPubdataByteLimit. Expected {}. Received: {}",
                EXPECTED_GAS_PER_PUBDATA, self._request.l2GasPerPubdataByteLimit
            ));
        }

        if !self._request.factoryDeps.is_empty() {
            result.report_error("factoryDeps should be empty.");
        }

        if self._request.refundRecipient != expected_refund_recipient {
            result.report_error(&format!(
                "Invalid refundRecipient. Expected {:?}. Received: {:?}",
                expected_refund_recipient,
                self._request.refundRecipient
            ));
        }

        // Note: We do not check `mintValue` here as it depends on L1 gas price.
        // It is assumed to be sufficiently funded and tested internally.
    }
}

impl requestL2TransactionTwoBridgesCall {
    fn verify_basic_params(
        &self,
        result: &mut crate::verifiers::VerificationResult,
        expected_chain_id: U256,
        expected_refund_recipient: Address,
    ) {
        if self._request.chainId != expected_chain_id {
            result.report_error(&format!(
                "Invalid chainId for L1->L2 calls. Expected {}. Received: {}",
                expected_chain_id,
                self._request.chainId
            ));
        }

        if self._request.l2Value != U256::ZERO {
            result.report_error(&format!(
                "Invalid l2Value. Expected 0. Received: {}",
                self._request.l2Value
            ));
        }

        if self._request.l2GasLimit != U256::from(EXPECTED_L1_TO_L2_GAS_LIMIT) {
            result.report_error(&format!(
                "Invalid l2GasLimit. Expected {}. Received: {}",
                EXPECTED_L1_TO_L2_GAS_LIMIT, self._request.l2GasLimit
            ));
        }

        if self._request.l2GasPerPubdataByteLimit != U256::from(EXPECTED_GAS_PER_PUBDATA) {
            result.report_error(&format!(
                "Invalid l2GasPerPubdataByteLimit. Expected {}. Received: {}",
                EXPECTED_GAS_PER_PUBDATA, self._request.l2GasPerPubdataByteLimit
            ));
        }

        if self._request.refundRecipient != expected_refund_recipient {
            result.report_error(&format!(
                "Invalid refundRecipient. Expected {:?}. Received: {:?}",
                expected_refund_recipient,
                self._request.refundRecipient
            ));
        }

        if self._request.secondBridgeValue != U256::ZERO {
            result.report_error(&format!(
                "Invalid secondBridgeValue. Expected 0. Received: {}",
                self._request.secondBridgeValue
            ));
        }

        // Note: We do not check `mintValue` or `secondBridgeValue` here, as they may depend
        // on L1 gas price and internal logic, and are assumed to be validated elsewhere.
    }
}

impl SetAssetHandlerCounterpartData {
    fn parse(bytes: Vec<u8>) -> anyhow::Result<Self> {
        const EXPECTED_ENCODING_VERSION: u8 = 2;

        if bytes.is_empty() {
            anyhow::bail!("Invalid SetAssetHandlerCounterpartData encoding");
        }

        let version = bytes[0];
        if version != EXPECTED_ENCODING_VERSION {
            anyhow::bail!("Invalid SetAssetHandlerCounterpartData version");
        }

        Ok(SetAssetHandlerCounterpartData::abi_decode(&bytes[1..], true)?)
    }
}

impl CTMDeploymentTrackerSecondBridgeData {
    fn parse(bytes: Vec<u8>) -> anyhow::Result<Self> {
        const EXPECTED_ENCODING_VERSION: u8 = 1;

        if bytes.is_empty() {
            anyhow::bail!("Invalid CTMDeploymentTrackerSecondBridgeData encoding");
        }

        let version = bytes[0];
        if version != EXPECTED_ENCODING_VERSION {
            anyhow::bail!("Invalid CTMDeploymentTrackerSecondBridgeData version");
        }

        Ok(CTMDeploymentTrackerSecondBridgeData::abi_decode(&bytes[1..], true)?)
    }
}


impl EcosystemAdminCalls {
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== Ecosystem Admin Calls ===");

        let list_of_calls = [
           // Set server notifier
           ("chain_type_manager_proxy_addr", "setServerNotifier(address)"),
           // Accept ownership
           ("server_notifier_addr", "acceptOwnership()")
        ];
        const SET_SERVER_NOTIFIER: usize = 0;

        // For calls without any params, we don't have to check
        // anything else.

        self.calls.verify(&list_of_calls, verifiers, result)?;

        // Verify setNewVersionUpgrade
        {
            let calldata = &self.calls.elems[SET_SERVER_NOTIFIER].data;
            let data = setServerNotifierCall::abi_decode(calldata, true).unwrap();

            result.expect_address(verifiers, &data._serverNotifier, "server_notifier_addr");
        }


        Ok(())
    }
}

impl GovernanceCalls {
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        l1_chain_id: u64,
        gateway_chain_id: u64,
        refund_recipient: Address
    ) -> anyhow::Result<()> {
        let list_of_calls = [
           // register settlement layer
           ("bridgehub_proxy_addr", "registerSettlementLayer(uint256,bool)"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Gateway Add Chain Type Manager
           ("bridgehub_proxy_addr", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
           // Set asset deployment tracker
           ("l1_asset_router_addr", "setAssetDeploymentTracker(bytes32,address)"),
           // Register CTM asset on L1
           ("ctm_deployment_tracker_proxy_addr", "registerCTMAssetOnL1(address)"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Set asset handler counterpart
           ("bridgehub_proxy_addr", "requestL2TransactionTwoBridges((uint256,uint256,uint256,uint256,uint256,address,address,uint256,bytes))"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Set address of GW Chaintype manager
           ("bridgehub_proxy_addr", "requestL2TransactionTwoBridges((uint256,uint256,uint256,uint256,uint256,address,address,uint256,bytes))"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Gateway Ownershup: RollupDAManager
           ("bridgehub_proxy_addr", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Gateway Ownershup: ValidatorTimelock
           ("bridgehub_proxy_addr", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Gateway Ownershup: ServerNotifier
           ("bridgehub_proxy_addr", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
           // Approve base token
           ("gateway_base_token_addr", "approve(address,uint256)"),
           // Gateway Update DA Pair
           ("bridgehub_proxy_addr", "requestL2TransactionDirect((uint256,uint256,address,uint256,bytes,uint256,uint256,bytes[],address))"),
        ];
        self.calls.verify(&list_of_calls, verifiers, result)?;

        let gateway_chain_id = U256::from(gateway_chain_id);
        let l1_ctm_address = verifiers.address_verifier.name_to_address["ctm_proxy_address"];
        let expected_asset_data = fixed_bytes20_to_32(l1_ctm_address.0);  

        let mut call_index = 0;
        // 0: registerSettlementLayer
        {
            let params = registerSettlementLayerCall::abi_decode(&self.calls.elems[call_index].data, true)?;

            if params.settlementLayerChainId != gateway_chain_id {
                result.report_error("Invalid Gateway chainId");
            }

            call_index+=1;
        }

        // 1: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;

            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 2: requestL2TransactionDirect
        {
            let params = requestL2TransactionDirectCall::abi_decode(&self.calls.elems[call_index].data, true)?;

            params.verify_basic_params(result, gateway_chain_id, refund_recipient);
            result.expect_address(verifiers, &params._request.l2Contract, "l2_bridgehub");

            let inner_params = addChainTypeManagerCall::abi_decode(&params._request.l2Calldata, true)?;

            result.expect_address(verifiers, &inner_params._chainTypeManager, "gw_ctm_address");

            call_index += 1;
        }

        // 3: setAssetDeploymentTracker
        {
            let params = setAssetDeploymentTrackerCall::abi_decode(&self.calls.elems[call_index].data, true)?;

            if params._assetRegistrationData != expected_asset_data {
                result.report_error(&format!("Unexpected asset registration data. Expected: {}, Received: {}", expected_asset_data, params._assetRegistrationData));
            }
            result.expect_address(verifiers, &params._assetDeploymentTracker, "l1_ctm_deployment_tracker");


            call_index += 1;
        }

        // 4: registerCTMAssetOnL1
        {
            let params = registerCTMAssetOnL1Call::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(verifiers, &params._ctmAddress, "ctm_proxy_address");

            call_index += 1;
        }

        // 5: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 6: requestL2TransactionTwoBridges
        {
            let params = requestL2TransactionTwoBridgesCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            params.verify_basic_params(result, gateway_chain_id, refund_recipient);

            result.expect_address(verifiers, &params._request.secondBridgeAddress, "l1_asset_router_proxy");

            let data = SetAssetHandlerCounterpartData::parse(params._request.secondBridgeCalldata.clone().into())?;
            result.expect_address(verifiers, &data.assetHandler, "l2_bridgehub");

            let expected_asset_id = encode_asset_id(
                U256::from(l1_chain_id),
                expected_asset_data,
                verifiers.address_verifier.name_to_address["l1_ctm_deployment_tracker"]
            );
            if data.chainAssetId != expected_asset_id {
                result.report_error(&format!("Invalid asset id. Expected: {}, Recevied: {}", expected_asset_id, data.chainAssetId));
            }

            call_index += 1;
        }

        // 7: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 8: requestL2TransactionTwoBridges
        {
            let params = requestL2TransactionTwoBridgesCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            params.verify_basic_params(result, gateway_chain_id, refund_recipient);

            result.expect_address(verifiers, &params._request.secondBridgeAddress, "ctm_proxy_address");

            let data = CTMDeploymentTrackerSecondBridgeData::parse(params._request.secondBridgeCalldata.clone().into())?;
            result.expect_address(verifiers, &data.l1CTMAddress, "ctm_proxy_address");
            result.expect_address(verifiers, &data.gatewayCTMAddress, "gw_ctm_proxy_address");

            call_index += 1;
        }

        // 9: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 10: requestL2TransactionDirect (acceptOwnership for RollupDAManager)
        {
            let params = requestL2TransactionDirectCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            params.verify_basic_params(result, gateway_chain_id, refund_recipient);
            result.expect_address(verifiers, &params._request.l2Contract, "gw_rollup_da_manager");
            // We just parse to double check correctness
            acceptOwnershipCall::abi_decode(&params._request.l2Calldata, true);

            call_index += 1;
        }

        // 11: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 12: requestL2TransactionDirect (acceptOwnership for ValidatorTimelock)
        {
            let params = requestL2TransactionDirectCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            params.verify_basic_params(result, gateway_chain_id, refund_recipient);
            result.expect_address(verifiers, &params._request.l2Contract, "gw_validator_timelock");
            // We just parse to double check correctness
            acceptOwnershipCall::abi_decode(&params._request.l2Calldata, true);

            call_index += 1;
        }

        // 13: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 14: requestL2TransactionDirect (acceptOwnership for ServerNotifier)
        {
            let params = requestL2TransactionDirectCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            params.verify_basic_params(result, gateway_chain_id, refund_recipient);
            result.expect_address(verifiers, &params._request.l2Contract, "gw_server_notifier");
            // We just parse to double check correctness
            acceptOwnershipCall::abi_decode(&params._request.l2Calldata, true);

            call_index += 1;
        }

        // 15: approve
        {
            let params = approveCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            result.expect_address(
                verifiers, 
                &params.toWhom, 
                "l1_asset_router_proxy"
            );

            call_index += 1;
        }

        // 16: requestL2TransactionDirect (Update DA Pair)
        {
            let params = requestL2TransactionDirectCall::abi_decode(&self.calls.elems[call_index].data, true)?;
            params.verify_basic_params(result, gateway_chain_id, refund_recipient);
            result.expect_address(verifiers, &params._request.l2Contract, "gw_rollup_da_manager");

            let data = updateDAPairCall::abi_decode(&params._request.l2Calldata, true)?;
            
            if !data.is_active {
                result.report_error("Expected whitelist of the old DA validator pair, found unwhitelisting");
            }

            result.expect_address(verifiers, &data.l1_da_addr, "gw_sl_relayed_da_validator");
            result.expect_address(verifiers, &data.l2_da_addr, "old_l2_da_validator");

            call_index += 1;
        }

    Ok(())
    }
}

impl ChainCreationParams {
    /// Verifies the chain creation parameters.
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        expected_chain_creation_facets: FacetCutSet,
    ) -> anyhow::Result<()> {
        result.print_info("== Chain creation params ==");
        let genesis_upgrade_name = verifiers
            .address_verifier
            .name_or_unknown(&self.genesisUpgrade);
        if genesis_upgrade_name != "genesis_upgrade_addr" {
            result.report_error(&format!(
                "Expected genesis upgrade address to be genesis_upgrade_addr, but got {}",
                genesis_upgrade_name
            ));
        }

        if self.genesisBatchHash.to_string() != verifiers.genesis_config.genesis_root {
            result.report_error(&format!(
                "Expected genesis batch hash to be {}, but got {}",
                verifiers.genesis_config.genesis_root, self.genesisBatchHash
            ));
        }

        if self.genesisIndexRepeatedStorageChanges
            != verifiers.genesis_config.genesis_rollup_leaf_index
        {
            result.report_error(&format!(
                "Expected genesis index repeated storage changes to be {}, but got {}",
                verifiers.genesis_config.genesis_rollup_leaf_index,
                self.genesisIndexRepeatedStorageChanges
            ));
        }

        if self.genesisBatchCommitment.to_string()
            != verifiers.genesis_config.genesis_batch_commitment
        {
            result.report_error(&format!(
                "Expected genesis batch commitment to be {}, but got {}",
                verifiers.genesis_config.genesis_batch_commitment, self.genesisBatchCommitment
            ));
        }

        verify_chain_creation_diamond_cut(
            verifiers,
            result,
            &self.diamondCut,
            expected_chain_creation_facets,
        )
        .await?;

        let fixed_force_deployments_data =
            FixedForceDeploymentsData::abi_decode(&self.forceDeploymentsData, true)
                .expect("Failed to decode FixedForceDeploymentsData");
        fixed_force_deployments_data
            .verify(verifiers, result)
            .await?;

        Ok(())
    }
}

/// Verifies the diamond cut used during chain creation.
pub async fn verify_chain_creation_diamond_cut(
    verifiers: &crate::verifiers::Verifiers,
    result: &mut crate::verifiers::VerificationResult,
    diamond_cut: &DiamondCutData,
    expected_chain_creation_facets: FacetCutSet,
) -> anyhow::Result<()> {
    let mut proposed_facet_cut = FacetCutSet::new();
    for facet in &diamond_cut.facetCuts {
        let action = match facet.action {
            Action::Add => facet_cut_set::Action::Add,
            Action::Remove => {
                result.report_error("Remove action is unexpected in diamond cut");
                continue;
            }
            Action::Replace => {
                result.report_error("Replace action is unexpected in diamond cut");
                continue;
            }
            Action::__Invalid => {
                result.report_error("Invalid action in diamond cut");
                continue;
            }
        };
        proposed_facet_cut.add_facet(FacetInfo {
            facet: facet.facet,
            action,
            is_freezable: facet.isFreezable,
            selectors: facet.selectors.iter().map(|x| x.0).collect(),
        });
    }

    if expected_chain_creation_facets != proposed_facet_cut {
        result.report_error(&format!(
            "Invalid chain creation facet cut. Expected: {:#?}\nReceived: {:#?}",
            expected_chain_creation_facets, proposed_facet_cut
        ));
    }

    result.expect_address(verifiers, &diamond_cut.initAddress, "diamond_init");
    let initialize_data_new_chain =
        InitializeDataNewChain::abi_decode(&diamond_cut.initCalldata, true)
            .expect("Failed to decode InitializeDataNewChain");
    initialize_data_new_chain.verify(verifiers, result).await?;

    Ok(())
}

pub async fn verity_facet_cuts(
    facet_cuts: &[set_new_version_upgrade::FacetCut],
    result: &mut crate::verifiers::VerificationResult,
    expected_upgrade_facets: FacetCutSet,
) {
    // We ensure two invariants here:
    // - Firstly we use `Remove` operations only. This is mainly for ensuring that
    // the upgrade will pass.
    // - Secondly, we ensure that the set of operations is identical.
    let mut used_add = false;
    let mut proposed_facet_cuts = FacetCutSet::new();
    facet_cuts.iter().for_each(|facet| {
        let action = match facet.action {
            set_new_version_upgrade::Action::Add => {
                used_add = true;
                facet_cut_set::Action::Add
            }
            set_new_version_upgrade::Action::Remove => {
                assert!(!used_add, "Unexpected `Remove` operation after `Add`");
                facet_cut_set::Action::Remove
            }
            set_new_version_upgrade::Action::Replace => panic!("Replace unexpected"),
            set_new_version_upgrade::Action::__Invalid => panic!("Invalid unexpected"),
        };

        proposed_facet_cuts.add_facet(FacetInfo {
            facet: facet.facet,
            action,
            is_freezable: facet.isFreezable,
            selectors: facet.selectors.iter().map(|x| x.0).collect(),
        });
    });

    if proposed_facet_cuts != expected_upgrade_facets {
        result.report_error(&format!(
            "Incorrect facet cuts. Expected {:#?}\nReceived: {:#?}",
            expected_upgrade_facets, proposed_facet_cuts
        ));
    }
}

// impl GovernanceStage0Calls {
//     /// Stage0 is executed before the main upgrade even starts.
//     pub(crate) async fn verify(
//         &self,
//         verifiers: &crate::verifiers::Verifiers,
//         result: &mut crate::verifiers::VerificationResult,
//     ) -> anyhow::Result<()> {
//         result.print_info("== Gov stage 0 calls ===");
//         Ok(())
//     }
// }
// impl GovernanceStage2Calls {
//     /// Stage2 is executed after all the chains have upgraded.
//     pub(crate) async fn verify(
//         &self,
//         verifiers: &crate::verifiers::Verifiers,
//         result: &mut crate::verifiers::VerificationResult,
//     ) -> anyhow::Result<()> {
//         result.print_info("== Gov stage 2 calls ===");
//         Ok(())
//     }
// }
