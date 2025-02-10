use anyhow::{Context, ensure, Result};

use crate::{
    utils::{
        address_verifier::AddressVerifier,
        facet_cut_set::{self, FacetCutSet, FacetInfo},
        network_verifier::BridgehubInfo,
    },
    UpgradeOutput,
};
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    sol,
    sol_types::{SolCall, SolConstructor},
};
use serde::Deserialize;
use super::protocol_version::ProtocolVersion;

const MAINNET_CHAIN_ID: u64 = 1;

sol! {

    contract L1NativeTokenVault {
        constructor(
            address _l1WethAddress,
            address _l1AssetRouter,
            address _l1Nullifier
        );

        function initialize(address _owner, address _bridgedTokenBeacon);
    }

    #[sol(rpc)]
    contract ValidatorTimelock {
        constructor(address _initialOwner, uint32 _executionDelay);
        address public chainTypeManager;
        address public owner;
        uint32 public executionDelay;
    }

    #[sol(rpc)]
    contract L2WrappedBaseTokenStore {
        constructor(address _initialOwner, address _admin) {}
        address public admin;
        address public owner;
        function l2WBaseTokenAddress(uint256 chainId) external view returns (address l2WBaseTokenAddress);
    }

    #[sol(rpc)]
    contract CTMDeploymentTracker {
        constructor(address _bridgehub, address _l1AssetRouter);
        address public owner;

        function initialize(address _owner);
    }

    #[sol(rpc)]
    contract L1AssetRouter {
        constructor(
            address _l1WethAddress,
            address _bridgehub,
            address _l1Nullifier,
            uint256 _eraChainId,
            address _eraDiamondProxy
        ) {}
        function initialize(address _owner) external;

        /// @dev Address of native token vault.
        address public nativeTokenVault;

        /// @dev Address of legacy bridge.
        address public legacyBridge;

        address public owner;
    }

    contract L1Nullifier {
        constructor(address _bridgehub, uint256 _eraChainId, address _eraDiamondProxy);
    }

    contract L1ERC20Bridge {
        constructor(
            address _nullifier,
            address _assetRouter,
            address _nativeTokenVault,
            uint256 _eraChainId
        );
    }

    contract ChainTypeManager {
        constructor(address _bridgehub);
    }

    #[sol(rpc)]
    contract StateTransitionManagerLegacy {
        function getAllHyperchainChainIDs() public view override returns (uint256[] memory);
        function getHyperchain(uint256 _chainId) public view override returns (address chainAddress);
    }

    #[sol(rpc)]
    contract L1SharedBridgeLegacy {
        function l2BridgeAddress(uint256 chainId) public view override returns (address l2SharedBridgeAddress);
    }

    /// @notice Faсet structure compatible with the EIP-2535 diamond loupe
    /// @param addr The address of the facet contract
    /// @param selectors The NON-sorted array with selectors associated with facet
    struct Facet {
        address addr;
        bytes4[] selectors;
    }

    #[sol(rpc)]
    contract GettersFacet {
        function getProtocolVersion() external view returns (uint256);
        function facets() external view returns (Facet[] memory result);
    }

    contract AdminFacet {
        constructor(uint256 _l1ChainId, address _rollupDAManager);
    }

    contract ExecutorFacet {
        constructor(uint256 _l1ChainId);
    }

    contract MailboxFacet {
        constructor(uint256 _eraChainId, uint256 _l1ChainId);
    }

    contract BridgehubImpl {
        constructor(uint256 _l1ChainId, address _owner, uint256 _maxNumberOfZKChains);
    }

    #[sol(rpc)]
    contract RollupDAManager{
        function isPairAllowed(address _l1DAValidator, address _l2DAValidator) external view returns (bool);
        address public owner;
    }

    contract TransitionaryOwner {
        constructor(address _governanceAddress);
    }

    contract BridgedTokenBeacon {
        constructor(address _beacon);
    }

    contract MessageRoot {
        constructor(address _bridgehub);
        function initialize();
    }

    contract GovernanceUpgradeTimer {
        constructor(uint256 _initialDelay, uint256 _maxAdditionalDelay, address _timerGovernance, address _initialOwner) {}
    }

    #[sol(rpc)]
    contract ProtocolUpgradeHandler {
        /// @dev ZKsync smart contract that used to operate with L2 via asynchronous L2 <-> L1 communication.
        address public immutable ZKSYNC_ERA;

        /// @dev ZKsync smart contract that is responsible for creating new ZK Chains and changing parameters in existent.
        address public immutable CHAIN_TYPE_MANAGER;

        /// @dev Bridgehub smart contract that is used to operate with L2 via asynchronous L2 <-> L1 communication.
        address public immutable BRIDGE_HUB;

        /// @dev The nullifier contract that is used for bridging.
        address public immutable L1_NULLIFIER;

        /// @dev The asset router contract that is used for bridging.
        address public immutable L1_ASSET_ROUTER;

        /// @dev Vault holding L1 native ETH and ERC20 tokens bridged into the ZK chains.
        address public immutable L1_NATIVE_TOKEN_VAULT;
    }
}

struct BasicFacetInfo {
    name: &'static str,
    is_freezable: bool,
}

const EXPECTED_FACETS: [BasicFacetInfo; 4] = [
    BasicFacetInfo { name: "admin_facet",   is_freezable: false },
    BasicFacetInfo { name: "getters_facet", is_freezable: false },
    BasicFacetInfo { name: "mailbox_facet", is_freezable: true  },
    BasicFacetInfo { name: "executor_facet",is_freezable: true  },
];

#[derive(Debug, Deserialize)]
pub struct DeployedAddresses {
    pub(crate) native_token_vault_addr: Address,
    pub(crate) validator_timelock_addr: Address,
    pub(crate) l2_wrapped_base_token_store_addr: Address,
    pub(crate) l1_bytecodes_supplier_addr: Address,
    pub(crate) rollup_l1_da_validator_addr: Address,
    pub(crate) validium_l1_da_validator_addr: Address,
    pub(crate) l1_transitionary_owner: Address,
    pub(crate) l1_rollup_da_manager: Address,
    pub(crate) l1_gateway_upgrade: Address,
    pub(crate) l1_governance_upgrade_timer: Address,
    pub(crate) bridges: Bridges,
    pub(crate) bridgehub: Bridgehub,
    pub(crate) state_transition: StateTransition,
}

#[derive(Debug, Deserialize)]
pub struct Bridges {
    shared_bridge_proxy_addr: Address,
    pub l1_nullifier_implementation_addr: Address,
    pub erc20_bridge_implementation_addr: Address,
    pub bridged_standard_erc20_impl: Address,
    pub bridged_token_beacon: Address,
}

#[derive(Debug, Deserialize)]
pub struct Bridgehub {
    ctm_deployment_tracker_proxy_addr: Address,
    bridgehub_implementation_addr: Address,
    message_root_proxy_addr: Address,

    // Note, that while the original file may contain impl addresses,
    // we do not include or verify those here since the correctness of the
    // actual implementation behind the proxies above is already checked.
}

#[derive(Debug, Deserialize)]
pub struct StateTransition {
    pub admin_facet_addr: Address,
    pub default_upgrade_addr: Address,
    pub diamond_init_addr: Address,
    pub executor_facet_addr: Address,
    pub genesis_upgrade_addr: Address,
    pub getters_facet_addr: Address,
    pub mailbox_facet_addr: Address,
    pub state_transition_implementation_addr: Address,
    pub verifier_addr: Address,
}

impl DeployedAddresses {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.native_token_vault_addr, "native_token_vault");
        address_verifier.add_address(self.validator_timelock_addr, "validator_timelock");
        address_verifier.add_address(self.bridges.shared_bridge_proxy_addr, "l1_asset_router_proxy");
        address_verifier.add_address(self.bridgehub.message_root_proxy_addr, "l1_message_root");
        address_verifier.add_address(self.bridgehub.ctm_deployment_tracker_proxy_addr, "ctm_deployment_tracker");
        address_verifier.add_address(self.bridgehub.bridgehub_implementation_addr, "bridgehub_implementation_addr");
        address_verifier.add_address(self.l2_wrapped_base_token_store_addr, "l2_wrapped_base_token_store");
        address_verifier.add_address(self.bridges.l1_nullifier_implementation_addr, "l1_nullifier_implementation_addr");
        address_verifier.add_address(self.bridges.erc20_bridge_implementation_addr, "erc20_bridge_implementation_addr");
        address_verifier.add_address(self.l1_rollup_da_manager, "rollup_da_manager");
        address_verifier.add_address(self.l1_governance_upgrade_timer, "upgrade_timer");
        self.state_transition.add_to_verifier(address_verifier);
    }
}

impl StateTransition {
    pub fn add_to_verifier(&self, address_verifier: &mut AddressVerifier) {
        address_verifier.add_address(self.admin_facet_addr, "admin_facet");
        address_verifier.add_address(self.default_upgrade_addr, "default_upgrade");
        address_verifier.add_address(self.diamond_init_addr, "diamond_init");
        address_verifier.add_address(self.executor_facet_addr, "executor_facet");
        address_verifier.add_address(self.genesis_upgrade_addr, "genesis_upgrade_addr");
        address_verifier.add_address(self.getters_facet_addr, "getters_facet");
        address_verifier.add_address(self.mailbox_facet_addr, "mailbox_facet");
        address_verifier.add_address(self.state_transition_implementation_addr, "state_transition_implementation_addr");
        address_verifier.add_address(self.verifier_addr, "verifier");
    }
}

impl DeployedAddresses {
    async fn verify_ntv(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let l1_ntv_impl_constructor = L1NativeTokenVault::constructorCall::new((
            bridgehub_info.l1_weth_token_address,
            config.deployed_addresses.bridges.shared_bridge_proxy_addr,
            bridgehub_info.shared_bridge,
        ))
        .abi_encode();
        let l1_ntv_init_calldata =
            L1NativeTokenVault::initializeCall::new((config.protocol_upgrade_handler_proxy_address, self.bridges.bridged_token_beacon))
                .abi_encode();

        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                &self.native_token_vault_addr,
                l1_ntv_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                l1_ntv_impl_constructor,
                "l1-contracts/L1NativeTokenVault",
            )
            .await;
        Ok(())
    }

    async fn verify_validator_timelock(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let execution_delay = if config.l1_chain_id == MAINNET_CHAIN_ID {
            10800
        } else {
            0
        };
        result.expect_create2_params(
            verifiers,
            &self.validator_timelock_addr,
            ValidatorTimelock::constructorCall::new((config.deployer_addr, execution_delay)).abi_encode(),
            "l1-contracts/ValidatorTimelock",
        );

        let provider = verifiers
            .network_verifier
            .get_l1_provider();
        let validator_timelock = ValidatorTimelock::new(self.validator_timelock_addr, provider);
        let current_owner = validator_timelock.owner().call().await?.owner;
        ensure!(
            current_owner == self.l1_transitionary_owner,
            "ValidatorTimelock owner mismatch: expected {:?}, got {:?}",
            self.l1_transitionary_owner,
            current_owner
        );

        let current_execution_delay = validator_timelock.executionDelay().call().await?.executionDelay;
        ensure!(
            current_execution_delay == execution_delay,
            "ValidatorTimelock execution delay mismatch: expected {}, got {}",
            execution_delay,
            current_execution_delay
        );

        let chain_type_manager = validator_timelock.chainTypeManager().call().await?.chainTypeManager;
        ensure!(
            chain_type_manager == bridgehub_info.stm_address,
            "ValidatorTimelock chainTypeManager mismatch: expected {:?}, got {:?}",
            bridgehub_info.stm_address,
            chain_type_manager
        );

        Ok(())
    }

    async fn verify_wrapped_base_token_store(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.l2_wrapped_base_token_store_addr,
            L2WrappedBaseTokenStore::constructorCall::new((
                config.protocol_upgrade_handler_proxy_address,
                config.deployer_addr,
            ))
            .abi_encode(),
            "l1-contracts/L2WrappedBaseTokenStore",
        );

        let provider = verifiers
            .network_verifier
            .get_l1_provider();
        let l2_wrapped_base_token_store =
            L2WrappedBaseTokenStore::new(self.l2_wrapped_base_token_store_addr, provider);
        let admin_response = l2_wrapped_base_token_store.admin().call().await?;
        let l2_wrapped_base_token_store_admin = admin_response.admin;
        let owner_response = l2_wrapped_base_token_store.owner().call().await?;
        let l2_wrapped_base_token_store_owner = owner_response.owner;

        if l2_wrapped_base_token_store_admin != bridgehub_info.ecosystem_admin {
            result.report_warn("l2_wrapped_base_token_store admin is not equal to the ecosystem admin");
        }
        ensure!(
            l2_wrapped_base_token_store_owner
                == config.protocol_upgrade_handler_proxy_address,
            "l2_wrapped_base_token_store owner mismatch"
        );
        Ok(())
    }

    async fn verify_per_chain_info(
        &self,
        _config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let provider = verifiers
            .network_verifier
            .get_l1_provider();
        let l2_wrapped_base_token_store =
            L2WrappedBaseTokenStore::new(self.l2_wrapped_base_token_store_addr, provider);
        let l1_legacy_shared_bridge = L1SharedBridgeLegacy::new(
            bridgehub_info.shared_bridge,
            verifiers
                .network_verifier
                .get_l1_provider()
        );
        let stm = StateTransitionManagerLegacy::new(
            bridgehub_info.stm_address,
            verifiers
                .network_verifier
                .get_l1_provider()
        );
        let all_zkchains = stm.getAllHyperchainChainIDs().call().await?._0;

        for chain in all_zkchains {
            let l2_wrapped_base_token = l2_wrapped_base_token_store
                .l2WBaseTokenAddress(chain)
                .call()
                .await?
                .l2WBaseTokenAddress;
            if l2_wrapped_base_token == Address::ZERO {
                result.report_warn(&format!("Chain {} does not have an L2 wrapped base token", chain));
            }

            let l2_shared_bridge = l1_legacy_shared_bridge
                .l2BridgeAddress(chain)
                .call()
                .await?
                .l2SharedBridgeAddress;
            if l2_shared_bridge == Address::ZERO {
                result.report_warn(&format!("Chain {} does not have an L2 shared bridge", chain));
            }

            let getters = GettersFacet::new(
                stm.getHyperchain(chain).call().await?.chainAddress,
                verifiers
                    .network_verifier
                    .get_l1_provider()
            );
            let protocol_version = getters.getProtocolVersion().call().await?._0;
            if protocol_version != Self::expected_previous_protocol_version() {
                let semver_version = ProtocolVersion::from(protocol_version);
                result.report_warn(&format!(
                    "Chain {} has incorrect protocol version {}",
                    chain, semver_version
                ));
            }
        }
        Ok(())
    }

    fn expected_previous_protocol_version() -> U256 {
        U256::from(25) * U256::from(2).pow(U256::from(32))
    }

    async fn verify_ctm_deployment_tracker(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let ctm_deployer_impl_constructor = CTMDeploymentTracker::constructorCall::new((
            bridgehub_info.bridgehub_addr,
            config.deployed_addresses.bridges.shared_bridge_proxy_addr,
        ))
        .abi_encode();
        let ctm_deployer_init_calldata =
            CTMDeploymentTracker::initializeCall::new((config.deployer_addr,)).abi_encode();

        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                &self.bridgehub.ctm_deployment_tracker_proxy_addr,
                ctm_deployer_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                ctm_deployer_impl_constructor,
                "l1-contracts/CTMDeploymentTracker",
            )
            .await;

        let provider = verifiers
            .network_verifier
            .get_l1_provider();
        let ctm_dt = CTMDeploymentTracker::new(self.bridgehub.ctm_deployment_tracker_proxy_addr, provider);
        let owner = ctm_dt.owner().call().await?.owner;
        ensure!(owner == self.l1_transitionary_owner, "CTMDeploymentTracker owner mismatch");
        Ok(())
    }

    async fn verify_l1_asset_router(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let era_diamond_proxy = verifiers
            .network_verifier
            .get_chain_diamond_proxy(bridgehub_info.stm_address, config.era_chain_id)
            .await;
        let l1_asset_router_impl_constructor = L1AssetRouter::constructorCall::new((
            bridgehub_info.l1_weth_token_address,
            bridgehub_info.bridgehub_addr,
            bridgehub_info.shared_bridge,
            U256::from(config.era_chain_id),
            era_diamond_proxy,
        ))
        .abi_encode();
        let l1_asset_router_init_calldata =
            L1AssetRouter::initializeCall::new((config.deployer_addr,)).abi_encode();

        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                &self.bridges.shared_bridge_proxy_addr,
                l1_asset_router_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                l1_asset_router_impl_constructor,
                "l1-contracts/L1AssetRouter",
            )
            .await;

        let provider = verifiers
            .network_verifier
            .get_l1_provider();
        let l1_asset_router = L1AssetRouter::new(self.bridges.shared_bridge_proxy_addr, provider);
        let current_owner = l1_asset_router.owner().call().await?.owner;
        ensure!(current_owner == self.l1_transitionary_owner, "L1AssetRouter owner mismatch");

        let legacy_bridge = l1_asset_router.legacyBridge().call().await?.legacyBridge;
        ensure!(legacy_bridge == bridgehub_info.legacy_bridge, "L1AssetRouter legacyBridge mismatch");

        let l1_ntv = l1_asset_router.nativeTokenVault().call().await?.nativeTokenVault;
        ensure!(l1_ntv == self.native_token_vault_addr, "L1AssetRouter nativeTokenVault mismatch");
        Ok(())
    }

    async fn verify_l1_nullifier(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let era_diamond_proxy = verifiers
            .network_verifier
            .get_chain_diamond_proxy(bridgehub_info.stm_address, config.era_chain_id)
            .await;
        let l1nullifier_constructor_data = L1Nullifier::constructorCall::new((
            bridgehub_info.bridgehub_addr,
            U256::from(config.era_chain_id),
            era_diamond_proxy,
        ))
        .abi_encode();

        result.expect_create2_params(
            verifiers,
            &self.bridges.l1_nullifier_implementation_addr,
            l1nullifier_constructor_data,
            "l1-contracts/L1Nullifier",
        );
        Ok(())
    }

    async fn verify_l1_erc20_bridge(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.bridges.erc20_bridge_implementation_addr,
            L1ERC20Bridge::constructorCall::new((
                bridgehub_info.shared_bridge,
                self.bridges.shared_bridge_proxy_addr,
                self.native_token_vault_addr,
                U256::from(config.era_chain_id),
            ))
            .abi_encode(),
            "l1-contracts/L1ERC20Bridge",
        );
        Ok(())
    }

    async fn verify_bridgehub_impl(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> Result<()> {
        const MAX_NUMBER_OF_CHAINS: usize = 100;
        result.expect_create2_params(
            verifiers,
            &self.bridgehub.bridgehub_implementation_addr,
            BridgehubImpl::constructorCall::new((
                U256::from(config.l1_chain_id),
                config.protocol_upgrade_handler_proxy_address,
                U256::from(MAX_NUMBER_OF_CHAINS),
            ))
            .abi_encode(),
            "l1-contracts/Bridgehub",
        );
        Ok(())
    }

    async fn verify_chain_type_manager(
        &self,
        _config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.state_transition.state_transition_implementation_addr,
            ChainTypeManager::constructorCall::new((bridgehub_info.bridgehub_addr,)).abi_encode(),
            "l1-contracts/ChainTypeManager",
        );
        Ok(())
    }

    async fn verify_admin_facet(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.state_transition.admin_facet_addr,
            AdminFacet::constructorCall::new((U256::from(config.l1_chain_id), self.l1_rollup_da_manager))
                .abi_encode(),
            "l1-contracts/AdminFacet",
        );
        Ok(())
    }

    async fn verify_executor_facet(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.state_transition.executor_facet_addr,
            ExecutorFacet::constructorCall::new((U256::from(config.l1_chain_id),)).abi_encode(),
            "l1-contracts/ExecutorFacet",
        );
        Ok(())
    }

    async fn verify_getters_facet(
        &self,
        _config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.state_transition.getters_facet_addr,
            Vec::new(),
            "l1-contracts/GettersFacet",
        );
        Ok(())
    }

    async fn verify_mailbox_facet(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.state_transition.mailbox_facet_addr,
            MailboxFacet::constructorCall::new((U256::from(config.era_chain_id), U256::from(config.l1_chain_id)))
                .abi_encode(),
            "l1-contracts/MailboxFacet",
        );
        Ok(())
    }

    async fn verify_rollup_da_manager(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.l1_rollup_da_manager,
            Vec::new(),
            "l1-contracts/RollupDAManager",
        );

        let provider = verifiers
            .network_verifier
            .get_l1_provider();
        let rollup_da_manager = RollupDAManager::new(self.l1_rollup_da_manager, provider);
        let is_rollup_pair_allowed = rollup_da_manager
            .isPairAllowed(self.rollup_l1_da_validator_addr, config.contracts_config.expected_rollup_l2_da_validator)
            .call()
            .await?
            ._0;
        ensure!(is_rollup_pair_allowed, "Rollup pair not allowed in RollupDAManager");

        let current_owner = rollup_da_manager.owner().call().await?.owner;
        ensure!(
            current_owner == self.l1_transitionary_owner,
            "RollupDAManager owner mismatch"
        );
        Ok(())
    }

    async fn verify_transitionary_owner(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.l1_transitionary_owner,
            TransitionaryOwner::constructorCall::new((
                config.protocol_upgrade_handler_proxy_address,
            ))
            .abi_encode(),
            "l1-contracts/TransitionaryOwner",
        );
        Ok(())
    }

    async fn verify_bridged_token_beacon(
        &self,
        _config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        _bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        result.expect_create2_params(
            verifiers,
            &self.bridges.bridged_token_beacon,
            BridgedTokenBeacon::constructorCall::new((self.bridges.bridged_standard_erc20_impl,))
                .abi_encode(),
            "l1-contracts/UpgradeableBeacon",
        );
        Ok(())
    }

    async fn verify_message_root(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let message_root_impl_constructor =
            MessageRoot::constructorCall::new((bridgehub_info.bridgehub_addr,)).abi_encode();
        let message_root_init_calldata = MessageRoot::initializeCall::new(()).abi_encode();

        result
            .expect_create2_params_proxy_with_bytecode(
                verifiers,
                &self.bridgehub.message_root_proxy_addr,
                message_root_init_calldata,
                bridgehub_info.transparent_proxy_admin,
                message_root_impl_constructor,
                "l1-contracts/MessageRoot",
            )
            .await;
        Ok(())
    }

    async fn verify_governance_upgrade_timer(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo,
    ) -> Result<()> {
        let initial_delay = if config.era_chain_id == 300 || config.l1_chain_id == 1 {
            2 * 7 * 24 * 3600
        } else {
            24 * 3600
        };
        const MAX_INITIAL_DELAY: u32 = 1209600;
        let expected_constructor_params = GovernanceUpgradeTimer::constructorCall::new((
            U256::from(initial_delay),
            U256::from(MAX_INITIAL_DELAY),
            config.protocol_upgrade_handler_proxy_address,
            bridgehub_info.ecosystem_admin,
        ))
        .abi_encode();

        result.expect_create2_params(
            verifiers,
            &self.l1_governance_upgrade_timer,
            expected_constructor_params,
            "l1-contracts/GovernanceUpgradeTimer",
        );
        Ok(())
    }

    pub async fn get_expected_facet_cuts(
        &self,
        verifiers: &crate::verifiers::Verifiers,
    ) -> anyhow::Result<(FacetCutSet, FacetCutSet)> {
        let bridgehub_addr = verifiers.bridgehub_address;
        let bridgehub_info = verifiers.network_verifier.get_bridgehub_info(bridgehub_addr).await;

        let mut facets_to_remove = FacetCutSet::new();
        let getters_facet = GettersFacet::new(
            bridgehub_info.era_address,
            verifiers
                .network_verifier
                .get_l1_provider()
        );
        let current_facets = getters_facet.facets().call().await?.result;
        for f in current_facets {
            // Note, that when deleting facets, their address must be provided as zero.
            facets_to_remove.add_facet(FacetInfo {
                facet: Address::ZERO,
                is_freezable: false,
                action:  facet_cut_set::Action::Remove,
                selectors: f.selectors.iter().map(|x| x.0).collect()
            });
        }

        let mut facets_to_add = FacetCutSet::new();
        let l1_provider = verifiers
            .network_verifier
            .get_l1_provider();
        for facet in &EXPECTED_FACETS {
            let address = *verifiers
                .address_verifier
                .name_to_address
                .get(facet.name)
                .expect(&format!("{} not found", facet.name));
            let bytecode = l1_provider
                .get_code_at(address)
                .await
                .context(format!("Failed to retrieve the bytecode for {}", address))?;
            let info: Vec<_> = evmole::contract_info(
                evmole::ContractInfoArgs::new(&bytecode.0).with_selectors(),
            )
            .functions
            .unwrap()
            .into_iter()
            .map(|f| f.selector)
            // We filter out the selector for `getName()` which is equal to 0x17d7de7c.
            .filter(|selector| selector != &[0x17, 0xd7, 0xde, 0x7c])
            .collect();

            facets_to_add.add_facet(FacetInfo {
                facet: address,
                is_freezable: facet.is_freezable,
                action: facet_cut_set::Action::Add,
                selectors: info.into_iter().collect()
            });
        }
        Ok((facets_to_remove, facets_to_add))
    }

    pub async fn verify_protocol_upgrade_handler_impl(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        bridgehub_info: &BridgehubInfo
    ) -> anyhow::Result<()> {
        let protocol_upgrade_handler_impl = ProtocolUpgradeHandler::new(
            config.protocol_upgrade_handler_impl_address,
            verifiers.network_verifier.get_l1_provider()
        );

        let bridgehub = protocol_upgrade_handler_impl.BRIDGE_HUB().call().await.unwrap().BRIDGE_HUB;
        let chain_type_manager = protocol_upgrade_handler_impl.CHAIN_TYPE_MANAGER().call().await.unwrap().CHAIN_TYPE_MANAGER;
        let era = protocol_upgrade_handler_impl.ZKSYNC_ERA().call().await.unwrap().ZKSYNC_ERA;
        let l1_nullifier = protocol_upgrade_handler_impl.L1_NULLIFIER().call().await.unwrap().L1_NULLIFIER;
        let l1_asset_router = protocol_upgrade_handler_impl.L1_ASSET_ROUTER().call().await.unwrap().L1_ASSET_ROUTER;
        let l1_native_token_vault = protocol_upgrade_handler_impl.L1_NATIVE_TOKEN_VAULT().call().await.unwrap().L1_NATIVE_TOKEN_VAULT;


        result.expect_address(verifiers, &bridgehub, "bridgehub_proxy");
        result.expect_address(verifiers, &chain_type_manager, "state_transition_manager");
        if bridgehub_info.era_address != era {
            result.report_error(&format!("Incorrect era address. Expected {}, received: {}", bridgehub_info.era_address, era));
        }
        result.expect_address(verifiers, &l1_nullifier, "old_shared_bridge_proxy");
        result.expect_address(verifiers, &l1_asset_router, "l1_asset_router_proxy");
        result.expect_address(verifiers, &l1_native_token_vault, "native_token_vault");

        Ok(())
    }

    pub async fn verify(
        &self,
        config: &UpgradeOutput,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        let bridgehub_addr = verifiers.bridgehub_address;
        let bridgehub_info = verifiers.network_verifier.get_bridgehub_info(bridgehub_addr).await;

        self.verify_ntv(config, verifiers, result, &bridgehub_info).await?;
        self.verify_validator_timelock(config, verifiers, result, &bridgehub_info).await?;
        self.verify_wrapped_base_token_store(config, verifiers, result, &bridgehub_info).await?;
        self.verify_ctm_deployment_tracker(config, verifiers, result, &bridgehub_info).await?;
        self.verify_l1_asset_router(config, verifiers, result, &bridgehub_info).await?;
        self.verify_l1_nullifier(config, verifiers, result, &bridgehub_info).await?;
        self.verify_l1_erc20_bridge(config, verifiers, result, &bridgehub_info).await?;
        self.verify_bridgehub_impl(config, verifiers, result).await?;
        self.verify_chain_type_manager(config, verifiers, result, &bridgehub_info).await?;
        self.verify_admin_facet(config, verifiers, result, &bridgehub_info).await?;
        self.verify_executor_facet(config, verifiers, result, &bridgehub_info).await?;
        self.verify_getters_facet(config, verifiers, result, &bridgehub_info).await?;
        self.verify_mailbox_facet(config, verifiers, result, &bridgehub_info).await?;
        self.verify_rollup_da_manager(config, verifiers, result, &bridgehub_info).await?;
        self.verify_transitionary_owner(config, verifiers, result, &bridgehub_info).await?;
        self.verify_bridged_token_beacon(config, verifiers, result, &bridgehub_info).await?;
        self.verify_message_root(verifiers, result, &bridgehub_info).await?;
        self.verify_governance_upgrade_timer(config, verifiers, result, &bridgehub_info).await?;
        self.verify_per_chain_info(config, verifiers, result, &bridgehub_info).await?;
        self.verify_protocol_upgrade_handler_impl(config, verifiers, result, &bridgehub_info).await?;

        result.expect_create2_params(
            verifiers,
            &self.state_transition.verifier_addr,
            Vec::new(),
            if verifiers.testnet_contracts {
                "l1-contracts/TestnetVerifier"
            } else {
                "l1-contracts/Verifier"
            },
        );
        result.expect_create2_params(verifiers, &self.state_transition.genesis_upgrade_addr, Vec::new(), "l1-contracts/L1GenesisUpgrade");
        result.expect_create2_params(verifiers, &self.state_transition.default_upgrade_addr, Vec::new(), "l1-contracts/DefaultUpgrade");
        result.expect_create2_params(verifiers, &self.state_transition.diamond_init_addr, Vec::new(), "l1-contracts/DiamondInit");
        result.expect_create2_params(verifiers, &self.l1_bytecodes_supplier_addr, Vec::new(), "l1-contracts/BytecodesSupplier");
        result.expect_create2_params(verifiers, &self.rollup_l1_da_validator_addr, Vec::new(), "da-contracts/RollupL1DAValidator");
        result.expect_create2_params(verifiers, &self.validium_l1_da_validator_addr, Vec::new(), "l1-contracts/ValidiumL1DAValidator");
        result.expect_create2_params(verifiers, &self.bridges.bridged_standard_erc20_impl, Vec::new(), "l1-contracts/BridgedStandardERC20");
        result.expect_create2_params(verifiers, &self.l1_gateway_upgrade, Vec::new(), "l1-contracts/GatewayUpgrade");

        result.report_ok("deployed addresses");
        Ok(())
    }
}
