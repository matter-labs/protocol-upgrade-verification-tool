use alloy::{
    hex::FromHex, primitives::{Address, U256}, providers::Provider, sol, sol_types::SolConstructor
};
use anyhow::Result;
use serde::Deserialize;

use crate::utils::{
    address_verifier::AddressVerifier,
    network_verifier::{self, BridgehubInfo, NetworkVerifier},
};

use super::UpgradeOutput;

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
        constructor(address _initialOwner, address _admin);
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
        );
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

    #[sol(rpc)]
    contract ChainTypeManager {
        constructor(address _bridgehub);
        function serverNotifierAddress() external view returns (address serverNotifierAddress);
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
        constructor(uint256 _initialDelay, uint256 _maxAdditionalDelay, address _timerGovernance, address _initialOwner);
    }

    #[sol(rpc)]
    contract DualVerifier {
        constructor(address _fflonkVerifier, address _plonkVerifier);
        address public immutable FFLONK_VERIFIER;
        address public immutable PLONK_VERIFIER;
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

#[derive(Debug, Deserialize)]
pub struct GatewayStateTransition {
    pub(crate) admin_facet_addr: Address,
    pub(crate) chain_type_manager_implementation_addr: Address,
    pub(crate) chain_type_manager_proxy_addr: Address,
    pub(crate) default_upgrade_addr: Address,
    pub(crate) diamond_init_addr: Address,
    pub(crate) diamond_proxy_addr: Address,
    pub(crate) executor_facet_addr: Address,
    pub(crate) genesis_upgrade_addr: Address,
    pub(crate) getters_facet_addr: Address,
    pub(crate) mailbox_facet_addr: Address,
    pub(crate) validator_timelock_addr: Address,
    pub(crate) verifier_addr: Address,
}

impl GatewayStateTransition {
    pub async fn add_to_verifier(
        &self,
        address_verifier: &mut AddressVerifier,
        network_verifier: &NetworkVerifier,
        bridgehub_addr: Address,
    ) {
        let proxy_admin_slot = U256::from_str_radix("81955473079516046949633743016697847541294818689821282749996681496272635257091", 10).unwrap();

        let gw_provider = network_verifier.gw_provider.clone();
        address_verifier.add_address(self.admin_facet_addr, "gateway_admin_facet_addr");
        address_verifier.add_address(
            self.chain_type_manager_implementation_addr,
            "gateway_chain_type_manager_implementation_addr",
        );
        address_verifier.add_address(
            self.chain_type_manager_proxy_addr,
            "gateway_chain_type_manager_proxy_addr",
        );
        address_verifier.add_address(self.default_upgrade_addr, "gateway_default_upgrade_addr");
        address_verifier.add_address(self.diamond_init_addr, "gateway_diamond_init_addr");
        address_verifier.add_address(self.diamond_proxy_addr, "gateway_diamond_proxy_addr");
        address_verifier.add_address(self.executor_facet_addr, "gateway_executor_facet_addr");
        address_verifier.add_address(self.genesis_upgrade_addr, "gateway_genesis_upgrade_addr");
        address_verifier.add_address(self.getters_facet_addr, "gateway_getters_facet_addr");
        address_verifier.add_address(self.mailbox_facet_addr, "gateway_mailbox_facet_addr");
        address_verifier.add_address(
            self.validator_timelock_addr,
            "gateway_validator_timelock_addr",
        );
        address_verifier.add_address(self.verifier_addr, "gateway_verifier_addr");

        let dual_verifier = DualVerifier::new(self.verifier_addr, gw_provider.clone());
        let plonk_verifier_addr = dual_verifier.PLONK_VERIFIER().call().await.unwrap().PLONK_VERIFIER;
        let fflonk_verifier_addr = dual_verifier.FFLONK_VERIFIER().call().await.unwrap().FFLONK_VERIFIER;

        address_verifier.add_address(plonk_verifier_addr, "gateway_verifier_plonk_addr");
        address_verifier.add_address(fflonk_verifier_addr, "gateway_verifier_fflonk_addr");

        let gw_ctm_proxy_admin_bytes = gw_provider.get_storage_at(self.chain_type_manager_proxy_addr, proxy_admin_slot).await.unwrap();
        let gw_ctm_proxy_admin: [u8; 20] = gw_ctm_proxy_admin_bytes.to_be_bytes::<32>()[12..].try_into().unwrap();

        address_verifier.add_address(Address::from_slice(&gw_ctm_proxy_admin), "gateway_chain_type_manager_proxy_admin_addr");

        let bridgehub_info = network_verifier.get_bridgehub_info(bridgehub_addr).await;

        address_verifier.add_address(
            bridgehub_info.l1_asset_router_proxy_addr,
            "l1_asset_router_addr",
        );
        address_verifier.add_address(
            bridgehub_info.ctm_deployment_tracker_proxy_addr,
            "ctm_deployment_tracker_proxy_addr",
        );
        address_verifier.add_address(
            bridgehub_info.gateway_base_token_addr,
            "gateway_base_token_addr",
        );
        address_verifier.add_address(bridgehub_addr, "bridgehub_proxy_addr");
        address_verifier.add_address(bridgehub_info.stm_address, "chain_type_manager_proxy_addr");
        address_verifier.add_address(bridgehub_info.ecosystem_admin, "ecosystem_admin");
    }

    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
