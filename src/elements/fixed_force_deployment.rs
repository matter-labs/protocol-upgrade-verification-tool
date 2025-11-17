use alloy::{
    primitives::{Address, U256},
    sol,
};

use crate::MAX_NUMBER_OF_ZK_CHAINS;

sol! {
    #[derive(Debug)]
    struct FixedForceDeploymentsData {
        uint256 l1ChainId;
        uint256 eraChainId;
        address l1AssetRouter;
        bytes32 l2TokenProxyBytecodeHash;
        address aliasedL1Governance;
        uint256 maxNumberOfZKChains;
        bytes bridgehubBytecodeInfo;
        bytes l2AssetRouterBytecodeInfo;
        bytes l2NtvBytecodeInfo;
        bytes messageRootBytecodeInfo;
        bytes chainAssetHandlerBytecodeInfo;
        bytes beaconDeployerInfo;
        address l2SharedBridgeLegacyImpl;
        address l2BridgedStandardERC20Impl;
        // The forced beacon address. It is needed only for internal testing.
        // MUST be equal to 0 in production.
        // It will be the job of the governance to ensure that this value is set correctly.
        address dangerousTestOnlyForcedBeacon;
    }
}

impl FixedForceDeploymentsData {
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        let expected_l1_chain_id = verifiers.network_verifier.get_l1_chain_id();
        if U256::from(expected_l1_chain_id) != self.l1ChainId {
            result.report_error(&format!(
                "L1 chain id mismatch: expected {}, got {}",
                expected_l1_chain_id, self.l1ChainId,
            ));
        }

        let era_chain_id = verifiers.network_verifier.get_era_chain_id();
        if U256::from(era_chain_id) != self.eraChainId {
            result.report_error(&format!(
                "Era chain id mismatch: expected {}, got {}",
                era_chain_id, self.eraChainId
            ));
        }

        result.expect_address(verifiers, &self.l1AssetRouter, "l1_asset_router_proxy");
        // Even though this is a ZK bytecode, we just dont use it in zksync os.
        result.expect_zk_bytecode(
            verifiers,
            &self.l2TokenProxyBytecodeHash,
            "l1-contracts/BeaconProxy",
        );
        result.expect_address(
            verifiers,
            &self.aliasedL1Governance,
            "aliased_owner",
        );

        if self.maxNumberOfZKChains != U256::from(MAX_NUMBER_OF_ZK_CHAINS) {
            result.report_error("maxNumberOfZKChains must be 100");
        }

        result.expect_zksync_os_system_proxy_upgrade_bytecode_info(
            verifiers,
            &self.bridgehubBytecodeInfo,
            "l1-contracts/L2Bridgehub",
        );
        result.expect_zksync_os_system_proxy_upgrade_bytecode_info(
            verifiers,
            &self.l2AssetRouterBytecodeInfo,
            "l1-contracts/L2AssetRouter",
        );
        result.expect_zksync_os_system_proxy_upgrade_bytecode_info(
            verifiers,
            &self.l2NtvBytecodeInfo,
            "l1-contracts/L2NativeTokenVaultZKOS",
        );

        result.expect_zksync_os_system_proxy_upgrade_bytecode_info(
            verifiers,
            &self.messageRootBytecodeInfo,
            "l1-contracts/L2MessageRoot",
        );

        result.expect_zksync_os_system_proxy_upgrade_bytecode_info(
            verifiers,
            &self.chainAssetHandlerBytecodeInfo,
            "l1-contracts/L2ChainAssetHandler",
        );

        result.expect_zksync_os_system_proxy_upgrade_bytecode_info(
            verifiers,
            &self.beaconDeployerInfo,
            "l1-contracts/UpgradeableBeaconDeployer",
        );

        result.expect_address(verifiers, &self.l2SharedBridgeLegacyImpl, "zero");

        result.expect_address(verifiers, &self.l2BridgedStandardERC20Impl, "zero");

        if self.dangerousTestOnlyForcedBeacon != Address::ZERO {
            result.report_error("dangerousTestOnlyForcedBeacon must be 0");
        }

        Ok(())
    }
}
