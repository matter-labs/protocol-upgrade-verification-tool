use alloy::{
    dyn_abi::SolType,
    hex,
    primitives::{Address, Bytes, FixedBytes, U256},
    sol,
    sol_types::SolCall,
};

use super::{gateway_ctm_deployer::GatewayCTMDeployerConfig, UpgradeOutput};

sol! {
    function create2(
        bytes32 _salt,
        bytes32 _bytecodeHash,
        bytes calldata _input,
    ) external payable returns (address);
}

pub struct Create2 {
    pub _salt: FixedBytes<32>,
    pub _bytecode_hash: FixedBytes<32>,
    pub input: Bytes,
}

impl Create2 {
    pub fn parse(hex_data: &str) -> Self {
        let call = create2Call::abi_decode(&hex::decode(hex_data).expect("Invalid hex"), true)
            .expect("Decoding calls failed");

        Self {
            _salt: call._salt,
            _bytecode_hash: call._bytecodeHash,
            input: call._input,
        }
    }

    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
        config: &UpgradeOutput,
    ) -> anyhow::Result<()> {
        let gateway_deployer_ctm_config = GatewayCTMDeployerConfig::abi_decode(&self.input, true)
            .expect("Decoding ctm config failed");

        if gateway_deployer_ctm_config.rollupL2DAValidatorAddress
            == config.old_rollup_l2_da_validator
        {
            result.report_error("Incorrect rollupL2DAValidatorAddress");
        }

        if gateway_deployer_ctm_config.bootloaderHash.to_string() != verifiers.genesis_config.bootloader_hash {
            result.report_error("Incorrect bootloaderHash");
        }

        if gateway_deployer_ctm_config.defaultAccountHash.to_string() != verifiers.genesis_config.default_aa_hash {
            result.report_error("Incorrect defaultAccountHash");
        }

        if gateway_deployer_ctm_config.evmEmulatorHash.to_string() != verifiers.genesis_config.evm_emulator_hash {
            result.report_error("Incorrect evmEmulatorHash");
        }

        if gateway_deployer_ctm_config.genesisRoot.to_string() != verifiers.genesis_config.genesis_root {
            result.report_error("Incorrect genesisRoot");
        }

        if gateway_deployer_ctm_config.genesisRollupLeafIndex != U256::from(verifiers.genesis_config.genesis_rollup_leaf_index) {
            result.report_error("Incorrect genesisRollupLeafIndex");
        }

        if gateway_deployer_ctm_config.genesisBatchCommitment.to_string() != verifiers.genesis_config.genesis_batch_commitment {
            result.report_error("Incorrect genesisBatchCommitment");
        }

        gateway_deployer_ctm_config.verify(verifiers, result)?;

        result.report_ok("Gateway CTM Deployer Create2 verified");

        Ok(())
    }
}
