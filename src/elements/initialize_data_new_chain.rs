use std::fmt::Display;

use alloy::{primitives::U256, sol};

sol! {
    #[derive(Debug, Default, PartialEq, Eq)]
    enum PubdataPricingMode {
        #[default]
        Rollup,
        Validium
    }

    #[derive(Debug, Default, PartialEq, Eq)]
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

    struct InitializeDataNewChain {
        address verifier;
        VerifierParams verifierParams;
        bytes32 l2BootloaderBytecodeHash;
        bytes32 l2DefaultAccountBytecodeHash;
        uint256 priorityTxMaxGasLimit;
        FeeParams feeParams;
        address blobVersionedHashRetriever;
    }
}

impl InitializeDataNewChain {
    pub async fn verify(
        &self,
        verifiers: &crate::verifiers::Verifiers,
        result: &mut crate::verifiers::VerificationResult,
    ) -> anyhow::Result<()> {
        result.print_info("== checking initialize data ===");

        result.expect_address(verifiers, &self.verifier, "verifier");
        if self.verifierParams.recursionNodeLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionLeafLevelVkHash != [0u8; 32]
            || self.verifierParams.recursionCircuitsSetVksHash != [0u8; 32]
        {
            result.report_error("Verifier params must be empty.");
        }

        result.expect_zk_bytecode(
            verifiers,
            &self.l2BootloaderBytecodeHash,
            "proved_batch.yul",
        );
        result.expect_zk_bytecode(
            verifiers,
            &self.l2DefaultAccountBytecodeHash,
            "system-contracts/DefaultAccount",
        );

        if self.priorityTxMaxGasLimit != U256::from(72_000_000) {
            result.report_warn(&format!(
                "priorityTxMaxGasLimit must be 72_000_000 got {}",
                self.priorityTxMaxGasLimit
            ));
        }

        if self.feeParams != verifiers.fee_param_verifier.fee_params {
            result.report_error(&format!(
                "Incorrect fee params. Expected: {:#?}\nReceived: {:#?}",
                verifiers.fee_param_verifier.fee_params,
                self.feeParams 
            ));
        } else {
            result.report_ok("Fee params are correct");
        }
        Ok(())
    }
}

impl Display for PubdataPricingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubdataPricingMode::Rollup => write!(f, "{}", "Rollup"),
            PubdataPricingMode::Validium => write!(f, "{}", "Validium"),
            PubdataPricingMode::__Invalid => write!(f, "{}", "Invalid"),
        }
    }
}
