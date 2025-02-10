use std::fmt::Display;

use alloy::sol;

sol! {
    #[derive(Debug)]
    struct ForceDeployment {
        bytes32 bytecodeHash;
        address newAddress;
        bool callConstructor;
        uint256 value;
        bytes input;
    }
}

impl Display for ForceDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Force deploy: {} to {}",
            self.bytecodeHash, self.newAddress
        )
    }
}
