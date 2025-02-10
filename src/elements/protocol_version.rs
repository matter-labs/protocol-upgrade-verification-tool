use std::{fmt, str::FromStr};
use alloy::primitives::U256;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct ProtocolVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidProtocolVersionError;

impl fmt::Display for InvalidProtocolVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid protocol version format")
    }
}

impl std::error::Error for InvalidProtocolVersionError {}

impl FromStr for ProtocolVersion {
    type Err = InvalidProtocolVersionError;

    fn from_str(version: &str) -> Result<Self, Self::Err> {
        let mut parts = version.split('.').map(str::parse::<u64>);
        
        let major = parts.next().ok_or(InvalidProtocolVersionError)?.map_err(|_| InvalidProtocolVersionError)?;
        let minor = parts.next().ok_or(InvalidProtocolVersionError)?.map_err(|_| InvalidProtocolVersionError)?;
        let patch = parts.next().ok_or(InvalidProtocolVersionError)?.map_err(|_| InvalidProtocolVersionError)?;
        
        if parts.next().is_some() {
            return Err(InvalidProtocolVersionError);
        }

        Ok(Self { major, minor, patch })
    }
}

impl From<U256> for ProtocolVersion {
    fn from(value: U256) -> Self {
        let rem: U256 = (1u64 << 32).try_into().unwrap();
        Self {
            major: (value.checked_shr(64.try_into().unwrap()).unwrap())
                .wrapping_rem(rem)
                .try_into()
                .unwrap(),
            minor: (value.overflowing_shr(32.try_into().unwrap()).0)
                .wrapping_rem(rem)
                .try_into()
                .unwrap(),
            patch: value.wrapping_rem(rem).try_into().unwrap(),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}
