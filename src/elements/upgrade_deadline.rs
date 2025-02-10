use std::fmt::Display;

use alloy::primitives::U256;
use chrono::DateTime;

pub struct UpgradeDeadline {
    pub deadline: U256,
}

impl From<U256> for UpgradeDeadline {
    fn from(value: U256) -> Self {
        Self { deadline: value }
    }
}

impl Display for UpgradeDeadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.deadline == U256::MAX {
            write!(f, "INFINITY")
        } else {
            let seconds_since_epoch = self.deadline.try_into();

            match seconds_since_epoch {
                Ok(seconds) => {
                    let datetime = DateTime::from_timestamp(seconds, 0).unwrap();
                    write!(f, "UTC Time: {}", datetime.format("%Y-%m-%d %H:%M:%S"))
                }
                Err(_) => write!(f, "Huge, but not infinity.. strange"),
            }
        }
    }
}
