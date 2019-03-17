use chrono::{DateTime, TimeZone, Utc};

use crate::schema::types;


#[derive(Debug, Clone)]
pub struct Salt {
    valid_since: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    salt: i64,
}

impl From<types::FutureSalt> for Salt {
    fn from(fs: types::FutureSalt) -> Self {
        match fs {
            types::FutureSalt::future_salt(fs) => {
                Salt {
                    valid_since: Utc.timestamp(fs.valid_since as i64, 0), // from i32
                    valid_until: Utc.timestamp(fs.valid_until as i64, 0), // same here
                    salt: fs.salt,
                }
            },
        }
    }
}
