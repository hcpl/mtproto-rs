mod common;

pub(crate) use self::common::{KNOWN_RAW_KEYS, find_first_key};


cfg_if! {
    // Prefer non-OpenSSL implementations even if OpenSSL ones exist
    if #[cfg(feature = "non-openssl-impls")] {
        pub(crate) mod num_bigint;
        pub(crate) use self::num_bigint::RsaPublicKey;
    } else {
        pub(crate) mod openssl;
        pub(crate) use self::openssl::RsaPublicKey;
    }
}
