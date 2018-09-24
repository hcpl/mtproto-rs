mod common;

pub(crate) use self::common::{KNOWN_RAW_KEYS, find_first_key};


cfg_if! {
    if #[cfg(all(test, feature = "non-openssl-impls", feature = "openssl"))] {
        pub(crate) mod num_bigint;
        pub(crate) mod openssl;
        mod tests;

        pub(crate) use self::num_bigint::RsaPublicKey;
    } else if #[cfg(feature = "non-openssl-impls")] {
        // Prefer non-OpenSSL implementations even if OpenSSL ones exist
        pub(crate) mod num_bigint;
        pub(crate) use self::num_bigint::RsaPublicKey;
    } else {
        pub(crate) mod openssl;
        pub(crate) use self::openssl::RsaPublicKey;
    }
}
