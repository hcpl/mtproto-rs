cfg_if! {
    // Prefer non-OpenSSL implementations even if OpenSSL ones exist
    if #[cfg(feature = "non-openssl-impls")] {
        pub(crate) mod rust_crypto;
        pub(crate) use self::rust_crypto::{sha1_from_bytes, sha256_from_bytes};
    } else {
        pub(crate) mod openssl;
        pub(crate) use self::openssl::{sha1_from_bytes, sha256_from_bytes};
    }
}
