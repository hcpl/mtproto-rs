use cfg_if::cfg_if;


cfg_if! {
    if #[cfg(all(test, feature = "non-openssl-impls", feature = "openssl"))] {
        pub(crate) mod openssl;
        pub(crate) mod rust_crypto;
        mod tests;

        pub(crate) use self::rust_crypto::{sha1_from_bytes, sha256_from_bytes};
    } else if #[cfg(feature = "non-openssl-impls")] {
        // Prefer non-OpenSSL implementations even if OpenSSL ones exist
        pub(crate) mod rust_crypto;
        pub(crate) use self::rust_crypto::{sha1_from_bytes, sha256_from_bytes};
    } else {
        pub(crate) mod openssl;
        pub(crate) use self::openssl::{sha1_from_bytes, sha256_from_bytes};
    }
}
