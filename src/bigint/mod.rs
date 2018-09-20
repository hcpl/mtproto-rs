cfg_if! {
    // Prefer non-OpenSSL implementations even if OpenSSL ones exist
    if #[cfg(feature = "non-openssl-impls")] {
        pub(crate) mod num_bigint;
        pub(crate) use self::num_bigint::calc_g_pows_bytes;
    } else {
        pub(crate) mod openssl;
        pub(crate) use self::openssl::calc_g_pows_bytes;
    }
}
