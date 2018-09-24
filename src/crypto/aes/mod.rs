mod common;

pub(crate) use self::common::{
    AesParams,
    calc_aes_params_decrypt_v1,
    calc_aes_params_decrypt_v2,
    calc_aes_params_encrypt_v1,
    calc_aes_params_encrypt_v2,
};


cfg_if! {
    if #[cfg(all(test, feature = "non-openssl-impls", feature = "openssl"))] {
        pub(crate) mod openssl;
        pub(crate) mod rust_crypto;
        mod tests;

        pub(crate) use self::rust_crypto::{aes_ige_decrypt, aes_ige_encrypt};
    } else if #[cfg(feature = "non-openssl-impls")] {
        // Prefer non-OpenSSL implementations even if OpenSSL ones exist
        pub(crate) mod rust_crypto;
        pub(crate) use self::rust_crypto::{aes_ige_decrypt, aes_ige_encrypt};
    } else {
        pub(crate) mod openssl;
        pub(crate) use self::openssl::{aes_ige_decrypt, aes_ige_encrypt};
    }
}
