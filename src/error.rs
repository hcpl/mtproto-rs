//! Error handling related to this crate.

error_chain! {
    links {
        SerdeMtProto(::serde_mtproto::Error, ::serde_mtproto::ErrorKind);
    }

    foreign_links {
        Base64Decode(::base64::DecodeError) #[cfg(feature = "non-openssl-impls")];
        Envy(::envy::Error);
        FromUtf8(::std::string::FromUtf8Error);
        Http(::http::Error);
        Hyper(::hyper::Error);
        Nom(::nom::Err<Vec<u8>>) #[cfg(feature = "non-openssl-impls")];
        Io(::std::io::Error);
        OpenSsl(::openssl::error::ErrorStack);
        TomlDeserialize(::toml::de::Error);
        Utf8(::std::str::Utf8Error);
    }

    errors {
        AuthKeyTooLong(expected_max_key_size: usize, found_key_in: Vec<u8>) {
            description("Authorization key is too long")
            display("Authorization key is too long (expected maximum {} bytes, found {:?})",
                expected_max_key_size, found_key_in)
        }

        WrongFingerprint(expected: i64, found: i64) {
            description("Wrong fingerprint of an encrypted message")
            display("Wrong fingerprint of an encrypted message (expected {}, found {})", expected, found)
        }

        NoServerSalts {
            description("No server salts found in the session")
            display("No server salts found in the session")
        }

        NotEnoughFields(type_or_variant: &'static str, fields_count_so_far: usize) {
            description("Not enough deserialized fields")
            display("Not enough deserialized fields for {}: {} fields deserialized so far",
                type_or_variant, fields_count_so_far)
        }

        Sha1Total255Longer {
            description("The input string is already longer than 255 bytes")
            display("The input string is already longer than 255 bytes")
        }

        RsaPublicKeyInvalid(raw_key: String) {
            description("RSA public key is invalid")
            display("RSA public key is invalid: {:?}", raw_key)
        }

        NoRsaPublicKeyForFingerprints(fingerprints: Vec<i64>) {
            description("No RSA public key found corresponding to any of specified fingerprints")
            display("No RSA public key found corresponding to any of specified fingerprints: {:?}",
                fingerprints)
        }

        NoModulus {
            description("No modulus found from a RSA key")
            display("No modulus found from a RSA key")
        }

        NoExponent {
            description("No exponent found from a RSA key")
            display("No exponent found from a RSA key")
        }

        FactorizationFailureSquarePq(pq: u64) {
            description("Factorization failed: pq is a square number")
            display("Factorization failed: pq = {} is a square number", pq)
        }

        FactorizationFailureOther(pq: u64) {
            description("Factorization failed: other reason")
            display("Factorization failed: other reason (pq = {})", pq)
        }

        SignedIntegerCast(num: i128) {
            description("error while casting a signed integer")
            display("error while casting a signed integer: {}", num)
        }

        UnsignedIntegerCast(num: u128) {
            description("error while casting an unsigned integer")
            display("error while casting an unsigned integer: {}", num)
        }

        NoAuthKey {
            description("Authorization key not found")
            display("Authorization key not found")
        }

        NoEncryptedDataLengthProvided {
            description("No encrypted data length provided to deserialize an encrypted message")
            display("No encrypted data length provided to deserialize an encrypted message")
        }

        UnknownConstructorId(type_or_variant: &'static str, ctor_id: u32) {
            description("Unknown constructor id found while deserializing")
            display("Unknown constructor id found while deserializing {}: {:#x}", type_or_variant, ctor_id)
        }

        MessageTooLong(len: usize) {
            description("Message is too long to send")
            display("Message of length {} is too long to send", len)
        }

        TcpFullModeResponseInvalidChecksum(expected: u32, found: u32) {
            description("Invalid CRC32 checksum of a response received via TCP in full mode")
            display("Invalid CRC32 checksum of a response received via TCP in full mode \
                     (expected {}, found {})", expected, found)
        }

        TcpErrorCode(code: i32) {
            description("RPC returned an error code")
            display("RPC returned a {} error code", code)
        }

        BadTcpMessage(found_len: usize) {
            description("Message length is neither 4, nor >= 24 bytes")
            display("Message length is neither 4, nor >= 24 bytes: {}", found_len)
        }

        HtmlErrorText(error_text: String) {
            description("RPC returned an HTML error")
            display("RPC returned an HTML error with text: {}", error_text)
        }

        BadHtmlMessage(found_len: usize) {
            description("Message is not HTML error and is < 24 bytes long")
            display("Message is not HTML error and is {} < 24 bytes long", found_len)
        }

        UnknownHtmlErrorStructure(html: String) {
            description("Unknown HTML error structure")
            display("Unknown HTML error structure:\n{}", html)
        }

        NonceMismatch(expected: i128, found: i128) {
            description("nonce mismatch")
            display("nonce mismatch (expected {:x}, found {:x})", expected, found)
        }

        ServerNonceMismatch(expected: i128, found: i128) {
            description("server nonce mismatch")
            display("server nonce mismatch (expected {:x}, found {:x})", expected, found)
        }

        NewNonceHashMismatch(
            expected_new_nonce: ::manual_types::i256::I256,
            found_hash: i128
        ) {
            description("new nonce hash mismatch")
            display("new nonce hash mismatch (expected new nonce = {:x}, found hash {:x})",
                expected_new_nonce, found_hash)
        }

        NewNonceDerivedHashMismatch(
            expected_new_nonce: ::manual_types::i256::I256,
            marker: u8,
            aux_hash: i64,
            found_hash: i128
        ) {
            description("new nonce derived hash mismatch")
            display(
                "new nonce derived hash mismatch \
                 (expected new nonce = {:x}, marker = {}, auth key aux hash = {:?}; found hash {:x})",
                expected_new_nonce, marker, aux_hash, found_hash)
        }

        Sha1Mismatch(expected: Vec<u8>, found: Vec<u8>) {
            description("SHA1 hash mismatch")
            display("SHA1 hash mismatch (expected {:?}, found {:?})", expected, found)
        }

        ServerDHParamsFail {
            description("server didn't send DH parameters")
            display("server didn't send DH parameters")
        }

        SetClientDHParamsAnswerFail {
            description("server failed to verify DH parameters")
            display("server failed to verify DH parameters")
        }
    }
}
