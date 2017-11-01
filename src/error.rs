//! Error handling related to this crate.

error_chain! {
    links {
        SerdeMtProto(::serde_mtproto::Error, ::serde_mtproto::ErrorKind);
    }

    foreign_links {
        Envy(::envy::Error);
        FromUtf8(::std::string::FromUtf8Error);
        Io(::std::io::Error);
        OpenSsl(::openssl::error::ErrorStack);
        TomlDeserialize(::toml::de::Error);
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

        IntegerCast(num: u64) {
            description("Error while casting an integer")
            display("Error while casting an integer: {}", num)
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

        ErrorCode(code: i32) {
            description("RPC returned an error code")
            display("RPC returned a {} error code", code)
        }

        BadMessage(found_len: usize) {
            description("Message length is neither 4, nor >= 24 bytes")
            display("Message length is neither 4, nor >= 24 bytes: {}", found_len)
        }
    }
}
