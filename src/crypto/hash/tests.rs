use crate::crypto::hash::{openssl, rust_crypto};


// For syncing with `EXPECTED` arrays
const INPUTS_COUNT: usize = 3;
const INPUTS: [&[&[u8]]; INPUTS_COUNT] = [
    &[b""],
    &[b"Hello, world!"],
    &[b"foo", b"bar", b"baz"],
];

#[test]
fn sha1() {
    const EXPECTED: [[u8; 20]; INPUTS_COUNT] = [
        [
            218,  57, 163, 238,  94, 107,  75,  13,
             50,  85, 191, 239, 149,  96,  24, 144,
            175, 216,   7,   9,
        ],
        [
            148,  58, 112,  45,   6, 243,  69, 153,
            174, 225, 248, 218, 142, 249, 247,  41,
             96,  49, 214, 153,
        ],
        [
             95,  85,  19, 248, 130,  47, 219, 229,
             20,  90, 243,  59, 100, 216, 217, 112,
            220, 249,  92, 110,
        ],
    ];

    for (input, expected) in INPUTS.iter().zip(EXPECTED.iter()) {
        let res_openssl = openssl::sha1_from_bytes(input).unwrap();
        let res_rust_crypto = rust_crypto::sha1_from_bytes(input).unwrap();

        assert_eq!(*res_openssl, *expected);
        assert_eq!(*res_rust_crypto, *expected);
        assert_eq!(*res_openssl, *res_rust_crypto);
    }
}

#[test]
fn sha256() {
    const EXPECTED: [[u8; 32]; INPUTS_COUNT] = [
        [
            227, 176, 196,  66, 152, 252,  28,  20,
            154, 251, 244, 200, 153, 111, 185,  36,
             39, 174,  65, 228, 100, 155, 147,  76,
            164, 149, 153,  27, 120,  82, 184,  85,
        ],
        [
             49,  95,  91, 219, 118, 208, 120, 196,
             59, 138, 192,   6,  78,  74,   1, 100,
             97,  43,  31, 206, 119, 200, 105,  52,
             91, 252, 148, 199,  88, 148, 237, 211,
        ],
        [
            151, 223,  53, 136, 181, 163, 242,  75,
            171, 195, 133,  27,  55,  47,  11, 167,
             26, 157, 205, 222, 212,  59,  20, 185,
            208, 105,  97, 191, 193, 112, 125, 157,
        ],
    ];

    for (input, expected) in INPUTS.iter().zip(EXPECTED.iter()) {
        let res_openssl = openssl::sha256_from_bytes(input).unwrap();
        let res_rust_crypto = rust_crypto::sha256_from_bytes(input).unwrap();

        assert_eq!(*res_openssl, *expected);
        assert_eq!(*res_rust_crypto, *expected);
        assert_eq!(*res_openssl, *res_rust_crypto);
    }
}
