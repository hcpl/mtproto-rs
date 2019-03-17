use crate::crypto::rsa::{common, num_bigint, openssl};


const ZERO_MARKER_BYTE_LEN: usize = 1;
const SHA1_BYTES_LEN: usize = 20;
const MAX_INPUT_LEN: usize = 256 - ZERO_MARKER_BYTE_LEN - SHA1_BYTES_LEN;

const INPUT: [u8; MAX_INPUT_LEN] = [
     86,  98, 166, 209, 141, 214,  83, 250, 148, 133, 176,  85,   6,  29, 113, 247, 
    216,  56, 146,  70, 200,  33,  15, 251,  27,   0, 120,  93, 132, 108, 136, 102, 
    187,  59, 124,  39, 199, 231, 223, 100, 179, 191, 127,  94, 109, 149,  88, 121, 
     25, 255, 134, 233, 114, 252, 162,  46, 155, 217, 175, 195,  28,  55, 140,  49, 
     13, 230,  58,   7, 126,  18,  50, 249, 201,  31,  21, 178,  79, 211, 181,  67, 
    243,  12, 220,  87, 254,  80, 234,  35, 111, 150,  71, 192, 158, 177, 190, 101, 
    186, 206, 219,  54, 224, 142, 160, 246, 164, 212, 225,  84, 115,  60,  40,  52, 
     90,   8,  73,  82,  89, 229,  30,  34,  42, 183, 103, 118, 210, 154, 170,  20, 
    207, 239,   1,  37, 188,  81, 196, 117, 147, 122,  92, 245,  99,  23,  22,  69, 
    165,  72, 138,  24,   9,   2, 161,  64, 129, 167,  78, 125, 185,  97, 112,  74, 
     32, 169,  43,  66,  19, 227, 131, 241, 159, 198,  96,  11,   3, 240, 152, 194, 
    151,   5, 119,  38, 123, 232, 204,  76,  44,  91, 156, 197,  17,  53, 215, 228, 
    202, 218,  61,  10, 105,  47, 238,  77, 145, 182, 172, 168, 248, 173, 144, 174, 
    242, 180, 104,  45, 213,  63, 203, 193, 110, 153, 128,  48,  14, 244, 137, 237, 
     57,  65, 189,   4, 236,  62, 157,  51, 205, 184, 226,
];


#[test]
fn sha1_fingerprint() {
    const EXPECTED: [u8; 20] = [
        40,  85,  94, 156, 117, 240,  61,  22,
        65, 244, 169,   2,  33, 107, 232, 108,
         2,  43, 180, 195,
    ];

    let pkey_num_bigint = num_bigint::RsaPublicKey::new(common::KNOWN_RAW_KEYS[0]).unwrap();
    let res_num_bigint = pkey_num_bigint.sha1_fingerprint().unwrap();

    let pkey_openssl = openssl::RsaPublicKey::new(common::KNOWN_RAW_KEYS[0]).unwrap();
    let res_openssl = pkey_openssl.sha1_fingerprint().unwrap();

    assert_eq!(res_num_bigint, EXPECTED);
    assert_eq!(res_openssl, EXPECTED);
    assert_eq!(res_num_bigint, res_openssl);
}

#[test]
fn fingerprint() {
    const EXPECTED: i64 = -0x3c4bd4fd931794df;

    let pkey_num_bigint = num_bigint::RsaPublicKey::new(common::KNOWN_RAW_KEYS[0]).unwrap();
    let res_num_bigint = pkey_num_bigint.fingerprint().unwrap();

    let pkey_openssl = openssl::RsaPublicKey::new(common::KNOWN_RAW_KEYS[0]).unwrap();
    let res_openssl = pkey_openssl.fingerprint().unwrap();

    assert_eq!(res_num_bigint, EXPECTED);
    assert_eq!(res_openssl, EXPECTED);
    assert_eq!(res_num_bigint, res_openssl);
}

#[test]
fn encrypt() {
    const EXPECTED: [u8; 256] = [
        181,  22, 163, 134,  64,  97, 196, 195, 153, 222, 204, 100,  63, 129, 181,  10,
         82, 145,  20, 172, 176, 168, 142,  76,  47, 237,  36,  28, 218, 182, 249, 101,
        250, 194, 162, 195, 230, 233, 156, 236, 138,  72, 254, 117,  67, 242, 114,  34,
        187, 222, 124,   7,  58,  21, 245, 222, 118,  38, 132,  48, 166,  96,  74, 225,
         52, 226,  28, 205, 239, 157,  54, 116, 159, 162,  51,  66, 129, 194, 131,  21,
         18, 199, 221, 244, 118, 220,  80,  96, 103,  54,  62, 224,   5,   9, 237, 204,
        214,  31,  68,  27, 103,  77,  57, 110,  69, 241, 240,  84, 221, 144,  49, 148,
        139, 100, 207,  77, 109,  47,  21,  57,  66,   7,  66, 232, 189,  36, 132, 255,
        236, 180, 124, 123, 175, 191,  20, 171, 157, 135, 221,  67,  73,  55, 235, 105,
         48,  93,  13,  14, 209,  16,  87, 112, 245, 106, 166,   5,   1, 126, 218, 222,
        110, 154, 139,  19,  94, 148, 144, 195, 142, 247,  72, 196, 102, 100, 137, 167,
         65, 183, 152, 159, 173,  92,  79, 207,  24, 177,  92, 128, 225,   6, 244, 193,
         67, 143, 170, 229, 202,  33,  46,  70,  48,  31,  57, 170,  36, 206, 110,  93,
        241, 125,  87, 136, 164,  91, 214,  58, 220,  67, 134, 183, 159,   3, 218, 176,
        101, 123, 225, 189,   9,  53, 111, 200, 151,  78,  68,  81,  15, 235, 234, 253,
         82, 162, 189,  26, 153, 147,  80, 156, 212, 255, 103, 214,  23,  70, 249, 177,
    ];

    let pkey_num_bigint = num_bigint::RsaPublicKey::new(common::KNOWN_RAW_KEYS[0]).unwrap();
    let res_num_bigint = pkey_num_bigint.encrypt(&INPUT).unwrap();

    let pkey_openssl = openssl::RsaPublicKey::new(common::KNOWN_RAW_KEYS[0]).unwrap();
    let res_openssl = pkey_openssl.encrypt(&INPUT).unwrap();

    assert_eq!(res_num_bigint[..], EXPECTED[..]);
    assert_eq!(res_openssl[..], EXPECTED[..]);
    assert_eq!(res_num_bigint[..], res_openssl[..]);
}
