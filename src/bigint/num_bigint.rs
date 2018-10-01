use num_bigint::{BigUint, RandBigInt};
use rand;

use ::error;


const BITS: usize = 2048;
const DIGIT_BITS: usize = 32;
const DIGITS: usize = BITS / DIGIT_BITS;

pub(crate) fn calc_g_pows_bytes(
    g: u32,
    g_a: &[u8],
    dh_prime: &[u8],
) -> error::Result<(Vec<u8>, Vec<u8>)> {
    // TODO: check that `dh_prime` is actually prime
    // TODO: check that `g` is a quadratic residue modulo `p`

    let g = BigUint::new(vec![g as u32]);
    let b = gen_biguint_with_msb_one();  // FIXME: Make 2 leading ones for generated numbers
    assert_eq!(b.bits(), BITS);
    let dh_prime = BigUint::from_bytes_be(dh_prime);
    let g_b = BigUint::modpow(&g, &b, &dh_prime).to_bytes_be();

    let g_a = BigUint::from_bytes_be(&g_a);
    let g_ab = BigUint::modpow(&g_a, &b, &dh_prime).to_bytes_be();

    Ok((g_b, g_ab))
}

fn gen_biguint_with_msb_one() -> BigUint {
    let highest_bit_mask = {
        let mut digits = vec![0; DIGITS];
        digits[DIGITS - 1] = 0x8000_0000;
        BigUint::new(digits)
    };

    assert_eq!(highest_bit_mask.bits(), BITS);
    let random_value = rand::thread_rng().gen_biguint(BITS);  // FIXME: Use more secure RNG?

    random_value | highest_bit_mask
}
