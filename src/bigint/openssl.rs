use openssl::bn;

use crate::error;


pub(crate) fn calc_g_pows_bytes(
    g: u32,
    g_a: &[u8],
    dh_prime: &[u8],
) -> error::Result<(Vec<u8>, Vec<u8>)> {
    // TODO: check that `dh_prime` is actually prime
    // TODO: check that `g` is a quadratic residue modulo `p`

    let mut ctx = bn::BigNumContext::new()?;

    let g = bn::BigNum::from_u32(g)?;
    let mut b = bn::BigNum::new()?;
    b.rand(2048, bn::MsbOption::ONE, true)?;
    let dh_prime = bn::BigNum::from_slice(dh_prime)?;
    let mut g_b = bn::BigNum::new()?;
    g_b.mod_exp(&g, &b, &dh_prime, &mut ctx)?;

    let g_a = bn::BigNum::from_slice(g_a)?;
    let mut g_ab = bn::BigNum::new()?;
    g_ab.mod_exp(&g_a, &b, &dh_prime, &mut ctx)?;

    Ok((g_b.to_vec(), g_ab.to_vec()))
}
