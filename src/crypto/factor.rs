use ::error::{self, ErrorKind};
use ::utils::safe_uint_cast;


/// Decomposes a large composite number into 2 primes.
///
/// Uses [Fermat's factorization method][fermat].
///
/// [fermat]: https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
pub(crate) fn decompose_pq(pq: u64) -> error::Result<(u32, u32)> {
    let mut pq_sqrt = ceil_isqrt(pq);

    loop {
        let y_sqr = pq_sqrt * pq_sqrt - pq;
        if y_sqr == 0 { bail!(ErrorKind::FactorizationFailureSquarePq(pq)) }
        let y = ceil_isqrt(y_sqr);
        if y + pq_sqrt >= pq { bail!(ErrorKind::FactorizationFailureOther(pq)) }
        if y * y != y_sqr {
            pq_sqrt += 1;
            continue;
        }
        let p = safe_uint_cast::<u64, u32>(pq_sqrt + y)?;
        let q = safe_uint_cast::<u64, u32>(if pq_sqrt > y { pq_sqrt - y } else { y - pq_sqrt })?;
        let (p, q) = if p > q {(q, p)} else {(p, q)};
        trace!("decompose_pq({}) = ({}, {})", pq, p, q);
        return Ok((p, q))
    }
}

fn ceil_isqrt(x: u64) -> u64 {
    let mut ret = (x as f64).sqrt().trunc() as u64;
    while ret * ret > x { ret -= 1; }
    while ret * ret < x { ret += 1; }
    trace!("ceil_isqrt({}) == {}", x, ret);
    ret
}
