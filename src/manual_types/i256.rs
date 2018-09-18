use std::cmp;
use std::fmt::{self, Write};
use std::str;

use rand;


/// The smallest signed 256-bit integer (`-57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_968`).
pub const MIN: I256 = I256 { hi: i128::min_value(), lo: 0 };

/// The largest signed 256-bit integer (`57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_967`).
#[cfg(test)]
pub const MAX: I256 = I256 { hi: i128::max_value(), lo: !0 };

/// The constant `1`.
pub const ZERO: I256 = I256 { hi: 0, lo: 0 };

/// The constant `1`.
pub const ONE: I256 = I256 { hi: 0, lo: 1 };


/// A signed 256-bit number.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, Serialize, Deserialize, MtProtoSized)]
#[repr(C)]
pub struct I256 {
    #[cfg(target_endian = "little")]
    lo: u128,
    hi: i128,
    #[cfg(target_endian = "big")]
    lo: u128,
}

impl I256 {
    /// Constructs a new 256-bit integer from a 128-bit integer.
    pub fn new(n: i128) -> I256 {
        I256 {
            hi: n >> 127,
            lo: n as u128,
        }
    }

    /// Constructs a new 256-bit integer from the high-128-bit and low-128-bit
    /// parts.
    pub fn from_parts(hi: i128, lo: u128) -> I256 {
        I256 { hi, lo }
    }

    /// Fetch the lower-128-bit of the number.
    pub fn low128(self) -> u128 {
        self.lo
    }

    /// Fetch the higher-128-bit of the number.
    pub fn high128(self) -> i128 {
        self.hi
    }

    fn is_negative(self) -> bool {
        self.hi < 0
    }

    fn wrapping_add(self, other: I256) -> I256 {
        let (lo, carry) = self.lo.overflowing_add(other.lo);
        let hi = self.hi.wrapping_add(other.hi);
        let hi = hi.wrapping_add(if carry { 1 } else { 0 });
        I256::from_parts(hi, lo)
    }

    fn wrapping_sub(self, other: I256) -> I256 {
        let (lo, borrow) = self.lo.overflowing_sub(other.lo);
        let hi = self.hi.wrapping_sub(other.hi);
        let hi = hi.wrapping_sub(if borrow { 1 } else { 0 });
        I256::from_parts(hi, lo)
    }

    fn wrapping_neg(self) -> I256 {
        ONE.wrapping_add(not(self))
    }

    fn leading_zeros(self) -> u32 {
        if self.hi == 0 {
            128 + self.lo.leading_zeros()
        } else {
            self.hi.leading_zeros()
        }
    }
}


impl PartialOrd for I256 {
    fn partial_cmp(&self, other: &I256) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for I256 {
    fn cmp(&self, other: &I256) -> cmp::Ordering {
        (self.hi, self.lo).cmp(&(other.hi, other.lo))
    }
}

impl fmt::Display for I256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.hi == 0 {
            self.lo.fmt(f)
        } else if !self.is_negative() {
            const TEN38: I256 = I256 {
                hi: 0,
                lo: 100_000_000_000_000_000_000_000_000_000_000_000_000,  // 10^38
            };

            let mut buffer = [0u8; 77];
            let mut buf = FormatBuffer::new(&mut buffer);

            let (mid, lo) = div_rem(*self, TEN38);
            if mid.hi == 0 {
                write!(&mut buf, "{}{:038}", mid.lo, lo.lo)?;
            } else {
                let (hi, mid) = div_rem(mid, TEN38);
                write!(&mut buf, "{}{:038}{:038}", hi.lo, mid.lo, lo.lo)?;
            }

            f.pad_integral(true, "", buf.into_str())
        } else if *self == MIN {
            f.pad_integral(false, "", "57896044618658097711785492504343953926634992332820282019728792003956564819968")
        } else {
            assert!(self.is_negative());

            let mut buffer = [0u8; 77];
            let mut buf = FormatBuffer::new(&mut buffer);
            write!(&mut buf, "{}", self.wrapping_neg())?;
            f.pad_integral(false, "", buf.into_str())
        }
    }
}

impl fmt::Debug for I256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "I256({})", self)
    }
}

impl fmt::Binary for I256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.hi == 0 {
            self.lo.fmt(f)
        } else {
            let mut buffer = [0u8; 256];
            let mut buf = FormatBuffer::new(&mut buffer);

            write!(&mut buf, "{:b}{:0128b}", self.hi, self.lo)?;
            f.pad_integral(true, "0b", buf.into_str())
        }
    }
}

impl fmt::LowerHex for I256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.hi == 0 {
            self.lo.fmt(f)
        } else {
            let mut buffer = [0u8; 64];
            let mut buf = FormatBuffer::new(&mut buffer);

            write!(&mut buf, "{:x}{:032x}", self.hi, self.lo)?;
            f.pad_integral(true, "0x", buf.into_str())
        }
    }
}

impl fmt::UpperHex for I256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.hi == 0 {
            self.lo.fmt(f)
        } else {
            let mut buffer = [0u8; 64];
            let mut buf = FormatBuffer::new(&mut buffer);

            write!(&mut buf, "{:X}{:032X}", self.hi, self.lo)?;
            f.pad_integral(true, "0x", buf.into_str())
        }
    }
}


// A workaround for writing to arrays of bytes using the `fmt::Error`
// machinery instead of `io::Error` for error reporting
struct FormatBuffer<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> FormatBuffer<'a> {
    fn new(buffer: &mut [u8]) -> FormatBuffer {
        FormatBuffer { buffer, len: 0 }
    }

    #[cfg(test)]
    fn is_filled(&self) -> bool {
        assert!(self.len <= self.buffer.len());
        self.len == self.buffer.len()
    }

    fn into_str(self) -> &'a str {
        assert!(self.len <= self.buffer.len());
        str::from_utf8(&self.buffer[..self.len]).unwrap()
    }
}

impl<'a> fmt::Write for FormatBuffer<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let new_len = self.len + bytes.len();
        assert!(new_len <= self.buffer.len());
        self.buffer[self.len .. new_len].copy_from_slice(bytes);
        self.len = new_len;
        Ok(())
    }
}


#[cfg(test)]
mod show_tests {
    use super::*;

    macro_rules! assert_fmt_eq {
        ($expected:expr, $max_len:expr, $($args:expr),*) => {{
            use ::std::fmt::Write;

            let mut buffer = [0u8; $max_len];
            let mut buf = FormatBuffer::new(&mut buffer);
            write!(&mut buf, $($args),*).unwrap();
            assert!(buf.is_filled());
            assert_eq!($expected, buf.into_str());
        }}
    }

    #[test]
    fn show() {
        assert_fmt_eq!("0", 1, "{}", ZERO);
        assert_fmt_eq!("1", 1, "{}", ONE);
        assert_fmt_eq!("-1", 2, "{}", neg(ONE));
        assert_fmt_eq!("57896044618658097711785492504343953926634992332820282019728792003956564819967", 77, "{}", MAX);
        assert_fmt_eq!("-57896044618658097711785492504343953926634992332820282019728792003956564819967", 78, "{}", neg(MAX));
        assert_fmt_eq!("-57896044618658097711785492504343953926634992332820282019728792003956564819968", 78, "{}", MIN);
        assert_fmt_eq!("-11060352933915170951356902541139377940156763725492906083282599001109623830030", 78, "{}", I256::from_parts(-32503455979794992209719933608342387958, 292215322065297404942240754388108216818));
        assert_fmt_eq!("+0057896044618658097711785492504343953926634992332820282019728792003956564819967", 80, "{:+080}", MAX);
        assert_fmt_eq!("-0057896044618658097711785492504343953926634992332820282019728792003956564819968", 80, "{:+080}", MIN);

        // Sanity test
        assert_fmt_eq!("ff", 2, "{:x}", -1i8);
    }
}


impl rand::distributions::Distribution<I256> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> I256 {
        // Use LE; we explicitly generate one value before the next.
        // Explained in <https://docs.rs/rand/0.5.5/src/rand/distributions/integer.rs.html#48>.
        let lo = self.sample(rng);
        let hi = self.sample(rng);

        I256 { hi, lo }
    }
}


// Some operations that we don't want to put in trait impls yet (as trait impls are public)

fn neg(v: I256) -> I256 {
    if v == MIN {
        panic!("arithmetic operation overflowed");
    } else {
        v.wrapping_neg()
    }
}

fn not(v: I256) -> I256 {
    I256 {
        hi: !v.hi,
        lo: !v.lo,
    }
}


// ========== `div_rem` implementation ==========

fn sign_abs(x: I256) -> (bool, I256) {
    if x.is_negative() {
        (true, x.wrapping_neg())
    } else {
        (false, x)
    }
}

fn from_sign_abs(sign: bool, abs: I256) -> I256 {
    assert!(!abs.is_negative());

    if sign {
        abs.wrapping_neg()
    } else {
        abs
    }
}

fn div_rem(numerator: I256, denominator: I256) -> (I256, I256) {
    if denominator == ZERO {
        panic!("attempted to divide by zero");
    } else if cfg!(debug_assertions) && numerator == MIN && denominator == neg(ONE) {
        panic!("arithmetic operation overflowed");
    }

    let (sn, n) = sign_abs(numerator);
    let (sd, d) = sign_abs(denominator);
    let (div, rem) = div_rem_as_u256(n, d);
    (from_sign_abs(sn != sd, div), from_sign_abs(sn, rem))
}

fn shl_as_u256(x: I256, bits: u32) -> I256 {
    if bits >= 256 {
        ZERO
    } else if bits >= 128 {
        I256 {
            hi: (x.lo << (bits - 128)) as i128,
            lo: 0,
        }
    } else {
        I256 {
            hi: (((x.hi as u128) << bits) | (x.lo >> (128 - bits))) as i128,
            lo: x.lo << bits,
        }
    }
}

fn shr_as_u256(x: I256, bits: u32) -> I256 {
    if bits >= 256 {
        ZERO
    } else if bits >= 128 {
        I256 {
            hi: 0,
            lo: (x.hi as u128 >> (bits - 128)),
        }
    } else {
        I256 {
            hi: ((x.hi as u128) >> bits) as i128,
            lo: ((x.hi as u128) << (128 - bits)) | (x.lo >> bits),
        }
    }
}

fn div_rem_as_u256(n: I256, d: I256) -> (I256, I256) {
    if n < d {
        return (ZERO, n);
    }

    let div;
    let rem;

    match (n.hi, n.lo, d.hi, d.lo) {
        (0, x, 0, y) => {
            div = I256 { hi: 0, lo: x / y };
            rem = I256 { hi: 0, lo: x % y };
        },
        (x, 0, y, 0) => {
            assert!(x >= 0 && y >= 0);
            div = I256 { hi: 0, lo: (x / y) as u128 };
            rem = I256 { hi: x % y, lo: 0 };
        },
        (_, _, dh, 0) if (dh as u128).is_power_of_two() => {
            div = shr_as_u256(I256::new(n.hi), dh.trailing_zeros());
            rem = I256 {
                hi: n.hi & (dh - 1),
                lo: n.lo,
            };
        },
        (_, _, 0, dl) if dl.is_power_of_two() => {
            div = shr_as_u256(n, dl.trailing_zeros());
            rem = I256 {
                hi: 0,
                lo: n.lo & (dl - 1),
            };
        },
        _ => {
            let sr = d.leading_zeros() - n.leading_zeros() + 1;

            let mut q = shl_as_u256(n, 256 - sr);
            let mut r = shr_as_u256(n, sr);
            let mut carry = 0;

            for _ in 0..sr {
                r = shl_as_u256(r, 1);
                r.lo |= (q.hi as u128) >> 127;
                q = shl_as_u256(q, 1);
                q.lo |= carry;

                carry = 0;
                if r >= d {
                    r = r.wrapping_sub(d);  // FIXME?
                    carry = 1;
                }
            }

            q = shl_as_u256(q, 1);
            q.lo |= carry;

            rem = r;
            div = q;
        }
    };

    (div, rem)
}
