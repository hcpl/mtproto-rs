use byteorder::{ByteOrder, LittleEndian};
use num_traits::cast::cast;
use num_traits::int::PrimInt;
use num_traits::sign::Unsigned;
use openssl::hash;

use ::I256;
use ::error::{self, ErrorKind};


pub(crate) fn safe_uint_cast<T, U>(n: T) -> error::Result<U>
    where T: PrimInt + Unsigned,
          U: PrimInt + Unsigned,
{
    cast(n).ok_or_else(|| {
        let upcasted = cast::<T, u128>(n).unwrap();    // Shouldn't panic
        ErrorKind::UnsignedIntegerCast(upcasted).into()
    })
}


pub(crate) fn little_endian_i128_from_array(arr: &[u8; 16]) -> i128 {
    let lo = LittleEndian::read_u64(&arr[0..8]);
    let hi = LittleEndian::read_i64(&arr[8..16]);
    i128_from_parts(hi, lo)
}

pub(crate) fn little_endian_i128_into_array(n: i128) -> [u8; 16] {
    let mut arr = [0; 16];
    let (hi, lo) = i128_to_parts(n);
    LittleEndian::write_u64(&mut arr[0..8], lo);
    LittleEndian::write_i64(&mut arr[8..16], hi);
    arr
}

pub(crate) fn little_endian_i256_into_array(n: I256) -> [u8; 32] {
    let mut arr = [0; 32];
    little_endian_i256_to_array(&mut arr, n);
    arr
}

pub(crate) fn little_endian_i256_to_array(arr: &mut [u8; 32], n: I256) {
    let (lo128_hi, lo128_lo) = u128_to_parts(n.low128());
    let (hi128_hi, hi128_lo) = i128_to_parts(n.high128());

    LittleEndian::write_u64(&mut arr[0..8], lo128_lo);
    LittleEndian::write_u64(&mut arr[8..16], lo128_hi);
    LittleEndian::write_u64(&mut arr[16..24], hi128_lo);
    LittleEndian::write_i64(&mut arr[24..32], hi128_hi);
}

pub(crate) fn i128_from_parts(hi: i64, lo: u64) -> i128 {
    i128::from(hi) << 64 | i128::from(lo)
}

fn u128_to_parts(n: u128) -> (u64, u64) {
    let lo = n as u64;
    let hi = (n >> 64) as u64;
    (hi, lo)
}

fn i128_to_parts(n: i128) -> (i64, u64) {
    let lo = n as u64;
    let hi = (n >> 64) as i64;
    (hi, lo)
}


pub(crate) fn sha1_from_bytes(parts: &[&[u8]]) -> error::Result<hash::DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha1())?;
    for part in parts {
        hasher.update(part)?;
    }
    hasher.finish().map_err(Into::into)
}

pub(crate) fn sha256_from_bytes(parts: &[&[u8]]) -> error::Result<hash::DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256())?;
    for part in parts {
        hasher.update(part)?;
    }
    hasher.finish().map_err(Into::into)
}


macro_rules! bailf {
    ($e:expr) => {
        return Box::new(::futures::future::err($e.into()))
    }
}

macro_rules! tryf {
    ($e:expr) => {
        match { $e } {
            Ok(v) => v,
            Err(e) => bailf!(e),
        }
    }
}

macro_rules! array_int {
    ($($len:tt => $source:expr,)+) => {{
        let mut arr = [0; 0 $(+ $len)+];
        array_int! { @iter arr [] [$($len => $source,)+] }
        arr
    }};

    ($($len:tt => $source:expr),+) => {
        array_int! { $($len => $source,)+ }
    };

    (@iter
        $arr:ident
        [$($used_len:tt => $used_source:expr,)*]
        []
    ) => {};

    (@iter
        $arr:ident
        [$($used_len:tt => $used_source:expr,)*]
        [
            $first_unused_len:tt => $first_unused_source:expr,
            $($rest_unused_len:tt => $rest_unused_source:expr,)*
        ]
    ) => {
        $arr[(0 $(+ $used_len)*)..($first_unused_len $(+ $used_len)*)]
            .copy_from_slice($first_unused_source);
        array_int! { @iter
            $arr
            [
                $($used_len => $used_source,)*
                $first_unused_len => $first_unused_source,
            ]
            [$($rest_unused_len => $rest_unused_source,)*]
        }
    };
}
