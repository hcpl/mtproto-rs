use std::fmt::{self, Write};
use std::str;

use rand;

use tl::dynamic::TLObject;


pub type Object = Box<TLObject>;
//pub use tl::dynamic::LengthAndObject;

#[derive(
    Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
    Serialize, Deserialize, MtProtoSized,
)]
#[repr(C)]
pub struct I256 {
    #[cfg(target_endian = "little")]
    lo: u128,
    hi: i128,
    #[cfg(target_endian = "big")]
    lo: u128,
}

impl I256 {
    pub fn from_parts(lo: u128, hi: i128) -> I256 {
        I256 { lo, hi }
    }

    pub fn low128(self) -> u128 {
        self.lo
    }

    pub fn high128(self) -> i128 {
        self.hi
    }
}

impl fmt::Display for I256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.hi == 0 {
            self.lo.fmt(f)
        } else {
            unimplemented!()
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

impl rand::distributions::Distribution<I256> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> I256 {
        // Use LE; we explicitly generate one value before the next.
        // Explained in <https://docs.rs/rand/0.5.5/src/rand/distributions/integer.rs.html#48>.
        let lo = self.sample(rng);
        let hi = self.sample(rng);

        I256 { lo, hi }
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
