use std::{fmt, slice};

/// Converts a number to an array of its byte representation
pub trait AsBeBytes {
    type Output;

    fn split_to_bytes(self) -> <Self as AsBeBytes>::Output;
}

macro_rules! impl_split_to_bytes {
    ($($prim_type:ident -> $num_bytes:expr),*) => ($(
        impl AsBeBytes for $prim_type {
            type Output = [u8; $num_bytes];

            fn split_to_bytes(mut self) -> <Self as AsBeBytes>::Output {
                let mut bytes_arr = [0u8; $num_bytes];
                let mut i: usize = bytes_arr.len()-1;
                while self > 256 {
                    bytes_arr[i] = (self%256) as u8;
                    self = self >> 8;
                    i = i-1;
                }
                bytes_arr[i] = self as u8;
                bytes_arr
            }
        }
    )*)
}

impl_split_to_bytes!(u16 -> 2, u32 -> 4, u64 -> 8);

// manual implementation for u8 since u8 is byte, so just return self
impl AsBeBytes for u8 {
    type Output = u8;

    fn split_to_bytes(self) -> u8 {
        self
    }
}


// Checksum algorithms:

/// Calculates a checksum. Used by ipv4 and icmp. The two bytes starting at `skipword * 2` will be
/// ignored. Supposed to be the checksum field, which is regarded as zero during calculation.
pub fn checksum(data: &[u8], skipword: usize) -> u16 {
    finalize_checksum(sum_be_words(data, skipword))
}

/// Finalises a checksum by making sure its 16 bits, then returning it's 1's compliment
#[inline]
fn finalize_checksum(mut cs: u32) -> u16 {
    while cs >> 16 != 0 {
        cs = (cs >> 16) + (cs & 0xFFFF);
    }
    !cs as u16
}

/// Return the sum of the data as 16-bit words (assumes big endian)
pub fn sum_be_words(d: &[u8], mut skipword: usize) -> u32 {
    let len = d.len();
    let word_data: &[u16] = unsafe { slice::from_raw_parts(d.as_ptr() as *const u16, len / 2) };
    let word_data_length = word_data.len();
    skipword = ::std::cmp::min(skipword, word_data_length);

    let mut sum = 0u32;
    let mut i = 0;
    while i < word_data_length {
        if i == skipword && i != 0 {
            i += 1;
            continue;
        }
        sum += u16::from_be(unsafe { *word_data.get_unchecked(i) }) as u32;
        i += 1;
    }
    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 {
        sum += (unsafe { *d.get_unchecked(len - 1) } as u32) << 8;
    }

    sum
}

#[derive(Debug)]
pub enum ParseError {
    InvalidCharacter,
    InvalidLength,
    InvalidFormat,
    NotYetImplemented
}

impl ParseError {
    pub fn get_msg(&self) -> &'static str {
        match self {
            Self::InvalidCharacter => "invalid character encountered",
            Self::InvalidLength => "invalid length for the protocol format",
            Self::InvalidFormat => "invalid format of data for the protocol",
            Self::NotYetImplemented => "the implementation for parsing this type of packet has not yet been made"
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse packet: {}", self.get_msg())
    }
}

impl std::error::Error for ParseError {}