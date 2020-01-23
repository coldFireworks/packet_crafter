#[macro_use] extern crate add_getters_setters;

pub mod protocol_numbers;
pub mod headers;
use headers::{EthernetHeader, ArpHeader, Header, IcmpHeader, IpHeader, TcpHeader};
use std::{slice, fmt};

/// Converts a number to an array of its byte representation
pub trait AsBeBytes {
    type Output;

    fn split_to_bytes(&self) -> <Self as AsBeBytes>::Output;
}

macro_rules! impl_split_to_bytes {
    ($($prim_type:ident -> $num_bytes:expr),*) => ($(
        impl AsBeBytes for $prim_type {
            type Output = [u8; $num_bytes];

            fn split_to_bytes(&self) -> <Self as AsBeBytes>::Output {
                let mut bytes_arr = [0u8; $num_bytes];
                let mut i: usize = bytes_arr.len()-1;
                let mut x = self.clone();
                while x > 256 {
                    bytes_arr[i] = (x%256) as u8;
                    x = x >> 8;
                    i = i-1;
                }
                bytes_arr[i] = x as u8;
                bytes_arr
            }
        }
    )*)
}

impl_split_to_bytes!(u16 -> 2, u32 -> 4, u64 -> 8);

// manual implementation for u8 since u8 is byte, so just return self
impl AsBeBytes for u8 {
    type Output = u8;

    fn split_to_bytes(&self) -> u8 {
        self.clone()
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

#[inline(always)]
fn ip_sum(octets: [u8; 4]) -> u32 {
    ((octets[0] as u32) << 8 | octets[1] as u32) + ((octets[2] as u32) << 8 | octets[3] as u32)
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum Protocol {
    ETH,
    ARP,
    ICMP,
    TCP,
    UDP,
    IP,
}

impl Protocol {
    pub fn min_header_len(&self) -> u8 {
        match self {
            Self::ETH => EthernetHeader::<[u8; 6]>::get_min_length(),
            Self::ARP => ArpHeader::<[u8; 6]>::get_min_length(),
            Self::ICMP => IcmpHeader::get_min_length(),
            Self::TCP => TcpHeader::get_min_length(),
            Self::UDP => 0, // not yet implemented
            Self::IP => IpHeader::get_min_length(),
        }
    }

    pub fn protocol_number(&self) -> u8 {
        // returns the number of this protocol as of RFC 1700
        match self {
            Self::ETH => protocol_numbers::IPPROTO_ETHERIP,
            Self::ICMP => protocol_numbers::IPPROTO_ICMP,
            Self::TCP => protocol_numbers::IPPROTO_TCP,
            Self::UDP => protocol_numbers::IPPROTO_UDP,
            Self::IP => protocol_numbers::IPPROTO_IPV4,
            Self::ARP => panic!("ARP does not have an assigned ip protocol number"),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::ETH => write!(f, "Ethernet"),
            Protocol::ARP => write!(f, "Arp"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::IP => write!(f, "IP"),
        }
    }
}

#[derive(AddGetter, AddSetter)]
pub struct Packet {
    buffer: Vec<u8>,
    #[get]
    selection: Vec<Protocol>,
    #[set]
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(protos: Vec<Protocol>) -> Self {
        Self {
            buffer: Vec::with_capacity(protos.iter().fold(0, |c, protocol| c + protocol.min_header_len()) as usize),
            selection: protos,
            payload: vec![],
        }
    }

    pub fn new_empty() -> Self {
        Self {
            buffer: vec![],
            selection: vec![],
            payload: vec![],
        }
    }

    pub fn add_header(&mut self, buf: impl Header) {
        self.selection.push(buf.get_proto());
        self.buffer.extend(buf.make().into_iter());
    }

    pub fn add_payload_data<T: IntoIterator<Item = u8>>(&mut self, buf: T) {
        self.payload.extend(buf);
    }
}

// tests

#[cfg(test)]
mod tests {
    use super::{headers};
    #[test]
    fn icmp_checksum_is_calculated() {
        use headers::Header;
        // let p = Packet::new(vec![Protocol::ICMP]);
        let icmp_header = headers::IcmpHeader::new(8, 0, 0xd49e, 0);
        let data = icmp_header.make();
        assert_ne!(data[2], 0);
        assert_ne!(data[3], 0);
    }
}