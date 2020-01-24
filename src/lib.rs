#[macro_use] extern crate add_getters_setters;

pub mod protocol_numbers;
pub mod headers;
use headers::{EthernetHeader, ArpHeader, Header, IcmpHeader, IpHeader, TcpHeader};
use std::{
    collections::HashMap,
    slice,
    fmt
};

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

#[derive(Debug)]
pub enum ParseError {
    InvalidCharacter,
    InvalidLength,
    InvalidFormat
}

impl ParseError {
    pub fn get_msg(&self) -> &'static str {
        match self {
            Self::InvalidCharacter => "invalid character encountered",
            Self::InvalidLength => "invalid length for the protocol format",
            Self::InvalidFormat => "invalid format of data for the protocol",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse packet: {}", self.get_msg())
    }
}

impl std::error::Error for ParseError {}

type ProtocolNumber = u8;

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
            Self::ETH => EthernetHeader::get_min_length(),
            Self::ARP => ArpHeader::get_min_length(),
            Self::ICMP => IcmpHeader::get_min_length(),
            Self::TCP => TcpHeader::get_min_length(),
            Self::UDP => 0, // not yet implemented
            Self::IP => IpHeader::get_min_length(),
        }
    }

    pub fn protocol_number(&self) -> ProtocolNumber {
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

impl From<ProtocolNumber> for Protocol {
    fn from(p: ProtocolNumber) -> Protocol {
        match p {
            protocol_numbers::IPPROTO_ETHERIP => Protocol::ETH,
            protocol_numbers::IPPROTO_ICMP => Protocol::ICMP,
            protocol_numbers::IPPROTO_TCP => Protocol::TCP,
            protocol_numbers::IPPROTO_UDP => Protocol::UDP,
            protocol_numbers::IPPROTO_IPV4 => Protocol::IP,
            _ => panic!("Could not convert to Protocol enum"),
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
    selection: HashMap<Protocol, u32>,
    current_index: u32,
    #[set]
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(protos: Vec<Protocol>) -> Self {
        Self {
            buffer: Vec::with_capacity(protos.iter().fold(0, |c, protocol| c + protocol.min_header_len()) as usize),
            selection: HashMap::new(),
            current_index: 0,
            payload: Vec::new(),
        }
    }

    pub fn new_empty() -> Self {
        Self {
            buffer: Vec::new(),
            selection: HashMap::new(),
            current_index: 0,
            payload: Vec::new(),
        }
    }

    pub fn add_header(&mut self, buf: impl Header) {
        self.selection.insert(buf.get_proto(), self.current_index);
        self.current_index += buf.get_length() as u32;
        self.buffer.extend(buf.make().into_iter());
    }

    pub fn extend_payload<T: IntoIterator<Item = u8>>(&mut self, buf: T) {
        self.payload.extend(buf);
    }

    pub fn into_vec(self) -> Vec<u8> {
        // TODO: need to do some benchmarks to find the best way to do this
        self.buffer.into_iter().chain(self.payload).collect()
    }

    pub fn parse(raw_data: &[u8]) -> Result<Self, ParseError> {
        if raw_data[0] >> 4 != 4 { // TODO: not ip, probably arp, need to do a match statement on this
            return Err(ParseError::InvalidFormat);
        }
        // if IP:
        let ip_header = IpHeader::parse(raw_data)?;
        let mut packet = Self::new_empty();
        let next_protocol = Protocol::from(*ip_header.get_next_protocol());
        let ip_hdr_len = ip_header.get_length() as usize;
        packet.add_header(ip_header);
        match next_protocol {
            Protocol::ETH => {
                packet.add_header(EthernetHeader::parse(&raw_data[ip_hdr_len..])?); // Ethernet in ip encapsulation
            },
            Protocol::ICMP => {
                packet.add_header(IcmpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::TCP => {
                packet.add_header(IcmpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::UDP => {
                packet.add_header(IcmpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::IP => {
                packet.add_header(IcmpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            _ => panic!("not a valid ip protocol"),
        }
        Ok(packet)
    }

    /// Returns Some(&[u8]) if the header is found in this packet, else None
    pub fn get_header_as_slice(&self, p: Protocol) -> Option<&[u8]> {
        match self.selection.get(&p) {
            Some(index) => {
                Some(&self.buffer[(*index as usize)..])
            },
            None => None,
        }
    }
}

macro_rules! impl_get_header_methods {
    ( $($funname:ident : $proto:path : $ret:ty),* ) => (
        impl Packet {
            $(
                pub fn $funname(&self) -> Option<Box<$ret>> {
                    let index = self.selection.get(&$proto)?;
                    Some(<$ret>::parse(&self.buffer[(*index as usize)..]).unwrap())
                }
            )*
        }
    )
}

impl_get_header_methods!(
    get_ip_header : Protocol::IP : IpHeader,
    get_arp_header : Protocol::ARP : ArpHeader,
    get_eth_header : Protocol::ETH : EthernetHeader,
    get_tcp_header : Protocol::TCP : TcpHeader,
    get_icmp_header : Protocol::ICMP : IcmpHeader
);

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