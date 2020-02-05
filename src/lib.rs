#[macro_use] extern crate add_getters_setters;

pub mod protocol_numbers;
pub mod ethertype_numbers;
pub mod headers;
mod protocol;
mod helpers;

pub use protocol::*;
pub use helpers::*;
use headers::{
    Header,
    EthernetHeader,
    ArpHeader,
    IcmpHeader,
    IpHeader,
    TcpHeader
};
use std::collections::HashMap;

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
    /// creates a new packet builder with the internal buffer capacity set to the appropriate size for the header data.
    /// note that the headers arent created with this method, you still have to add them with add_header.
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

    pub fn add_header(&mut self, buf: impl headers::Header) {
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
                packet.add_header(TcpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::UDP => {
                // packet.add_header(IcmpHeader::parse(&raw_data[ip_hdr_len..])?);
                panic!("UDP not yet implemented")
            },
            Protocol::IP => {
                packet.add_header(IpHeader::parse(&raw_data[ip_hdr_len..])?);
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


#[cfg(test)]
mod tests {
    use super::{headers, AsBeBytes};
    #[test]
    fn icmp_checksum_is_calculated() {
        use headers::Header;
        // let p = Packet::new(vec![Protocol::ICMP]);
        let icmp_header = headers::IcmpHeader::new(8, 0, 0xd49e, 0);
        let data = icmp_header.make();
        assert_ne!(data[2], 0);
        assert_ne!(data[3], 0);
    }

    #[test]
    fn test_1_byte_u16_to_bytes() {
        let x = 12u16;
        assert_eq!([0, 12], x.split_to_bytes());
    }

    #[test]
    fn test_2_byte_u16_to_bytes() {
        let x: u16 = 0b00100001_00101100;
        assert_eq!([0b00100001, 0b00101100], x.split_to_bytes());
    }

    // #[bench]
    // fn bench_split_to_bytes(b: &mut Bencher) {
    //     b.iter(|| test::black_box(300u16.split_to_bytes()));
    // }
}