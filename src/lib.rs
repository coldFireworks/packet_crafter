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
    TcpHeader,
    UdpHeader
};
use std::collections::HashMap;

/// represents a network packet. can be used to build or parse packets.
#[derive(AddSetter)]
pub struct Packet {
    buffer: Vec<u8>,
    selection: HashMap<Protocol, u32>,
    current_index: u32,
    #[set]
    payload: Vec<u8>,
}

impl Packet {
    /// creates a new `Packet` with the internal buffer capacity set to the appropriate size for the header data.
    /// note that the headers arent created with this method, you still have to add them with add_header.
    pub fn new(protos: Vec<Protocol>) -> Self {
        Self {
            buffer: Vec::with_capacity(protos.iter().fold(0, |c, protocol| c + protocol.min_header_len()) as usize),
            selection: HashMap::new(),
            current_index: 0,
            payload: Vec::new(),
        }
    }

    /// Creates a new `Packet` with an empty internal buffer and the capacity is 0
    pub fn new_empty() -> Self {
        Self {
            buffer: Vec::new(),
            selection: HashMap::new(),
            current_index: 0,
            payload: Vec::new(),
        }
    }

    /// Adds the header into the internal packet buffer.
    /// If the header is TCP or UDP, this method will call the `set_pseudo_header` method for you,
    /// as this method is required to be called before calculating the checksum of the header
    pub fn add_header(&mut self, mut buf: impl Header) {
        let proto = buf.get_proto();
        match proto {
            Protocol::TCP | Protocol::UDP => {
                match self.get_header_as_slice(Protocol::IP) {
                    Some(ip_header) => {
                        let src_ip: [u8; 4] = [ip_header[12], ip_header[13], ip_header[14], ip_header[15]];
                        let dst_ip: [u8; 4] = [ip_header[16], ip_header[17], ip_header[18], ip_header[19]];
                        let all_data_len: u16 = (self.buffer.len() + self.payload.len()) as u16;
                        let th = buf.into_transport_header().unwrap();
                        th.set_pseudo_header(src_ip, dst_ip, all_data_len);
                    },
                    None => {}
                }
            }
            _ => {}
        }
        self.selection.insert(proto, self.current_index);
        self.current_index += buf.get_length() as u32;
        self.buffer.extend(buf.make().into_iter());
    }

    /// Appends the given data to the payload of this packet
    pub fn extend_payload<T: IntoIterator<Item = u8>>(&mut self, buf: T) {
        self.payload.extend(buf);
    }

    /// consumes self and returns the buffer which is the cooked data packet.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.buffer.append(&mut self.payload);
        self.buffer
    }


    /// Try to create a `Packet` from raw packet data and populate it with the values in the given data packet
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
                packet.add_header(UdpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::IP => {
                packet.add_header(IpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            _ => panic!("not a valid ip protocol"),
        }
        Ok(packet)
    }

    /// Returns `Option::Some(&[u8])` if the header is found in this packet, else None
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
    get_udp_header : Protocol::UDP : UdpHeader,
    get_icmp_header : Protocol::ICMP : IcmpHeader
);