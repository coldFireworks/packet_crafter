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
        self.calculate_fields(&mut buf);
        self.selection.insert(buf.get_proto(), self.current_index);
        self.current_index += buf.get_length() as u32;
        self.buffer.extend(buf.make().into_iter());
    }

    /// used internally to call functions which calculate checsum and length fields when the header is added to the packet
    fn calculate_fields(&mut self, buf: &mut impl Header) {
        match buf.into_transport_header() {
            Some(th) => {
                match self.get_header_as_slice(Protocol::IP) {
                    Some(ip_header) => {
                        let src_ip: [u8; 4] = [ip_header[12], ip_header[13], ip_header[14], ip_header[15]];
                        let dst_ip: [u8; 4] = [ip_header[16], ip_header[17], ip_header[18], ip_header[19]];
                        let all_data_len: u16 = (self.buffer.len() + self.payload.len()) as u16;
                        th.set_pseudo_header(src_ip, dst_ip, all_data_len);
                    },
                    None => {}
                }
            }
            None => {}
        };
    }

    /// If the header already exists in the packet, it will be updated with the one passed to this function.
    /// if the header doesn't already exist in the packet, it will be added as if you'd called `add_header` instead.
    pub fn update_header(&mut self, mut new_buf: impl Header) {
        match self.selection.remove(&new_buf.get_proto()){
            Some(i) => {
                self.calculate_fields(&mut new_buf);
                let proto = new_buf.get_proto();
                self.selection.insert(proto, i);
                let mut data_vec = new_buf.make();
                let data = data_vec.as_mut_slice();
                let index: usize = i as usize;
                let section = unsafe { self.buffer.get_unchecked_mut(index..(index + proto.min_header_len() as usize)) };
                let mut i = 0;
                for byte in section.iter_mut() {
                    *byte = data[i];
                    i += 1;
                }
            },
            None => self.add_header(new_buf)
        }
    }

    /// Appends the given data to the payload of this packet
    pub fn extend_payload<T: IntoIterator<Item = u8>>(&mut self, buf: T) {
        self.payload.extend(buf);
    }

    /// consumes self and returns the buffer which is the cooked data packet.
    pub fn into_vec(mut self) -> Vec<u8> {

        // calculate ICMP checksum if present.
        // this needs to be done here as it should include the payload in the checksum calculation
        if self.selection.contains_key(&Protocol::ICMP) {
            let index: usize = *self.selection.get(&Protocol::ICMP).unwrap() as usize;
            let mut icmp_data: Vec<u8> = self.buffer[(index as usize)..].iter().map(|x| *x).collect(); // assuming here that icmp header is the last one, i.e. there are no more added after it
            if self.payload.len() > 0 {
                icmp_data.extend(self.payload.iter());
            }
            let checksum = checksum(&icmp_data, 1).split_to_bytes();
            self.buffer[index + 2] = checksum[0];
            self.buffer[index + 3] = checksum[1];
        }
        self.buffer.append(&mut self.payload);
        self.buffer
    }


    /// Try to create a `Packet` from raw packet data and populate it with the values in the given data packet
    pub fn parse(raw_data: &[u8]) -> Result<Self, ParseError> {
        let mut packet = Self::new_empty();
        if raw_data[0] >> 4 == 4 {
            packet.parse_ip_packet(raw_data)?;
            return Ok(packet);
        }
        packet.parse_ethernet_packet(raw_data)?;
        Ok(packet)
    }

    fn parse_ip_packet(&mut self, raw_data: &[u8]) -> Result<(), ParseError> {
        let ip_header = IpHeader::parse(raw_data)?;
        let next_protocol = Protocol::from(*ip_header.get_next_protocol());
        let ip_hdr_len = ip_header.get_length() as usize;
        self.add_header(ip_header);
        match next_protocol {
            Protocol::ETH => {
                self.add_header(EthernetHeader::parse(&raw_data[ip_hdr_len..])?); // Ethernet in ip encapsulation
            },
            Protocol::ICMP => {
                self.add_header(IcmpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::TCP => {
                self.add_header(TcpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::UDP => {
                self.add_header(UdpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            Protocol::IP => {
                self.add_header(IpHeader::parse(&raw_data[ip_hdr_len..])?);
            },
            _ => panic!("not a valid ip protocol"),
        }
        Ok(())
    }

    fn parse_ethernet_packet(&mut self, raw_data: &[u8]) -> Result<(), ParseError> {
        let hdr: Box<EthernetHeader> = EthernetHeader::parse(raw_data)?;
        let et = *hdr.get_eth_type();
        self.add_header(hdr);
        match et {
            ethertype_numbers::ETHERTYPE_IPV4 => {
                self.parse_ip_packet(&raw_data[(EthernetHeader::get_min_length() as usize)..])?;
            },
            ethertype_numbers::ETHERTYPE_ARP |
            ethertype_numbers::ETHERTYPE_IPV6 |
            ethertype_numbers::ETHERTYPE_RARP |
            ethertype_numbers::ETHERTYPE_LLDP => {
                return Err(ParseError::NotYetImplemented);
            },
            _ => return Err(ParseError::InvalidFormat)
        }
        Ok(())
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