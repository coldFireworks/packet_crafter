use crate::{protocol_numbers, AsBeBytes, checksum};
use super::{Header, TransportHeader, PacketData, Protocol, ParseError};
// use crate::net_tools::{checksum, protocol_numbers};

// Note: always v4 until I implement v6 functionality
#[derive(AddGetter, AddSetter)]
pub struct IpHeader {
    #[get] #[set]   tos: u8,
    #[get] #[set]   packet_len: u16,
    #[get] #[set]   identification: u16,
    #[get] #[set]   ttl: u8,
    #[get]          next_protocol: u8,
    #[get]          src_ip: [u8; 4],
    #[get] #[set]   dst_ip: [u8; 4],
}

impl IpHeader {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], next_proto: Protocol) -> Self {
        IpHeader {
            tos: 0,
            packet_len: 0,
            identification: 0,
            ttl: 64,
            next_protocol: next_proto.protocol_number(),
            src_ip: src_ip,
            dst_ip: dst_ip,
        }
    }

    pub fn set_next_protocol(&mut self, proto: Protocol) -> &mut Self {
        self.next_protocol = match proto {
            Protocol::ICMP => protocol_numbers::IPPROTO_ICMP,
            Protocol::TCP => protocol_numbers::IPPROTO_TCP,
            Protocol::UDP => protocol_numbers::IPPROTO_UDP,
            _ => panic!("Invalid Option for setting next level protocol"),
        };
        self
    }
}

impl Header for IpHeader {
    fn make(self) -> PacketData {
        let length_bytes = self.packet_len.split_to_bytes();
        let ident_bytes = self.identification.split_to_bytes();
        let mut packet = vec![
            0b01000101,      // set version to 4 and header length to 5 ("20 bytes")
            self.tos,        // service type is just left as routine (0)
            length_bytes[0], //total length of the packet in bytes
            length_bytes[1], //total length of the packet in bytes
            ident_bytes[0],               // Identification
            ident_bytes[1],               // Identification
            0b01000000,
            0,                  // flags and fragment offset
            self.ttl,           // ttl
            self.next_protocol, // next level protocol
            0,                  // checksum
            0,                  // checksum
            self.src_ip[0],
            self.src_ip[1],
            self.src_ip[2],
            self.src_ip[3],
            self.dst_ip[0],
            self.dst_ip[1],
            self.dst_ip[2],
            self.dst_ip[3],
        ];
        let checksum = checksum(&packet, 5).split_to_bytes();
        packet[10] = checksum[0];
        packet[11] = checksum[1];
        packet
    }

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError> {
        if raw_data.len() < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        Ok(Box::new(Self {
            tos: raw_data[1],
            packet_len: ((raw_data[2] as u16) << 8) + raw_data[3] as u16,
            identification: ((raw_data[4] as u16) << 8) + raw_data[5] as u16,
            ttl: raw_data[8],
            next_protocol: raw_data[9],
            src_ip: [raw_data[12], raw_data[13], raw_data[14], raw_data[15]],
            dst_ip: [raw_data[16], raw_data[17], raw_data[18], raw_data[19]],
        }))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::IP
    }

    fn get_length(&self) -> u8 {
        20 // this should reflect the actual packet, not the min length
    }

    fn get_min_length() -> u8 {
        20
    }

    fn into_transport_header(&mut self) -> Option<&mut dyn TransportHeader> {
        None
    }
}
