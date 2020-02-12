use crate::{protocol_numbers, AsBeBytes, checksum};
use super::{Header, PacketData, Protocol, ParseError};
// use crate::net_tools::{checksum, protocol_numbers};

// Note: always v4 until I implement v6 functionality
#[derive(AddGetter, AddSetter)]
pub struct IpHeader {
    #[get] #[set]   tos: u8,
    #[get] #[set]   packet_len: u16,
    #[get] #[set]   identification: u16,
                    ttl: u8,
    #[get]          next_protocol: u8,
                    proto_set: bool,
    #[get]          src_ip: [u8; 4],
    #[get] #[set]   dst_ip: [u8; 4],
    payload: Vec<u8>
}

impl IpHeader {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Self {
        IpHeader {
            tos: 0,
            packet_len: 0,
            identification: 0,
            ttl: 64,
            next_protocol: 0,
            proto_set: false,
            src_ip: src_ip,
            dst_ip: dst_ip,
            payload: Vec::new()
        }
    }

    pub fn set_next_protocol(&mut self, proto: Protocol) -> &mut Self {
        self.next_protocol = match proto {
            Protocol::ICMP => protocol_numbers::IPPROTO_ICMP,
            Protocol::TCP => protocol_numbers::IPPROTO_TCP,
            Protocol::UDP => protocol_numbers::IPPROTO_UDP,
            _ => panic!("Invalid Option for setting next level protocol"),
        };
        self.proto_set = true;
        self
    }
}

impl Header for IpHeader {
    fn make(self) -> PacketData {
        if !self.proto_set {
            panic!("Can not build IP header -> next protocol has not been set");
        }
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
        let data_len = raw_data.len();
        if data_len < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        let mut header = Self {
            tos: raw_data[1],
            packet_len: ((raw_data[2] as u16) << 8) + raw_data[3] as u16,
            identification: ((raw_data[4] as u16) << 8) + raw_data[5] as u16,
            ttl: raw_data[8],
            next_protocol: raw_data[9],
            proto_set: true,
            src_ip: [raw_data[12], raw_data[13], raw_data[14], raw_data[15]],
            dst_ip: [raw_data[16], raw_data[17], raw_data[18], raw_data[19]],
            payload: Vec::new()
        };
        if data_len > 20 {
            header.payload.extend(raw_data.into_iter().skip(20));
        }
        Ok(Box::new(header))
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

    fn set_payload(&mut self, data: Vec<u8>) {
        self.payload = data;
    }
}
