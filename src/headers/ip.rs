use super::{Header, PacketData, ParseError, Protocol};
use crate::{checksum, protocol_numbers, AsBeBytes};
use std::net::IpAddr;

#[derive(AddGetter, AddSetter)]
pub struct IpHeader {
    #[get]
    #[set]
    tos: u8,
    #[get]
    #[set]
    packet_len: u16,
    #[get]
    #[set]
    identification: u16,
    #[get]
    #[set]
    ttl: u8,
    #[get]
    next_protocol: u8,
    #[get]
    src_ip: IpAddr,
    #[get]
    #[set]
    dst_ip: IpAddr,
}

impl IpHeader {
    /// Checks at runtime that we do not mix v4 and v6 addresses. Panics otherwise!
    ///
    /// When calling this function with the concrete IP version type or a array with the appropriate length you will
    /// get compile time guarantee that the versions match.
    pub fn new<IA: Into<IpAddr>>(src_ip: IA, dst_ip: IA, next_proto: Protocol) -> Self {
        let (src_ip, dst_ip) = (src_ip.into(), dst_ip.into());
        match (src_ip, dst_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => { /* OK */ }
            (IpAddr::V6(_), IpAddr::V6(_)) => { /* OK */ }
            _ => panic!("Invalid IP versions, must not mix IPv4 and IPv6"),
        };
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
    #[cfg(target_endian = "little")]
    /// needs testing on a big endian machine
    fn make(self) -> PacketData {
        use IpAddr::{V4, V6};

        match (&self.src_ip, &self.dst_ip) {
            (&V4(src_ip), &V4(dst_ip)) => {
                let (src_ip, dst_ip) = (src_ip.octets(), dst_ip.octets());

                let length_bytes = self.packet_len.split_to_bytes();
                let ident_bytes = self.identification.split_to_bytes();

                let mut packet = vec![
                    0b0100_0101,      // set version to 4 and header length to 5 ("20 bytes")
                    self.tos,        // service type is just left as routine (0)
                    length_bytes[0], //total length of the packet in bytes
                    length_bytes[1], //total length of the packet in bytes
                    ident_bytes[0],  // Identification
                    ident_bytes[1],  // Identification
                    0b0100_0000,
                    0,                  // flags and fragment offset
                    self.ttl,           // ttl
                    self.next_protocol, // next level protocol
                    0,                  // checksum
                    0,                  // checksum
                    src_ip[0],
                    src_ip[1],
                    src_ip[2],
                    src_ip[3],
                    dst_ip[0],
                    dst_ip[1],
                    dst_ip[2],
                    dst_ip[3],
                ];
                let checksum = checksum(&packet, 5).split_to_bytes();
                packet[10] = checksum[0];
                packet[11] = checksum[1];
                packet
            }
            (&V6(src_ip), &V6(dst_ip)) => {
                let (src_ip, dst_ip) = (src_ip.octets(), dst_ip.octets());

                // based on [RFC8200](https://tools.ietf.org/html/rfc8200#page-6)
                let traffic_class: u8 = 0;
                // 20bit
                let flow_label: u32 = 0;
                assert!(
                    flow_label < 2u32.pow(20),
                    "flow label must not exceed 20bit, was {:?}",
                    flow_label
                );

                // Lenght of payload + IPv6 extension headers (todo)
                let payload_len: u16 = self.packet_len;

                let mut packet = vec![
                    (6u8 << 4/* version */) + (traffic_class >> 4),
                    (traffic_class << 4) + (flow_label >> (32 - 20)) as u8,
                    (flow_label >> 8) as u8,
                    flow_label as u8,
                    (payload_len >> 8) as u8,
                    payload_len as u8,
                    self.next_protocol,
                    self.ttl, // hop limit
                ];

                packet.extend_from_slice(&src_ip);
                packet.extend_from_slice(&dst_ip);

                packet
            }
            _ => unreachable!(),
        }
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
            // TODO handle v6
            src_ip: [raw_data[12], raw_data[13], raw_data[14], raw_data[15]].into(),
            // TODO handle v6
            dst_ip: [raw_data[16], raw_data[17], raw_data[18], raw_data[19]].into(),
        }))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::IP
    }

    fn get_length(&self) -> u8 {
        // TODO this should reflect the actual packet, not the min length
        match self.src_ip {
            IpAddr::V4(_) => 20, 
            IpAddr::V6(_) => 40, 
        }
    }

    fn get_min_length() -> u8 {
        20
    }
}
