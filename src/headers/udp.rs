use crate::AsBeBytes;
use super::{Header, PacketData, Protocol, ParseError};

struct PseudoHeader {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    data_len: u16,
}

#[derive(AddGetter, AddSetter)]
#[get]
#[set]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    pseudo_header: Option<PseudoHeader>
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        UdpHeader {
            src_port: src_port,
            dst_port: dst_port,
            length: 8,
            checksum: 0,

            pseudo_header: None,
        }
    }

    pub fn set_pseudo_header(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], packet_data: &[u8]) {
        let len = packet_data.len();
        if len > (0xffff - 8) as usize {
            panic!("too much data");
        }
        self.length += len as u16;
        self.pseudo_header = Some(PseudoHeader {
            src_ip,
            dst_ip,
            protocol: 17, // 17 = UDP
            data_len: (len + 8) as u16,
        });
    }
}

impl Header for UdpHeader {
    fn make(self) -> PacketData {
        let src_p = self.src_port.split_to_bytes();
        let dst_p = self.dst_port.split_to_bytes();
        let length_bytes = self.length.split_to_bytes();
        let mut packet = vec![
            src_p[0],
            src_p[1],
            dst_p[0],
            dst_p[1],
            length_bytes[0],
            length_bytes[1],
            0,
            0
        ];

        // calculate checksum
        if let None = self.pseudo_header {
            panic!("Please set the pseudo header data before calculating the checksum");
        }
        let pseudo_header = self.pseudo_header.unwrap();
        let mut val = 0u32;
        val += ip_sum(pseudo_header.src_ip);
        val += ip_sum(pseudo_header.dst_ip);
        val += pseudo_header.protocol as u32;
        val += pseudo_header.data_len as u32;

        // add data to checksum
        val += pseudo_header.data_len as u32;
        let checksum = finalize_checksum(val).split_to_bytes();

        packet[6] = checksum[0];
        packet[7] = checksum[1];
        packet
    }

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError> {
        if raw_data.len() < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        Ok(Box::new(Self {
            src_port: ((raw_data[0] as u16) << 8) + raw_data[1] as u16,
            dst_port: ((raw_data[2] as u16) << 8) + raw_data[3] as u16,
            flags: raw_data[13],
            window: ((raw_data[14] as u16) << 8) + raw_data[15] as u16,
            pseudo_header: None,
        }))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::UDP
    }

    fn get_length(&self) -> u8 {
        8
    }

    fn get_min_length() -> u8 {
        8
    }
}

#[inline(always)]
fn ip_sum(octets: [u8; 4]) -> u32 {
    ((octets[0] as u32) << 8 | octets[1] as u32) + ((octets[2] as u32) << 8 | octets[3] as u32)
}

#[inline]
fn finalize_checksum(mut cs: u32) -> u16 {
    while cs >> 16 != 0 {
        cs = (cs >> 16) + (cs & 0xFFFF);
    }
    !cs as u16
}