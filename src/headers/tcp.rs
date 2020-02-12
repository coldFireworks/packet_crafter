use crate::AsBeBytes;
use super::{Header, PacketData, Protocol, ParseError};

struct PseudoHeader {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    data_len: u16,
}

#[derive(AddGetter, AddSetter)]
pub struct TcpHeader {
    #[get]
    #[set]
    src_port: u16,
    #[get]
    #[set]
    dst_port: u16,
    #[get]
    flags: u8,
    #[set]
    window: u16,
    pseudo_header: Option<PseudoHeader>,
    payload: Vec<u8>
}

pub enum TcpFlags {
    Urg,
    Ack,
    Psh,
    Rst,
    Syn,
    Fin,
}

impl TcpHeader {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        TcpHeader {
            src_port: src_port,
            dst_port: dst_port,
            window: 0xffff,
            flags: 0,
            pseudo_header: None,
            payload: Vec::new()
        }
    }

    pub fn set_flag(&mut self, f: TcpFlags) {
        match f {
            TcpFlags::Urg => self.flags = self.flags | 0b00100000,
            TcpFlags::Ack => self.flags = self.flags | 0b00010000,
            TcpFlags::Psh => self.flags = self.flags | 0b00001000,
            TcpFlags::Rst => self.flags = self.flags | 0b00000100,
            TcpFlags::Syn => self.flags = self.flags | 0b00000010,
            TcpFlags::Fin => self.flags = self.flags | 0b00000001,
        }
    }

    pub fn set_pseudo_header(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], packet_data: &[u8]) {
        let len = packet_data.len();
        if len > (0xffff - 20) as usize {
            panic!("too much data");
        }
        self.pseudo_header = Some(PseudoHeader {
            src_ip,
            dst_ip,
            protocol: 6, // 6 = tcp
            data_len: (len + 20) as u16,
        });
    }
}

impl Header for TcpHeader {
    fn make(self) -> PacketData {
        let src_p = self.src_port.split_to_bytes();
        let dst_p = self.dst_port.split_to_bytes();
        let window_bytes = self.window.split_to_bytes();
        let mut packet = vec![
            src_p[0],
            src_p[1],
            dst_p[0],
            dst_p[1],
            0,
            0,
            0,
            0, // Seq num
            0,
            0,
            0,
            0, // Ack num
            0, // Offset + 4 of the reserved bits, the other 2 of the 6 total reserved bits are included at the start of the `flags` byte
            self.flags,
            window_bytes[0],
            window_bytes[1],
            0,
            0,
            0,
            0, // Urgent Pointer -> Should do this at some point
        ];

        // calculate checksum
        if let None = self.pseudo_header {
            panic!("Please set the pseudo header data before calculating the checksum");
        }
        let pseudo_header = self.pseudo_header.unwrap();
        let mut val = 0u32;
        val += ip_sum(pseudo_header.src_ip);
        val += ip_sum(pseudo_header.dst_ip);
        val += pseudo_header.protocol as u32; // add the value of the protocol field. Since this field is preceeded by an empty reserved byte, it maintains its value so we can just add 6 to the value as so
        val += pseudo_header.data_len as u32; // header length (in bytes) : when there are no options+padding present, the header length is 20 bytes. this is a 16 bit field which is aligned on a boundary so we can just add this one aswell.
        // checksum over data
        let checksum = finalize_checksum(val).split_to_bytes();

        packet[16] = checksum[0];
        packet[17] = checksum[1];
        packet
    }

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError> {
        let data_len = raw_data.len();
        if data_len < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        let mut header = Self {
            src_port: ((raw_data[0] as u16) << 8) + raw_data[1] as u16,
            dst_port: ((raw_data[2] as u16) << 8) + raw_data[3] as u16,
            flags: raw_data[13],
            window: ((raw_data[14] as u16) << 8) + raw_data[15] as u16,
            pseudo_header: None,
            payload: Vec::new()
        };
        if raw_data.len() > 20 {
            header.payload.extend(raw_data.into_iter().skip(20));
        }
        Ok(Box::new(header))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::TCP
    }

    fn get_length(&self) -> u8 {
        20
    }

    fn get_min_length() -> u8 {
        20
    }

    fn set_payload(&mut self, data: Vec<u8>) {
        self.payload = data;
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