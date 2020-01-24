use crate::{AsBeBytes, checksum};
use super::{Header, PacketData, Protocol, ParseError};

#[derive(AddGetter, AddSetter)]
#[get]
#[set]
pub struct IcmpHeader {
    msg_type: u8,
    code: u8,
    identifier: u16,
    sequence_number: u16,
}

impl IcmpHeader {
    pub fn new(msg_type: u8, code: u8, identifier: u16, sequence_number: u16) -> Self {
        IcmpHeader {
            msg_type,
            code,
            identifier,
            sequence_number
        }
    }
}

impl Header for IcmpHeader {
    fn make(self) -> PacketData {
        // some hosts dont seem to reply when sequence number is 0, even though in RFC 792 on page 14 it says it can be zero
        let ident_bytes = self.identifier.split_to_bytes();
        let sn_bytes = self.sequence_number.split_to_bytes();
        let mut packet: Vec<u8> = vec![
            self.msg_type,
            self.code,
            0,
            0,
            ident_bytes[0],
            ident_bytes[1],
            sn_bytes[1],
            sn_bytes[0],
        ];
        let checksum = checksum(&packet, 1).split_to_bytes();
        packet[2] = checksum[0];
        packet[3] = checksum[1];
        packet
    }

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError> {
        if raw_data.len() < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        Ok(Box::new(Self {
            msg_type: raw_data[0],
            code: raw_data[1],
            identifier: ((raw_data[4] as u16) << 8) + raw_data[5] as u16,
            sequence_number: ((raw_data[6] as u16) << 8) + raw_data[7] as u16,
        }))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::ICMP
    }


    fn get_length(&self) -> u8 {
        8
    }

    fn get_min_length() -> u8 {
        8
    }
}
