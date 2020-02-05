use super::{Header, PacketData, Protocol, ParseError};
use crate::AsBeBytes;

#[derive(AddGetter, AddSetter)]
pub struct EthernetHeader {
    #[get]
    dst_mac: [u8; 6],

    #[get]
    src_mac: [u8; 6],

    #[get]
    #[set]
    ty: u16,
}

impl EthernetHeader {
    pub fn new(src_mac: [u8; 6], dst_mac: [u8; 6], ty: u16) -> Self {
        EthernetHeader {
            dst_mac: dst_mac,
            src_mac: src_mac,
            ty: ty,
        }
    }
}

impl Header for EthernetHeader {
    #[allow(unused_variables)]
    fn make(self) -> PacketData {
        let tyb = self.ty.split_to_bytes();
        let dst_mac: [u8; 6] = self.dst_mac.into();
        let src_mac: [u8; 6] = self.src_mac.into();
        vec![
            dst_mac[0],
            dst_mac[1],
            dst_mac[2],
            dst_mac[3],
            dst_mac[4],
            dst_mac[5],
            src_mac[0],
            src_mac[1],
            src_mac[2],
            src_mac[3],
            src_mac[4],
            src_mac[5],
            tyb[0],
            tyb[1],
        ]
    }

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError> {
        if raw_data.len() < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        Ok(Box::new(Self {
            dst_mac: [raw_data[0], raw_data[1], raw_data[2], raw_data[3], raw_data[4], raw_data[5]],
            src_mac: [raw_data[6], raw_data[7], raw_data[8], raw_data[9], raw_data[10], raw_data[11]],
            ty: ((raw_data[12] as u16) << 8) + raw_data[13] as u16
        }))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::ETH
    }

    fn get_length(&self) -> u8 {
        14
    }

    fn get_min_length() -> u8 {
        14
    }
}
