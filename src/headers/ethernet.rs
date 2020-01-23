use super::{Header, PacketData, Protocol};
use crate::AsBeBytes;

#[derive(AddGetter)]
pub struct EthernetHeader<MAC: Into<[u8; 6]>> {
    #[get]
    dst_mac: MAC,
    #[get]
    src_mac: MAC,
    ty: u16,
}

impl<MAC: Into<[u8; 6]>> EthernetHeader<MAC> {
    pub fn new(src_mac: MAC, dst_mac: MAC) -> Self {
        EthernetHeader {
            dst_mac: dst_mac,
            src_mac: src_mac,
            ty: 0x0800,
        }
    }
}

impl<MAC: Into<[u8; 6]>> Header for EthernetHeader<MAC> {
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
