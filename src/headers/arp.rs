use super::{Header, PacketData, Protocol};
use crate::AsBeBytes;

pub const REQUEST: u16 = 1;
pub const REPLY: u16 = 2;

#[derive(AddGetter, AddSetter)]
pub struct ArpHeader<MAC: Into<[u8; 6]>> {
    hardware_type: u16,
    protocol_type: u16,
    hardware_size: u8,
    protocol_size: u8,
    #[get] #[set] opcode: u16,
    #[get] #[set] sender_mac: MAC,
    #[get] #[set] sender_ip: [u8; 4],
    #[get] #[set] destination_mac: MAC,
    #[get] #[set] destination_ip: [u8; 4],
}

impl<MAC: Into<[u8; 6]>> ArpHeader<MAC> {
    pub fn new<T: Into<[u8; 4]>>(sender_mac: MAC, sender_ip: T, destination_mac: MAC, destination_ip: T) -> Self {
        ArpHeader {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_size: 6,
            protocol_size: 4,
            opcode: REQUEST,
            sender_mac: sender_mac,
            sender_ip: sender_ip.into(),
            destination_mac: destination_mac,
            destination_ip: destination_ip.into(),
        }
    }
}

impl<MAC: Into<[u8; 6]>> Header for ArpHeader<MAC> {
    fn make(self) -> PacketData {
        let hwt_b = self.hardware_type.split_to_bytes();
        let p_b = self.protocol_type.split_to_bytes();
        let opcode_b = self.opcode.split_to_bytes();
        let sender_mac: [u8; 6] = self.sender_mac.into();
        let destination_mac: [u8; 6] = self.destination_mac.into();
        vec![
            hwt_b[0],
            hwt_b[1],
            p_b[0],
            p_b[1],
            self.hardware_size,
            self.protocol_size,
            opcode_b[0],
            opcode_b[1],
            sender_mac[0],
            sender_mac[1],
            sender_mac[2],
            sender_mac[3],
            sender_mac[4],
            sender_mac[5],
            self.sender_ip[0],
            self.sender_ip[1],
            self.sender_ip[2],
            self.sender_ip[3],
            destination_mac[0],
            destination_mac[1],
            destination_mac[2],
            destination_mac[3],
            destination_mac[4],
            destination_mac[5],
            self.destination_ip[0],
            self.destination_ip[1],
            self.destination_ip[2],
            self.destination_ip[3],
        ]
    }

    fn get_proto(&self) -> Protocol {
        Protocol::ARP
    }

    fn get_length(&self) -> u8 {
        8 + self.hardware_size + self.protocol_size
    }

    fn get_min_length() -> u8 {
        /* no one really uses anything other than the typical arp over Ipv4,
         * using hardware length 6 (mac addr) and protocol length 4 (ipv4 addr),
         * making the total length 18, so we just always return that here
         */
        18
    }
}
