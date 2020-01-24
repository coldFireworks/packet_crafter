use super::{Header, PacketData, Protocol, ParseError};
use crate::AsBeBytes;

pub const REQUEST: u16 = 1;
pub const REPLY: u16 = 2;

#[derive(AddGetter, AddSetter)]
pub struct ArpHeader {
    hardware_type: u16,
    protocol_type: u16,
    hardware_size: u8,
    protocol_size: u8,
    #[get] #[set] opcode: u16,
    #[get] #[set] sender_mac: [u8; 6],
    #[get] #[set] sender_ip: [u8; 4],
    #[get] #[set] destination_mac: [u8; 6],
    #[get] #[set] destination_ip: [u8; 4],
}

impl ArpHeader {
    pub fn new<T: Into<[u8; 4]>>(sender_mac: [u8; 6], sender_ip: T, destination_mac: [u8; 6], destination_ip: T) -> Self {
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

impl Header for ArpHeader {
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

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError> {
        if raw_data.len() < Self::get_min_length().into() {
            return Err(ParseError::InvalidLength);
        }
        Ok(Box::new(Self {
            hardware_type: ((raw_data[0] as u16) << 8) + raw_data[1] as u16,
            protocol_type: ((raw_data[2] as u16) << 8) + raw_data[3] as u16,
            hardware_size: raw_data[4],
            protocol_size: raw_data[5],
            opcode: ((raw_data[6] as u16) << 8) + raw_data[7] as u16,
            sender_mac: [raw_data[8], raw_data[9], raw_data[10], raw_data[11], raw_data[12], raw_data[13]],
            sender_ip: [raw_data[14], raw_data[15], raw_data[16], raw_data[17]],
            destination_mac: [raw_data[18], raw_data[19], raw_data[20], raw_data[21], raw_data[22], raw_data[23]],
            destination_ip: [raw_data[24], raw_data[25], raw_data[26], raw_data[27]],
        }))
    }

    fn get_proto(&self) -> Protocol {
        Protocol::ARP
    }

    fn get_length(&self) -> u8 {
        8 + (self.hardware_size*2) + (self.protocol_size*2)
    }

    fn get_min_length() -> u8 {
        /* no one really uses anything other than the typical arp over Ipv4,
         * using hardware length 6 (mac addr) and protocol length 4 (ipv4 addr),
         * making the total length 18, so we just always return that here
         */
        28
    }
}
