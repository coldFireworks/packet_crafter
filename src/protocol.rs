use super::{
    protocol_numbers,
    Header,
    EthernetHeader,
    ArpHeader,
    IcmpHeader,
    IpHeader,
    TcpHeader
};
use std::fmt;

type ProtocolNumber = u8;

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum Protocol {
    ETH,
    ARP,
    ICMP,
    TCP,
    UDP,
    IP,
}

impl Protocol {
    pub fn min_header_len(&self) -> u8 {
        match self {
            Self::ETH => EthernetHeader::get_min_length(),
            Self::ARP => ArpHeader::get_min_length(),
            Self::ICMP => IcmpHeader::get_min_length(),
            Self::TCP => TcpHeader::get_min_length(),
            Self::UDP => 0, // not yet implemented
            Self::IP => IpHeader::get_min_length(),
        }
    }

    pub fn protocol_number(&self) -> ProtocolNumber {
        // returns the number of this protocol as of RFC 1700
        match self {
            Self::ETH => protocol_numbers::IPPROTO_ETHERIP,
            Self::ICMP => protocol_numbers::IPPROTO_ICMP,
            Self::TCP => protocol_numbers::IPPROTO_TCP,
            Self::UDP => protocol_numbers::IPPROTO_UDP,
            Self::IP => protocol_numbers::IPPROTO_IPV4,
            Self::ARP => panic!("ARP does not have an assigned ip protocol number"),
        }
    }
}

impl From<ProtocolNumber> for Protocol {
    fn from(p: ProtocolNumber) -> Protocol {
        match p {
            protocol_numbers::IPPROTO_ETHERIP => Protocol::ETH,
            protocol_numbers::IPPROTO_ICMP => Protocol::ICMP,
            protocol_numbers::IPPROTO_TCP => Protocol::TCP,
            protocol_numbers::IPPROTO_UDP => Protocol::UDP,
            protocol_numbers::IPPROTO_IPV4 => Protocol::IP,
            _ => panic!("Could not convert to Protocol enum"),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::ETH => write!(f, "Ethernet"),
            Protocol::ARP => write!(f, "Arp"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::IP => write!(f, "IP"),
        }
    }
}