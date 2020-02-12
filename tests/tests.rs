extern crate packet_crafter;

use packet_crafter::*;
use headers::Header;

#[test]
fn icmp_checksum_is_calculated() {
    // let p = Packet::new(vec![Protocol::ICMP]);
    let icmp_header = headers::IcmpHeader::new(8, 0, 0xd49e, 0);
    let data = icmp_header.make();
    assert_ne!(data[2], 0);
    assert_ne!(data[3], 0);
}

#[test]
fn test_get_header_method() {
    let mut p = Packet::new(vec![Protocol::ETH, Protocol::IP, Protocol::TCP]);
    p.add_header(
        headers::EthernetHeader::new(
            [6,5,4,3,2,1],
            [1,2,3,4,5,6],
            ethertype_numbers::ETHERTYPE_IPV4
        )
    );
    p.add_header(
        headers::IpHeader::new([192, 168, 1, 128], [192, 168, 1, 38], Protocol::TCP)
    );
    p.add_header(
        headers::TcpHeader::new(3838, 3838)
    );
    let tcp_header_slice = p.get_header_as_slice(Protocol::TCP).expect("could not find tcp header");
    let bytes = 3838u16.split_to_bytes();
    assert_eq!(bytes[0], tcp_header_slice[0]);
    assert_eq!(bytes[1], tcp_header_slice[1]);
    let eth_header_slice = p.get_header_as_slice(Protocol::ETH).expect("could not find eth header");
    assert_eq!(eth_header_slice[0], 1);
    assert_eq!(eth_header_slice[1], 2);
    assert_eq!(eth_header_slice[2], 3);
    assert_eq!(eth_header_slice[3], 4);
    assert_eq!(eth_header_slice[4], 5);
    assert_eq!(eth_header_slice[5], 6);
    assert_eq!(eth_header_slice[6], 6);
    assert_eq!(eth_header_slice[7], 5);
    assert_eq!(eth_header_slice[8], 4);
    assert_eq!(eth_header_slice[9], 3);
    assert_eq!(eth_header_slice[10], 2);
    assert_eq!(eth_header_slice[11], 1);
}

#[test]
fn test_eth_parse_function() {
    let raw_data: &[u8] = &[1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 8, 0];
    let eth_header_struct = headers::EthernetHeader::parse(raw_data).unwrap();
    assert_eq!(eth_header_struct.get_dst_mac(), &[1,2,3,4,5,6]);
    assert_eq!(eth_header_struct.get_src_mac(), &[6,5,4,3,2,1]);
    assert_eq!(eth_header_struct.get_eth_type(), &ethertype_numbers::ETHERTYPE_IPV4);
}

#[test]
fn test_1_byte_u16_to_bytes() {
    let x = 12u16;
    assert_eq!([0, 12], x.split_to_bytes());
}

#[test]
fn test_2_byte_u16_to_bytes() {
    let x: u16 = 0b00100001_00101100;
    assert_eq!([0b00100001, 0b00101100], x.split_to_bytes());
}