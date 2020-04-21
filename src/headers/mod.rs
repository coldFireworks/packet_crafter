use super::{Protocol, ParseError};

mod ethernet;
mod arp;
mod icmp;
mod ip;
mod tcp;
mod udp;
// de-glob the modules, doing this rather than having "pub mod x;" allows for shorter use paths
pub use ethernet::*;
pub use arp::*;
pub use icmp::*;
pub use ip::*;
pub use tcp::*;
pub use udp::*;

pub type PacketData = Vec<u8>;

pub trait Header {
    /// 'cook' the header, returning it as a `Vec<u8>`.
    /// this function will calculate checksums, even though they will be over-written by the OS if the packet is sent 'down the wire', likewise with a lot of `length` fields and such.
    /// 
    /// The reason i decided to still calculate checksums is incase someone uses the packet for some other purpose, or if they are building/using an experimntal OS which doesn calculate checksums (or they havent built that in yet).
    fn make(self) -> PacketData;

    /// parse() should never be run from a box<Header>, is hould only ever br un as <Header>::parse().
    /// this is just here to complete the implementation of Header onto boxed structs that implement header
    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError>;

    fn get_proto(&self) -> Protocol;

    /// get the current length of the header in bytes. this usually just returns a fixed value as most headers dont have variable length,
    /// only really IP does and even then its rare for it to be > 20 bytes
    fn get_length(&self) -> u8; // these are done as functions rather than constants in order to enforce all modules to have them if they want to implement this trait

    /// get the minimum length (in bytes) that this type of header can be
    fn get_min_length() -> u8; // these are done as functions rather than constants in order to enforce all modules to have them if they want to implement this trait

    /// attempts to coerce the header (a type which implements the Header trait) into a &mut dyn TransportHeader.
    /// Only returns `Option::Some` when the underlying concrete type is a `UdpHeader` or a `TcpHeader`
    fn into_transport_header(&mut self) -> Option<&mut dyn TransportHeader> {
        None
    }
}

pub trait TransportHeader {
    /// Sets the values of an internal value which represents the pseudo header that is used when calculating the checksum.
    /// This method must be called before the `make` method, which is called when the header is added to the `Packet` with the `add_header` method.
    /// If the IP header is already present in the `Packet` when this one is added, then this method will be called in the `add_header` method, using the data from the IP header.
    /// 
    /// TL;DR: you can ignore this method if you add this header to the `Packet` using the `add_header` method after you have added an IP header to the `Packet` with `add_header`
    fn set_pseudo_header(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], data_len: u16);
}

struct PseudoHeader {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    data_len: u16,
}

impl<T: Header> Header for Box<T> {
    fn make(self) -> PacketData {
        (*self).make()
    }

    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError>{
        match T::parse(raw_data) {
            Ok(boxed_header) => Ok(Box::new(boxed_header)),
            Err(e) => Err(e)
        }
    }

    fn get_proto(&self) -> Protocol{
        (**self).get_proto()
    }

    fn get_length(&self) -> u8{
        (**self).get_length()
    }

    fn get_min_length() -> u8{
        T::get_min_length()
    }

    fn into_transport_header(&mut self) -> Option<&mut dyn TransportHeader> {
        (**self).into_transport_header()
    }
}