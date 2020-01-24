use super::{Protocol, ParseError};

mod ethernet;
mod arp;
mod icmp;
mod ip;
mod tcp;
// de-glob the modules, doing this rather than having "pub mod x;" allows for shorter use paths
pub use ethernet::*;
pub use arp::*;
pub use icmp::*;
pub use ip::*;
pub use tcp::*;

pub type PacketData = Vec<u8>;

pub trait Header {
    fn make(self) -> PacketData;
    fn parse(raw_data: &[u8]) -> Result<Box<Self>, ParseError>;
    fn get_proto(&self) -> Protocol;
    fn get_length(&self) -> u8;
    fn get_min_length() -> u8;
}

impl<T: Header> Header for Box<T> {
    fn make(self) -> PacketData {
        (*self).make()
    }

    /// parse() should never be run from a box<Header>, is hould only ever br un as <Header>::parse().
    /// this is just here to complete the implementation of Header onto boxed structs that implement header
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
}