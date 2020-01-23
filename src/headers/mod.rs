use super::Protocol;

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
    fn get_proto(&self) -> Protocol;
    fn get_length(&self) -> u8;
    fn get_min_length() -> u8;
}