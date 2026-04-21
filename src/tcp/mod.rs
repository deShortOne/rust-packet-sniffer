use crate::ip_headers::ip_header::IpVersions;
use crate::tcp::arp::ArpObject;
use crate::tcp::tcp::TcpObject;
use crate::tcp::udp::UdpObject;

pub mod arp;
pub mod fake;
mod tcp;
mod udp;

pub trait PacketBodyObject {
    fn get_source_port(&self) -> u16;
    fn get_destination_port(&self) -> u16;
}

pub fn map_arp<'a>(data: &'a [u8]) -> Result<ArpObject, String> {
    ArpObject::new(data)
}

pub fn map_tcp<'a>(ip_header: &'a IpVersions) -> Result<TcpObject<'a>, String> {
    TcpObject::new(ip_header)
}

pub fn map_udp<'a>(ip_header: &'a IpVersions) -> Result<UdpObject<'a>, String> {
    UdpObject::new(ip_header)
}
