use crate::{ip_header::IpVersions, tcp::tcp::TcpObject, tcp::udp::UdpObject};

mod tcp;
mod udp;

pub fn map_tcp<'a>(ip_header: &'a IpVersions) -> Result<TcpObject<'a>, String> {
    TcpObject::new(ip_header)
}

pub fn map_udp<'a>(ip_header: &'a IpVersions) -> Result<UdpObject<'a>, String> {
    UdpObject::new(ip_header)
}
