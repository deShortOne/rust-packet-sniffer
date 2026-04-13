use crate::{ip_header::IpVersions, tcp::tcp::TcpObject};

mod tcp;

pub fn map_tcp(ip_header: &IpVersions) -> TcpObject {
    TcpObject::new(ip_header)
}
