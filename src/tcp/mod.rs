use crate::{ip_header::IpHeader, tcp::tcp::TcpObject};

mod tcp;

pub fn map_tcp(ip_header: &IpHeader) -> TcpObject {
    TcpObject::new(ip_header)
}
