use crate::{ip_header::IpVersions, tcp::tcp::TcpObject};

mod tcp;

pub fn map_tcp<'a>(ip_header: &'a IpVersions) -> TcpObject<'a> {
    TcpObject::new(ip_header)
}
