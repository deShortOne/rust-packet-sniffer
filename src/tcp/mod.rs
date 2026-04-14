use crate::{ip_header::IpVersions, tcp::tcp::TcpObject};

mod tcp;

pub fn map_tcp<'a>(ip_header: &'a IpVersions) -> Result<TcpObject<'a>, String> {
    TcpObject::new(ip_header)
}
