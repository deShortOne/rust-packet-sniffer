use crate::tcp::tcp::TcpObject;

mod tcp;

pub fn map_tcp(tcp_payload: &[u8]) -> TcpObject {
    TcpObject::new(tcp_payload)
}
