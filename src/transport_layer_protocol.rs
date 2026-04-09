use std::fmt;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum TransportLayerProtocol {
    TCP,
    UDP,
    Unknown(u8),
}

impl fmt::Display for TransportLayerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransportLayerProtocol::TCP => write!(f, "TCP"),
            TransportLayerProtocol::UDP => write!(f, "UDP"),
            TransportLayerProtocol::Unknown(i) => write!(f, "UNKNOWN protocol: {}", i),
        }
    }
}
