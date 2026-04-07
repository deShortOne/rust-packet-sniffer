use std::fmt;

#[derive(PartialEq, Eq)]
pub enum TransportLayerProtocol {
    TCP,
    UDP,
    Unknown,
}

impl fmt::Display for TransportLayerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransportLayerProtocol::TCP => write!(f, "TCP"),
            TransportLayerProtocol::UDP => write!(f, "UDP"),
            TransportLayerProtocol::Unknown => write!(f, "UNKNOWN"),
        }
    }
}
