use std::fmt;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum TransportLayerProtocol {
    TCP,
    UDP,
    Unknown(u8),
}

impl Into<usize> for TransportLayerProtocol {
    fn into(self) -> usize {
        match self {
            TransportLayerProtocol::TCP => 6,
            TransportLayerProtocol::UDP => 12,
            TransportLayerProtocol::Unknown(i) => i as usize,
        }
    }
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
