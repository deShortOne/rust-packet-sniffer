use std::fmt;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum TransportLayerProtocol {
    TCP,
    UDP,
    ARP,
    Unknown(u8),
}

impl From<TransportLayerProtocol> for u8 {
    fn from(value: TransportLayerProtocol) -> Self {
        match value {
            TransportLayerProtocol::ARP => 1, // ICMP?? Nope
            TransportLayerProtocol::TCP => 6,
            TransportLayerProtocol::UDP => 17,
            TransportLayerProtocol::Unknown(i) => i,
        }
    }
}

impl fmt::Display for TransportLayerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransportLayerProtocol::ARP => write!(f, "ARP"), // ICMP?? Nope
            TransportLayerProtocol::TCP => write!(f, "TCP"),
            TransportLayerProtocol::UDP => write!(f, "UDP"),
            TransportLayerProtocol::Unknown(i) => write!(f, "UNKNOWN protocol: {}", i),
        }
    }
}
