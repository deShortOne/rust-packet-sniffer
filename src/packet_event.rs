use crate::transport_layer_protocol::TransportLayerProtocol;

pub enum PacketSuccessMetric {
    Success(SuccessfulPacketParsed),
    Fail(FailedPacketParsed),
}

pub struct SuccessfulPacketParsed {
    pub ip_version: u32,
    pub protocol: TransportLayerProtocol,
    pub source_location: String,
    pub destination_location: String,
    pub content_size: usize,

    pub tcp_flag: String,
}

pub struct FailedPacketParsed {
    pub ip_version: u32,
    pub protocol: TransportLayerProtocol,
    pub source_location: String,
    pub destination_location: String,

    pub reason_for_failure: String,
}
