use crate::transport_layer_protocol::TransportLayerProtocol;

pub enum PacketSuccessMetric {
    ArpSuccess(ArpPacketSuccess),
    ArpFailure(ArpPacketFailure),
    NotHandled(NotHandledPacket),
    Success(SuccessfulPacketParsed),
    Fail(FailedPacketParsed),
}

pub struct ArpPacketSuccess {
    pub operation: String,
    pub sender_address: ArpPacketAddress,
    pub target_address: ArpPacketAddress,
}

pub struct ArpPacketAddress {
    pub mac_address: String,
    pub ip_address: String,
}

pub struct ArpPacketFailure {
    pub reason: String,
}

pub struct NotHandledPacket {
    pub not_handled_ethertype: String,
}

pub struct SuccessfulPacketParsed {
    pub ip_version: u32,
    pub protocol: TransportLayerProtocol,
    pub source_location: String,
    pub destination_location: String,
    pub content_size: usize,

    pub tcp_flag: String,
    pub tcp_ttl: u8,
}

pub struct FailedPacketParsed {
    pub ip_version: u32,
    pub protocol: TransportLayerProtocol,
    pub source_location: String,
    pub destination_location: String,

    pub reason_for_failure: String,
}
