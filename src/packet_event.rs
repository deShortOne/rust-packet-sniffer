use crate::transport_layer_protocol::TransportLayerProtocol;

pub struct SuccessfulPacketParsed {
    pub ip_version: u32,
    pub protocol: TransportLayerProtocol,
    pub source_location: String,
    pub destination_location: String,
    pub content_size: usize,

    pub tcp_flag: String,
}
