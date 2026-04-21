use std::fmt;

use crate::{
    locator::{custom_ip_address::IpAddressVariant, mac_address::MacAddress},
    tcp::arp::ArpOperation,
    transport_layer_protocol::TransportLayerProtocol,
};

pub enum PacketSuccessMetric {
    ArpSuccess(ArpPacketSuccess),
    ArpFailure(ArpPacketFailure),
    NotHandled(NotHandledPacket),
    Success(SuccessfulPacketParsed),
    Fail(FailedPacketParsed),
}

pub struct ArpPacketSuccess {
    pub operation: ArpOperation,
    pub sender_address: ArpPacketAddress,
    pub target_address: ArpPacketAddress,
}

pub struct ArpPacketAddress {
    pub mac_address: MacAddress,
    pub ip_address: IpAddressVariant,
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
    pub source_location: APacketAddress,
    pub destination_location: APacketAddress,
    pub content_size: usize,

    pub tcp_flag: String,
    pub tcp_ttl: u8,
}

pub struct FailedPacketParsed {
    pub ip_version: u32,
    pub protocol: TransportLayerProtocol,
    pub source_location: APacketAddress,
    pub destination_location: APacketAddress,

    pub reason_for_failure: String,
}

pub struct APacketAddress {
    pub ip_address: IpAddressVariant,
    pub port: u16,
}

impl fmt::Display for APacketAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.ip_address, self.port)
    }
}
