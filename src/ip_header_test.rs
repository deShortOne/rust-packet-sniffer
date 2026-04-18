use crate::{ip_header::IpObject, transport_layer_protocol::TransportLayerProtocol};

pub struct _IpHeaderTestObject {
    protocol: TransportLayerProtocol,
}

impl _IpHeaderTestObject {
    pub fn _new(protocol: TransportLayerProtocol) -> Self {
        Self { protocol }
    }
}

impl IpObject for _IpHeaderTestObject {
    fn get_data(&self) -> &[u8] {
        &[0; 0]
    }

    fn get_destination_ip(&self) -> String {
        String::new()
    }

    fn get_destination_ip_raw(&self) -> &[u8] {
        &[0; 0]
    }

    fn get_protocol(&self) -> TransportLayerProtocol {
        self.protocol.clone()
    }

    fn get_segment_length(&self) -> usize {
        0
    }

    fn get_source_ip(&self) -> String {
        String::new()
    }

    fn get_source_ip_raw(&self) -> &[u8] {
        &[0; 0]
    }

    fn get_ttl(&self) -> u8 {
        0
    }

    fn get_version(&self) -> u32 {
        0
    }

    fn is_valid(&self) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
}
