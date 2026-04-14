use crate::{
    custom_ip_address::{IpAddress, IpV6Address},
    ip_header::IpObject,
    transport_layer_protocol::TransportLayerProtocol,
};

pub struct IpV6Header<'a> {
    pub version: u8,
    pub _traffic_class: u8,
    pub _flow_label: u32,
    pub payload_length: u16,
    pub next_header: TransportLayerProtocol,
    pub hop_limit: u8,
    pub source_ip: IpV6Address<'a>,
    pub destination_ip: IpV6Address<'a>,
    pub data: &'a [u8],
}

impl<'a> IpV6Header<'a> {
    pub fn new(payload: &'a [u8]) -> Result<Self, String> {
        let version_and_first_half_of_traffic = payload[0];
        let version = version_and_first_half_of_traffic >> 4;
        let second_half_of_traffic_class_and_first_bit_of_flow_label = payload[1];
        let traffic_class = 0x0F & version_and_first_half_of_traffic
            | second_half_of_traffic_class_and_first_bit_of_flow_label >> 4;
        let last_bit_of_flow_label = (payload[2] as u32) << 8 | payload[3] as u32;
        let flow_label = (0x0F & second_half_of_traffic_class_and_first_bit_of_flow_label as u32)
            << 16
            | last_bit_of_flow_label;
        let payload_length = (payload[4] as u16) << 8 | payload[5] as u16;
        let next_header = match payload[6] {
            //https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            6 => TransportLayerProtocol::TCP,
            17 => TransportLayerProtocol::UDP,
            i => TransportLayerProtocol::Unknown(i),
        };
        let hop_limit = payload[7];
        let source_ip = IpV6Address::new(&payload[8..24]);
        let destination_ip = IpV6Address::new(&payload[24..40]);
        let data = &payload[40..];

        Ok(Self {
            version,
            _traffic_class: traffic_class,
            _flow_label: flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_ip,
            destination_ip,
            data,
        })
    }
}

impl<'a> IpObject for IpV6Header<'a> {
    fn get_data(&self) -> &[u8] {
        self.data
    }

    fn get_segment_length(&self) -> usize {
        self.payload_length as usize
    }

    fn is_valid(&self) -> Result<(), String> {
        Ok(())
    }

    fn get_protocol(&self) -> TransportLayerProtocol {
        self.next_header.clone()
    }

    fn get_version(&self) -> u32 {
        self.version.into()
    }

    fn get_source_ip(&self) -> String {
        self.source_ip.to_string()
    }

    fn get_source_ip_raw(&self) -> &[u8] {
        self.source_ip.get_raw_bytes()
    }

    fn get_destination_ip(&self) -> String {
        self.destination_ip.to_string()
    }

    fn get_destination_ip_raw(&self) -> &[u8] {
        self.destination_ip.get_raw_bytes()
    }

    fn get_ttl(&self) -> u8 {
        self.hop_limit
    }
}
