use crate::TransportLayerProtocol;
use crate::ip_headers::ip_header_v4::IpV4Header;
use crate::ip_headers::ip_header_v6::IpV6Header;

pub enum IpVersions<'a> {
    V4(IpV4Header<'a>),
    V6(IpV6Header<'a>),
}

impl<'a> IpObject for IpVersions<'a> {
    fn get_data(&self) -> &[u8] {
        match self {
            IpVersions::V4(i) => i.get_data(),
            IpVersions::V6(i) => i.get_data(),
        }
    }
    fn get_segment_length(&self) -> usize {
        match self {
            IpVersions::V4(i) => i.get_segment_length(),
            IpVersions::V6(i) => i.get_segment_length(),
        }
    }
    fn is_valid(&self) -> Result<(), String> {
        match self {
            IpVersions::V4(i) => i.is_valid(),
            IpVersions::V6(i) => i.is_valid(),
        }
    }
    fn get_protocol(&self) -> TransportLayerProtocol {
        match self {
            IpVersions::V4(i) => i.get_protocol(),
            IpVersions::V6(i) => i.get_protocol(),
        }
    }
    fn get_version(&self) -> u32 {
        match self {
            IpVersions::V4(i) => i.get_version(),
            IpVersions::V6(i) => i.get_version(),
        }
    }
    fn get_source_ip(&self) -> String {
        match self {
            IpVersions::V4(i) => i.get_source_ip(),
            IpVersions::V6(i) => i.get_source_ip(),
        }
    }
    fn get_source_ip_raw(&self) -> &[u8] {
        match self {
            IpVersions::V4(i) => i.get_source_ip_raw(),
            IpVersions::V6(i) => i.get_source_ip_raw(),
        }
    }
    fn get_destination_ip(&self) -> String {
        match self {
            IpVersions::V4(i) => i.get_destination_ip(),
            IpVersions::V6(i) => i.get_destination_ip(),
        }
    }
    fn get_destination_ip_raw(&self) -> &[u8] {
        match self {
            IpVersions::V4(i) => i.get_destination_ip_raw(),
            IpVersions::V6(i) => i.get_destination_ip_raw(),
        }
    }
    fn get_ttl(&self) -> u8 {
        match self {
            IpVersions::V4(i) => i.get_ttl(),
            IpVersions::V6(i) => i.get_ttl(),
        }
    }
}

pub trait IpObject {
    fn get_data(&self) -> &[u8];
    fn get_segment_length(&self) -> usize;
    fn is_valid(&self) -> Result<(), String>;
    fn get_protocol(&self) -> TransportLayerProtocol;
    fn get_version(&self) -> u32;
    fn get_source_ip(&self) -> String;
    fn get_source_ip_raw(&self) -> &[u8];
    fn get_destination_ip(&self) -> String;
    fn get_destination_ip_raw(&self) -> &[u8];
    fn get_ttl(&self) -> u8;
}
