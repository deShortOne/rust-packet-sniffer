use crate::{TransportLayerProtocol, custom_ip_address::IpV4Address, ip_header_v6::IpV6Header};

pub enum IpVersions<'a> {
    V4(IpHeader<'a>),
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
    fn get_destination_ip(&self) -> String {
        match self {
            IpVersions::V4(i) => i.get_destination_ip(),
            IpVersions::V6(i) => i.get_destination_ip(),
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
    fn get_destination_ip(&self) -> String;
    fn get_ttl(&self) -> u8;
}

pub struct IpHeader<'a> {
    pub version: u32,
    pub ihl: u32,
    pub _tos: u8,
    pub total_length: u16,
    pub _fragment: &'a [u8],
    pub _fragment_offset: &'a [u8],
    pub ttl: u8,
    pub protocol: TransportLayerProtocol,
    pub ip_header_checksum: u16,
    pub source_ip: IpV4Address,
    pub destination_ip: IpV4Address,
    pub _options: &'a [u8],
    pub data: &'a [u8],

    entire_payload_cause_im_lazy_plus_its_only_being_referenced: &'a [u8],
}

impl<'a> IpHeader<'a> {
    pub fn new(payload: &'a [u8]) -> Result<Self, String> {
        let version_and_ihl = format!("{:x}", payload[0]);
        let version = match &version_and_ihl.chars().nth(0) {
            Some(c) => c.to_digit(10).unwrap(),
            None => {
                return Err(format!(
                    "IpHeader version couldn't parse, attempted from payload: {:?}",
                    payload
                ));
            }
        };
        let ihl = 4 * match &version_and_ihl.chars().nth(1) {
            Some(c) => c.to_digit(10).unwrap(),
            None => {
                return Err(format!(
                    "IpHeader ihl couldn't parse, attempted from payload: {:?}",
                    payload
                ));
            }
        };

        //// IPv4 header
        // low delay, high throughput, reliability
        let tos = payload[1];
        let total_length = (payload[2] as u16) << 8 | (payload[3] as u16); // payload 2 is part of but not sure what factor
        // identification: unique packet id (16 bits)
        // flags: 3 flags, 1 bit each, reserved bit (must be 0), do not fragment flag, more fragments flag
        let fragment = &payload[4..6];
        // represents number of data bytes ahead of the particular fragment in the particular datagram
        let fragment_offset = &payload[6..8];
        // restruct number of hops taken by packet before delivering to the destination
        let ttl = payload[8];
        // name of protocol: tcp, udp
        let protocol = match payload[9] {
            //https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            6 => TransportLayerProtocol::TCP,
            17 => TransportLayerProtocol::UDP,
            i => TransportLayerProtocol::Unknown(i),
        };
        // 16 bit checksum for checking errors in datagram header
        let ip_header_checksum = (payload[10] as u16) << 8 | (payload[11] as u16);
        // 32 bits ip address of sender
        let source_ip = IpV4Address::new(&payload[12..16]);
        // 32 bits ip address of receiver
        let destination_ip = IpV4Address::new(&payload[16..20]);
        let options = &payload[20..ihl as usize];
        let data = &payload[ihl as usize..];

        Ok(Self {
            version,
            ihl,
            _tos: tos,
            total_length,
            _fragment: fragment,
            _fragment_offset: fragment_offset,
            ttl,
            protocol,
            ip_header_checksum,
            source_ip,
            destination_ip,
            _options: options,
            data,
            entire_payload_cause_im_lazy_plus_its_only_being_referenced: payload,
        })
    }
}

impl<'a> IpObject for IpHeader<'a> {
    fn get_data(&self) -> &[u8] {
        self.data
    }

    fn get_segment_length(&self) -> usize {
        self.total_length as usize - self.ihl as usize
    }

    fn is_valid(&self) -> Result<(), String> {
        let calculated_checksum = calculate_ip_header_checksum(&self);
        if self.ip_header_checksum != calculated_checksum {
            return Err(format!(
                "Checksum was not equal! Given: {}, but calculated: {}", // sucks because metrics get screwed
                self.ip_header_checksum, calculated_checksum,
            ));
        }
        Ok(())
    }

    fn get_protocol(&self) -> TransportLayerProtocol {
        self.protocol.clone()
    }

    fn get_version(&self) -> u32 {
        self.version
    }

    fn get_source_ip(&self) -> String {
        self.source_ip.to_string()
    }

    fn get_destination_ip(&self) -> String {
        self.destination_ip.to_string()
    }

    fn get_ttl(&self) -> u8 {
        self.ttl
    }
}

fn calculate_ip_header_checksum(data: &IpHeader) -> u16 {
    let mut sum = 0u32;
    for i in 0..10 {
        if i == 5 {
            continue; // skip checksum number
        }
        sum = sum.wrapping_add(
            (data.entire_payload_cause_im_lazy_plus_its_only_being_referenced[i * 2] as u32) << 8
                | (data.entire_payload_cause_im_lazy_plus_its_only_being_referenced[i * 2 + 1]
                    as u32),
        );
    }
    // One odd bit (carry) - could do during loop instead
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16) //1s complement
}
