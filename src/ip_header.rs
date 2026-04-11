use crate::{TransportLayerProtocol, custom_ip_address::IpV4Address};

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
}

impl<'a> IpHeader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        let version_and_ihl = format!("{:x}", payload[0]);
        let version = match &version_and_ihl.chars().nth(0) {
            Some(c) => c.to_digit(10).unwrap(),
            None => panic!("IpHeader version couldn't parse"),
        };
        let ihl = 4 * match &version_and_ihl.chars().nth(1) {
            Some(c) => c.to_digit(10).unwrap(),
            None => panic!("IpHeader ihl couldn't parse"),
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

        Self {
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
        }
    }
}
