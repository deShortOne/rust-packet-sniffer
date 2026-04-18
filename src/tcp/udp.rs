use crate::{
    checksum_status::ChecksumStatus,
    ip_header::{IpObject, IpVersions},
    tcp::PacketBodyObject,
};

pub struct UdpObject<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub check_sum: u16,
    pub content: String,

    based_off: &'a IpVersions<'a>,
}

impl<'a> UdpObject<'a> {
    pub fn new(ip_header: &'a IpVersions) -> Result<Self, String> {
        let udp_payload = ip_header.get_data();
        if udp_payload.len() < 28 {
            return Err(format!(
                "udp payload has a minimum size of 28, but got {}",
                udp_payload.len()
            ));
        }
        let source_port = (udp_payload[0] as u16) << 8 | udp_payload[1] as u16;
        let destination_port = (udp_payload[2] as u16) << 8 | udp_payload[3] as u16;
        let length = (udp_payload[4] as u16) << 8 | udp_payload[5] as u16;
        let check_sum = (udp_payload[6] as u16) << 8 | udp_payload[7] as u16;
        let content = udp_payload[8..]
            .iter()
            .map(|c| *c as char)
            .collect::<String>();

        Ok(Self {
            source_port,
            destination_port,
            length,
            check_sum,
            content: content,
            based_off: ip_header,
        })
    }

    pub fn is_valid(&self) -> ChecksumStatus {
        let protocol_num: usize = self.based_off.get_protocol().into();
        let sum = self.length as u32 + protocol_num as u32;

        compare_udp_checksum(
            self.based_off.get_source_ip_raw(),
            self.based_off.get_destination_ip_raw(),
            self.based_off.get_data(),
            sum,
            self.check_sum,
        )
    }
}

impl<'a> PacketBodyObject for UdpObject<'a> {
    fn get_source_port(&self) -> u16 {
        self.source_port
    }
    fn get_destination_port(&self) -> u16 {
        self.destination_port
    }
}

fn compare_udp_checksum(
    source_ip: &[u8],
    destination_ip: &[u8],
    data: &[u8],
    a_number: u32,
    given_checksum: u16,
) -> ChecksumStatus {
    let mut sum: u32 = a_number;

    let chunks = source_ip.chunks_exact(2);
    for chunk in chunks {
        sum = sum.wrapping_add((chunk[0] as u32) << 8 | (chunk[1] as u32));
    }
    let chunks = destination_ip.chunks_exact(2);
    for chunk in chunks {
        sum = sum.wrapping_add((chunk[0] as u32) << 8 | (chunk[1] as u32));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if sum as u16 == given_checksum {
        return ChecksumStatus::PartialMatch;
    }

    let chunks = data.chunks_exact(2);
    for chunk in chunks {
        sum = sum.wrapping_add((chunk[0] as u32) << 8 | (chunk[1] as u32));
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    match !(sum as u16) {
        final_checksum if final_checksum == given_checksum => ChecksumStatus::FullyMatched,
        final_checksum => ChecksumStatus::NoMatch(final_checksum),
    }
}

#[cfg(test)]
mod tcp_checksum_test {
    use crate::checksum_status::ChecksumStatus;

    use super::*;

    #[test]
    fn checksum_fully_matches() {
        let source_ip: [u8; 4] = [0x11, 0xf8, 0xd3, 0x14];
        let destination_ip: [u8; 4] = [0xc0, 0xa8, 0x00, 0x14];
        let udp_header: [u8; 30] = [
            0x1, 0xbb, 0xfc, 0xd0, 0x0, 0x20, 0x48, 0xbc, 0x12, 0x86, 0xda, 0x76, 0xd7, 0x5e, 0xca,
            0x48, 0x21, 0x2f, 0x44, 0x11, 0x80, 0x95, 0x42, 0xfa, 0x60, 0x99, 0xf6, 0x3a, 0x55,
            0x15,
        ];

        assert_eq!(
            compare_udp_checksum(&source_ip, &destination_ip, &udp_header, 0x31, 0xaf3e),
            ChecksumStatus::FullyMatched
        );
    }

    #[test]
    fn checksum_partially_matches() {
        // dunno if exists?
        let source_ip: [u8; 4] = [0x11, 0xf8, 0xd3, 0x14];
        let destination_ip: [u8; 4] = [0xc0, 0xa8, 0x00, 0x14];
        let udp_header: [u8; 30] = [
            0x1, 0xbb, 0xfc, 0xd0, 0x0, 0x20, 0x48, 0xbc, 0x12, 0x86, 0xda, 0x76, 0xd7, 0x5e, 0xca,
            0x48, 0x21, 0x2f, 0x44, 0x11, 0x80, 0x95, 0x42, 0xfa, 0x60, 0x99, 0xf6, 0x3a, 0x55,
            0x15,
        ];

        assert_eq!(
            compare_udp_checksum(&source_ip, &destination_ip, &udp_header, 0x31, 0xA5FA),
            ChecksumStatus::PartialMatch
        );
    }

    #[test]
    fn checksum_doesnt_match() {
        // defo does exist... But only from local to outbound for some reason
        let source_ip: [u8; 4] = [0x11, 0xf8, 0xd3, 0x14];
        let destination_ip: [u8; 4] = [0xc0, 0xa8, 0x00, 0x14];
        let udp_header: [u8; 30] = [
            0x1, 0xbb, 0xfc, 0xd0, 0x0, 0x20, 0x48, 0xbc, 0x12, 0x86, 0xda, 0x76, 0xd7, 0x5e, 0xca,
            0x48, 0x21, 0x2f, 0x44, 0x11, 0x80, 0x95, 0x42, 0xfa, 0x60, 0x99, 0xf6, 0x3a, 0x55,
            0x15,
        ];

        assert_eq!(
            compare_udp_checksum(&source_ip, &destination_ip, &udp_header, 0x31, 0x0),
            ChecksumStatus::NoMatch(0xaf3e)
        );
    }
}
