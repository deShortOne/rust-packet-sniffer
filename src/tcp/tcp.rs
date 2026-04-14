use std::cmp::min;

use crate::{
    checksum_status::ChecksumStatus,
    ip_header::{IpObject, IpVersions},
};

pub struct TcpObject<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub _sequence_number: u32,
    pub _acknowledgement_number: u32,
    pub _tcp_header_size: u32,
    pub flag: String,
    pub _window_size: u16,
    pub check_sum: u16,
    pub _urgent_pointer: u16,
    pub content: String,

    based_off: &'a IpVersions<'a>,
}

impl<'a> TcpObject<'a> {
    pub fn new(ip_header: &'a IpVersions) -> Self {
        let tcp_payload = ip_header.get_data();
        let source_port = (tcp_payload[0] as u16) << 8 | tcp_payload[1] as u16;
        let destination_port = (tcp_payload[2] as u16) << 8 | tcp_payload[3] as u16;
        let _sequence_number = (tcp_payload[4] as u32) << 24
            | (tcp_payload[5] as u32) << 16
            | (tcp_payload[6] as u32) << 16
            | tcp_payload[7] as u32;
        let _acknowledgement_number = (tcp_payload[8] as u32) << 24
            | (tcp_payload[9] as u32) << 16
            | (tcp_payload[10] as u32) << 16
            | tcp_payload[11] as u32;
        let data_offset_and_reserved = format!("{:x}", tcp_payload[12]);
        let tcp_header_size = match data_offset_and_reserved.chars().nth(0) {
            Some(i) => {
                4 * match i.to_digit(10) {
                    Some(i) => i,
                    None => panic!(
                        "\n\n\nCharacter that failed: {:?}\n\n\n\n",
                        data_offset_and_reserved.chars().nth(0)
                    ),
                }
            }
            None => 32, // bc why not
        };
        let flag = handle_tcp_flag(&tcp_payload[13]);
        let _window_size = (tcp_payload[14] as u16) << 8 | tcp_payload[15] as u16;
        let check_sum = (tcp_payload[16] as u16) << 8 | (tcp_payload[17] as u16);
        let _urgent_pointer = (tcp_payload[18] as u16) << 8 | (tcp_payload[19] as u16);

        let mut content_start_index: usize = tcp_header_size as usize;
        let mut content_end_index: usize = ip_header.get_segment_length();
        if content_start_index == content_end_index {
            content_start_index -= 1;
            content_end_index -= 1;
        } else if tcp_payload[content_start_index] == 80 || tcp_payload[content_start_index] == 81 {
            // assuming it's plain text postgres protocol
            let total_content_length = (tcp_payload[content_start_index + 1] as u32) << 24
                | (tcp_payload[content_start_index + 2] as u32) << 16
                | (tcp_payload[content_start_index + 3] as u32) << 8
                | tcp_payload[content_start_index + 4] as u32;

            content_start_index = min(content_start_index + 5, tcp_payload.len() - 1);
            content_end_index = min(
                content_start_index + total_content_length as usize,
                tcp_payload.len() - 1,
            );
        }
        let content = tcp_payload[content_start_index..content_end_index]
            .iter()
            .map(|c| *c as char)
            .collect::<String>();

        Self {
            source_port,
            destination_port,
            _sequence_number,
            _acknowledgement_number,
            _tcp_header_size: tcp_header_size,
            flag,
            _window_size,
            check_sum,
            _urgent_pointer,
            content,

            based_off: ip_header,
        }
    }

    pub fn is_valid(&self) -> ChecksumStatus {
        let protocol_num: usize = self.based_off.get_protocol().into();
        let sum = (self.based_off.get_segment_length() + protocol_num) as u32;

        compare_tcp_checksum(
            self.based_off.get_source_ip_raw(),
            self.based_off.get_destination_ip_raw(),
            self.based_off.get_data(),
            sum,
            self.check_sum,
        )
    }
}

fn handle_tcp_flag(flag: &u8) -> String {
    let mut res: Vec<&str> = Vec::new();

    // // Terminate exisitng TCP connection
    // // If sent without completing the necessary handshake, could indicate attempt
    // // to disrupt connection or carry out attack
    if flag & 1 != 0 {
        res.push("FIN");
    }
    // // Flag used to synchronise sequence numbers to initiate attack
    // // large numbers of SYN packets with fake source IP address could indicate SYN flood attack
    if flag & 2 != 0 {
        res.push("SYN");
    }
    // // Flag used to reset TCP connection
    // // Large number of RST packets could indicate DOS attack or disrupt connection
    if flag & 4 != 0 {
        res.push("RST");
    }
    // // request receiver to pass data to application as soon as its received
    if flag & 8 != 0 {
        res.push("PSH");
    }
    // // Indicate acknowledgement number field is valid
    // // If sent on a closed port or an unexpected sequence number
    // // could be a sign of reconnaissance or scanning activity
    if flag & 16 != 0 {
        res.push("ACK");
    }
    // // data should be processed as soon as possible
    // // Attackers could use to hide malicious traffic or bypass security controls
    if flag & 32 != 0 {
        res.push("URG");
    }

    if res.len() == 0 {
        return String::from("UNKNOWN FLAG");
    }
    res.join("-")
}

fn compare_tcp_checksum(
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
    use super::*;

    #[test]
    fn checksum_fully_matches() {
        // this example stolen from: https://stackoverflow.com/questions/70174406/ipv4-tcp-checksum-calculation
        let source_ip: [u8; 4] = [0xc0, 0xa8, 0x00, 0x96];
        let destination_ip: [u8; 4] = [0xc0, 0xa8, 0x00, 0x72];
        // let protocol_number: u8 = 6;
        // let ihl: u8 = 20; // = 20 generated from 5 from ip header then multiplied by 4
        let tcp_header: [u8; 16] = [
            0xb2, 0x6e, 0xfd, 0xb8, 0x42, 0xc6, 0x1f, 0x88, 0x68, 0xdc, 0x69, 0x95, 0x50, 0x10,
            0x01, 0xf6,
        ];

        assert_eq!(
            compare_tcp_checksum(&source_ip, &destination_ip, &tcp_header, 0x1a, 18078),
            ChecksumStatus::FullyMatched
        );
    }

    #[test]
    fn checksum_partially_matches() {
        let source_ip: [u8; 4] = [0xc0, 0xa8, 0x0, 0x14];
        let destination_ip: [u8; 4] = [0xa2, 0x9f, 0x86, 0xea];
        // let protocol_number: u8 = 6;
        // let ihl: u8 = 20; // = 20 generated from 5 from ip header then multiplied by 4
        let tcp_header: [u8; 16] = [
            0xe5, 0xa4, 0x1, 0xbb, 0xbc, 0x66, 0x51, 0x17, 0xb0, 0xe4, 0x8, 0xa9, 0x50, 0x10, 0x20,
            0x54,
        ];

        assert_eq!(
            compare_tcp_checksum(&source_ip, &destination_ip, &tcp_header, 0x1a, 0xea60),
            ChecksumStatus::PartialMatch
        );
    }

    #[test]
    fn checksum_doesnt_match() {
        let source_ip: [u8; 4] = [0xc0, 0xa8, 0x0, 0x14];
        let destination_ip: [u8; 4] = [0xa2, 0x9f, 0x86, 0xea];
        // let protocol_number: u8 = 6;
        // let ihl: u8 = 20; // = 20 generated from 5 from ip header then multiplied by 4
        let tcp_header: [u8; 16] = [
            0xe5, 0xa4, 0x1, 0xbb, 0xbc, 0x66, 0x51, 0x17, 0xb0, 0xe4, 0x8, 0xa9, 0x50, 0x10, 0x20,
            0x54,
        ];

        assert_eq!(
            compare_tcp_checksum(&source_ip, &destination_ip, &tcp_header, 0x1a, 0x0),
            ChecksumStatus::NoMatch(0xf6ce)
        );
    }
}
