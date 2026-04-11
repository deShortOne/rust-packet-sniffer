use std::cmp::min;

pub struct TcpObject {
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
}

impl TcpObject {
    pub fn new(tcp_payload: &[u8]) -> Self {
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
            Some(i) => i.to_digit(10).unwrap() * 4,
            None => 32, // bc why not
        };
        let flag = handle_tcp_flag(&tcp_payload[13]);
        let _window_size = (tcp_payload[14] as u16) << 8 | tcp_payload[15] as u16;
        let check_sum = (tcp_payload[16] as u16) << 8 | (tcp_payload[17] as u16);
        let _urgent_pointer = (tcp_payload[18] as u16) << 8 | (tcp_payload[19] as u16);
        // skipping tcp options

        let mut content_start: usize = tcp_header_size as usize;
        let mut content_end: usize = tcp_payload.len();
        if content_start == content_end {
            content_start -= 1;
            content_end -= 1;
        } else if tcp_payload[content_start] == 80 || tcp_payload[content_start] == 81 {
            // assuming it's plain text postgres protocol
            let total_content_length = (tcp_payload[content_start + 1] as u32) << 24
                | (tcp_payload[content_start + 2] as u32) << 16
                | (tcp_payload[content_start + 3] as u32) << 8
                | tcp_payload[content_start + 4] as u32;

            content_start = min(content_start + 5, tcp_payload.len() - 1);
            content_end = min(
                content_start + total_content_length as usize,
                tcp_payload.len() - 1,
            );
        }
        let content = tcp_payload[content_start..content_end]
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
        }
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
