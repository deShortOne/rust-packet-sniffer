extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{MutablePacket, Packet};

use std::cmp::min;
use std::env;

// Invoke as echo <interface name>
fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                if let Some(_why_make_our_life_easier_when_practicing) =
                    Ipv4Packet::new(packet.payload())
                {
                    let payload = packet.payload();
                    let version_and_ihl = format!("{:x}", payload[0]);
                    let version = match &version_and_ihl.chars().nth(0) {
                        Some(c) => c.to_digit(10).unwrap(),
                        None => continue,
                    };
                    let ihl = 4 * match &version_and_ihl.chars().nth(1) {
                        Some(c) => c.to_digit(10).unwrap(),
                        None => continue,
                    };
                    if ihl != 20 {
                        println!(
                            "Received IPv{}: but IHL is {}, can only handle 20",
                            version, ihl,
                        );
                        continue;
                    }

                    //// IPv4 header
                    // low delay, high throughput, reliability
                    let tos = payload[1];
                    let total_length = payload[3]; // payload 2 is part of but not sure what factor
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
                        6 => "TCP",
                        _ => "UNKOWN",
                    };
                    // 16 bit checksum for checking errors in datagram header
                    let header_checksum = &payload[10..12];
                    // 32 bits ip address of sender
                    let source_ip = join_nums(&payload[12..16], ".");
                    // 32 bits ip address of receiver
                    let destination_ip = join_nums(&payload[16..20], ".");

                    //// tcp header
                    let source_port = convert_binary_to_decimal(&payload[20..22]);
                    let destination_port = convert_binary_to_decimal(&payload[22..24]);
                    let sequence_number = convert_binary_to_decimal(&payload[24..28]);
                    let acknowledgement_number = convert_binary_to_decimal(&payload[28..32]);
                    let data_offset_and_reserved = format!("{:x}", payload[32]);
                    let tcp_header_size = match data_offset_and_reserved.chars().nth(0) {
                        Some(i) => i.to_digit(10).unwrap() * 4,
                        None => 32, // bc why not
                    };
                    let flag = handle_tcp_flag(&payload[33]);
                    let window_size = convert_binary_to_decimal(&payload[34..36]);
                    let check_sum = convert_binary_to_decimal(&payload[36..38]);
                    let urgent_pointer = convert_binary_to_decimal(&payload[38..40]);
                    // skipping tcp options

                    let mut content_start: usize = ihl as usize + tcp_header_size as usize;
                    let mut content_end: usize = payload.len();
                    let mut header_footer = "";
                    // assuming it's plain text postgres protocol
                    if content_start == content_end {
                        content_start -= 1;
                        content_end -= 1;
                    } else if payload[content_start] == 80 || payload[content_start] == 81 {
                        header_footer = "\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n";

                        let total_content_length = convert_binary_to_decimal(
                            &payload[content_start + 1..content_start + 5],
                        );

                        content_start = min(content_start + 5, payload.len() - 1);
                        content_end = min(content_start + total_content_length, payload.len() - 1);
                    }
                    let content = &payload[content_start..content_end]
                        .iter()
                        .map(|c| *c as char)
                        .collect::<String>();

                    println!(
                        "{header_footer}IPv{}: {}:{} -> {}:{} {} using {}, content: {:?}{header_footer}",
                        version,
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        flag,
                        protocol,
                        content,
                    );
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn join_nums(nums: &[u8], sep: &str) -> String {
    let str_nums: Vec<String> = nums.iter().map(|n| n.to_string()).collect();
    str_nums.join(sep)
}

fn convert_binary_to_decimal(nums: &[u8]) -> usize {
    // could also do bitwise notation but (payload[20] as usize) << 8 | (payload[21] as usize) but easy to screw up
    let str_nums: Vec<String> = nums.iter().map(|n| format!("{:0>8b}", n)).collect();
    let str_nums = str_nums.join("");
    usize::from_str_radix(&str_nums, 2).unwrap()
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
