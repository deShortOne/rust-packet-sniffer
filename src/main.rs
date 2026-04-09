extern crate pnet;

mod packet_event;
mod transport_layer_protocol;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;

use std::cmp::min;
use std::collections::HashMap;
use std::env;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::packet_event::{FailedPacketParsed, PacketSuccessMetric, SuccessfulPacketParsed};
use crate::transport_layer_protocol::TransportLayerProtocol;

fn main() {
    let (tx, rx) = mpsc::channel::<PacketSuccessMetric>();
    let producer = thread::spawn(move || {
        handle_receiving_packets(&env::args().nth(1).unwrap(), tx);
    });
    let consumer = thread::spawn(move || {
        handle_summary(rx);
    });

    match producer.join() {
        Ok(i) => println!("{:?}", i),
        Err(i) => eprintln!("{:?}", i),
    };
    consumer.join().unwrap();
}

fn handle_summary(receiver: Receiver<PacketSuccessMetric>) {
    let mut total_number_of_successful_packets: usize = 0;
    let mut total_number_of_failed_packets: usize = 0;
    let mut protocol_counts: HashMap<TransportLayerProtocol, usize> = HashMap::new();
    let mut failed_protocol_counts: HashMap<TransportLayerProtocol, usize> = HashMap::new();
    let mut total_bytes_captured: usize = 0;
    let mut ip_version_counts: HashMap<String, usize> = HashMap::new();
    let mut failed_ip_version_counts: HashMap<String, usize> = HashMap::new();
    // source_ip + destination_ip != destination_ip + source_ip
    let mut source_ips_to_destination_ips_counts: HashMap<String, usize> = HashMap::new();
    let mut failed_source_ips_to_destination_ips_counts: HashMap<String, usize> = HashMap::new();
    // source_ip + destination_ip == destination_ip + source_ip
    let mut source_ips_to_destination_ips_pairs_counts: HashMap<String, usize> = HashMap::new();
    let mut tcp_flag_counts: HashMap<String, usize> = HashMap::new();
    let mut total_ttl: usize = 0;

    let mut reasons_for_failure_count: HashMap<String, usize> = HashMap::new();

    let seperator = "========================================";

    let mut last_print = Instant::now();

    loop {
        // Try receiving with timeout so we can check time periodically
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(metric) => match metric {
                PacketSuccessMetric::Success(v) => {
                    total_number_of_successful_packets += 1;

                    if v.protocol == TransportLayerProtocol::TCP {
                        tcp_flag_counts
                            .entry(v.tcp_flag)
                            .and_modify(|count| *count += 1)
                            .or_insert(0);
                        total_ttl += v.tcp_ttl as usize;
                    }

                    protocol_counts
                        .entry(v.protocol)
                        .and_modify(|count| *count += 1)
                        .or_insert(0);

                    total_bytes_captured += v.content_size;

                    ip_version_counts
                        .entry(v.ip_version.to_string())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                    let source_ip_to_destination_ip =
                        format!("{}->{}", v.source_location, v.destination_location);
                    source_ips_to_destination_ips_counts
                        .entry(source_ip_to_destination_ip.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(0);

                    if source_ips_to_destination_ips_pairs_counts
                        .contains_key(&source_ip_to_destination_ip)
                    {
                        source_ips_to_destination_ips_pairs_counts
                            .entry(source_ip_to_destination_ip)
                            .and_modify(|count| *count += 1);
                    } else {
                        let destination_ip_to_source_ip =
                            format!("{}->{}", v.destination_location, v.source_location);
                        source_ips_to_destination_ips_pairs_counts
                            .entry(destination_ip_to_source_ip)
                            .and_modify(|count| *count += 1)
                            .or_insert(1);
                    }
                }
                PacketSuccessMetric::Fail(v) => {
                    total_number_of_failed_packets += 1;
                    ip_version_counts
                        .entry(v.ip_version.to_string())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                    failed_ip_version_counts
                        .entry(v.ip_version.to_string())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);

                    protocol_counts
                        .entry(v.protocol.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(0);
                    failed_protocol_counts
                        .entry(v.protocol)
                        .and_modify(|count| *count += 1)
                        .or_insert(0);

                    let source_ip_to_destination_ip =
                        format!("{}->{}", v.source_location, v.destination_location);
                    source_ips_to_destination_ips_counts
                        .entry(source_ip_to_destination_ip.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(0);
                    failed_source_ips_to_destination_ips_counts
                        .entry(source_ip_to_destination_ip.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(0);

                    reasons_for_failure_count
                        .entry(v.reason_for_failure)
                        .and_modify(|count| *count += 1)
                        .or_insert(0);
                }
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break, // channel closed
        }

        // Every 10 seconds, compute mean
        if last_print.elapsed() >= Duration::from_secs(10) {
            println!("{0}\n{0}\n{0}", seperator);

            println!(
                "Captured {} packets with a total of {} bytes captured",
                total_number_of_successful_packets + total_number_of_failed_packets,
                total_bytes_captured,
            );

            if let Some(value) = protocol_counts.get(&TransportLayerProtocol::TCP) {
                println!(
                    "Captured {} successful packets with an average ttl of {} for {:?} tcp packets",
                    total_number_of_successful_packets,
                    total_ttl / (*value),
                    *value,
                );
            } else {
                println!(
                    "Captured {} successful packets with no tcp packets",
                    total_number_of_successful_packets,
                );
            }

            print_biggest_value_for_key(&ip_version_counts, "is the most ip version with count");
            print_biggest_value_for_key(
                &source_ips_to_destination_ips_counts,
                "has the biggest count of",
            );
            print_biggest_value_for_key(
                &source_ips_to_destination_ips_pairs_counts,
                "pair has the biggest count of",
            );
            print_biggest_value_for_key(&tcp_flag_counts, "has the most flag count of");

            println!(
                "{} packets failed to be parsed",
                total_number_of_failed_packets,
            );
            if total_number_of_failed_packets > 0 {
                print_biggest_value_for_key(
                    &failed_ip_version_counts,
                    "is the most ip version that failed with count",
                );
                print_biggest_value_for_key(
                    &failed_source_ips_to_destination_ips_counts,
                    "has the biggest failure count of",
                );
                print_biggest_value_for_key(
                    &reasons_for_failure_count,
                    "is the biggest reason for failure with a count of",
                );
            }

            println!("{0}\n{0}\n{0}", seperator);
            last_print = Instant::now();
        }
    }
}

fn print_biggest_value_for_key(dict_to_check: &HashMap<String, usize>, custom_middle_text: &str) {
    let mut biggest_count: usize = 0;
    let mut source_ip_to_destination_ip_of_biggest_count = String::new();
    for (key, value) in dict_to_check {
        if *value > biggest_count {
            biggest_count = *value;
            source_ip_to_destination_ip_of_biggest_count = key.clone();
        }
    }
    println!("{source_ip_to_destination_ip_of_biggest_count} {custom_middle_text} {biggest_count}");
}

fn handle_receiving_packets(interface_name: &str, successful_sender: Sender<PacketSuccessMetric>) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
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
                let _tos = payload[1];
                let _total_length = payload[3]; // payload 2 is part of but not sure what factor
                // identification: unique packet id (16 bits)
                // flags: 3 flags, 1 bit each, reserved bit (must be 0), do not fragment flag, more fragments flag
                let _fragment = &payload[4..6];
                // represents number of data bytes ahead of the particular fragment in the particular datagram
                let _fragment_offset = &payload[6..8];
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
                let header_checksum = (payload[10] as u16) << 8 | (payload[11] as u16);
                // 32 bits ip address of sender
                let source_ip = join_nums(&payload[12..16], ".");
                // 32 bits ip address of receiver
                let destination_ip = join_nums(&payload[16..20], ".");

                if let TransportLayerProtocol::Unknown(protocol_number) = protocol {
                    successful_sender
                        .send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: version,
                            protocol: protocol,
                            source_location: source_ip,
                            destination_location: destination_ip,
                            reason_for_failure: format!(
                                "Unknown protocol occurred: {}",
                                protocol_number
                            ),
                        }))
                        .unwrap();
                    continue;
                }
                let calculated_checksum = calculate_ip_checksum(&payload);
                if header_checksum != calculated_checksum {
                    successful_sender
                        .send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: version,
                            protocol: protocol,
                            source_location: source_ip,
                            destination_location: destination_ip,
                            reason_for_failure: format!(
                                "Checksum was not equal! Given: {}, but calculated: {}", // sucks because metrics get screwed
                                header_checksum, calculated_checksum,
                            ),
                        }))
                        .unwrap();
                    continue;
                }

                if protocol == TransportLayerProtocol::TCP {
                    //// tcp header
                    let source_port = convert_binary_to_decimal(&payload[20..22]);
                    let destination_port = convert_binary_to_decimal(&payload[22..24]);
                    let _sequence_number = convert_binary_to_decimal(&payload[24..28]);
                    let _acknowledgement_number = convert_binary_to_decimal(&payload[28..32]);
                    let data_offset_and_reserved = format!("{:x}", payload[32]);
                    let tcp_header_size = match data_offset_and_reserved.chars().nth(0) {
                        Some(i) => i.to_digit(10).unwrap() * 4,
                        None => 32, // bc why not
                    };
                    let flag = handle_tcp_flag(&payload[33]);
                    let _window_size = convert_binary_to_decimal(&payload[34..36]);
                    let _check_sum = convert_binary_to_decimal(&payload[36..38]);
                    let _urgent_pointer = convert_binary_to_decimal(&payload[38..40]);
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
                    successful_sender
                        .send(PacketSuccessMetric::Success(SuccessfulPacketParsed {
                            ip_version: version,
                            protocol: protocol,
                            source_location: format!("{}:{}", source_ip, source_port),
                            destination_location: format!(
                                "{}:{}",
                                destination_ip, destination_port
                            ),
                            content_size: content.len(),
                            tcp_flag: flag,
                            tcp_ttl: ttl,
                        }))
                        .unwrap();
                } else if protocol == TransportLayerProtocol::UDP {
                    //// udp header
                    let source_port = convert_binary_to_decimal(&payload[20..22]);
                    let destination_port = convert_binary_to_decimal(&payload[22..24]);
                    let _length = convert_binary_to_decimal(&payload[24..26]);
                    let _check_sum = convert_binary_to_decimal(&payload[26..28]); // which can be optional
                    let content = &payload[28..].iter().map(|c| *c as char).collect::<String>();
                    println!(
                        "IPv{}: {}:{} -> {}:{} {}, content: {:?}",
                        version,
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        protocol,
                        content,
                    );
                    successful_sender
                        .send(PacketSuccessMetric::Success(SuccessfulPacketParsed {
                            ip_version: version,
                            protocol: protocol,
                            source_location: format!("{}:{}", source_ip, source_port),
                            destination_location: format!(
                                "{}:{}",
                                destination_ip, destination_port
                            ),
                            content_size: content.len(),

                            tcp_flag: String::new(),
                            tcp_ttl: 0,
                        }))
                        .unwrap();
                } else {
                    successful_sender
                        .send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: version,
                            protocol: protocol.clone(),
                            source_location: source_ip,
                            destination_location: destination_ip,
                            reason_for_failure: format!(
                                "Unhandled protocol occurred: {}",
                                protocol
                            ),
                        }))
                        .unwrap();
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

fn calculate_ip_checksum(nums: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in 0..10 {
        if i == 5 {
            continue; // skip checksum number
        }
        sum = sum.wrapping_add((nums[i * 2] as u32) << 8 | (nums[i * 2 + 1] as u32));
    }
    // One odd bit (carry) - could do during loop instead
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16) //1s complement
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
