extern crate pnet;

mod checksum_status;
mod custom_ip_address;
mod helper;
mod ip_header;
mod packet_event;
mod tcp;
mod transport_layer_protocol;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use std::collections::HashMap;
use std::env;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::checksum_status::ChecksumStatus;
use crate::helper::convert_binary_to_decimal;
use crate::ip_header::IpHeader;
use crate::packet_event::{
    FailedPacketParsed, NotHandledPacket, PacketSuccessMetric, SuccessfulPacketParsed,
};
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
    let mut total_number_of_dropped_packets: usize = 0;
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
    let mut dropped_packet_ethertypes: HashMap<String, usize> = HashMap::new();

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
                PacketSuccessMetric::NotHandled(v) => {
                    total_number_of_dropped_packets += 1;
                    dropped_packet_ethertypes
                        .entry(v.not_handled_ethertype)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
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
                total_number_of_successful_packets
                    + total_number_of_failed_packets
                    + total_number_of_dropped_packets,
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

            println!("{} dropped packets", total_number_of_dropped_packets);
            if total_number_of_dropped_packets > 0 {
                print_biggest_value_for_key(
                    &dropped_packet_ethertypes,
                    "is most frequent reason for packet drop with count",
                );
            }

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
    let interface = match interfaces.into_iter().filter(interface_names_match).next() {
        Some(i) => i,
        None => panic!("none interface"),
    };

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
                if packet.get_ethertype() != EtherTypes::Ipv4 {
                    successful_sender
                        .send(PacketSuccessMetric::NotHandled(NotHandledPacket {
                            not_handled_ethertype: packet.get_ethertype().to_string(),
                        }))
                        .unwrap();
                    continue;
                }

                let payload = packet.payload();

                let ip_header_and_data = match IpHeader::new(payload) {
                    Ok(obj) => obj,
                    Err(msg) => {
                        eprintln!("failed to parse ip header due to {}", msg);
                        continue;
                    }
                };

                if let TransportLayerProtocol::Unknown(protocol_number) =
                    ip_header_and_data.protocol
                {
                    successful_sender
                        .send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: ip_header_and_data.version,
                            protocol: ip_header_and_data.protocol,
                            source_location: ip_header_and_data.source_ip.to_string(),
                            destination_location: ip_header_and_data.destination_ip.to_string(),
                            reason_for_failure: format!(
                                "Unknown protocol occurred: {}",
                                protocol_number
                            ),
                        }))
                        .unwrap();
                    continue;
                }

                let calculated_checksum = calculate_ip_header_checksum(&payload);
                if ip_header_and_data.ip_header_checksum != calculated_checksum {
                    successful_sender
                        .send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: ip_header_and_data.version,
                            protocol: ip_header_and_data.protocol,
                            source_location: ip_header_and_data.source_ip.to_string(),
                            destination_location: ip_header_and_data.destination_ip.to_string(),
                            reason_for_failure: format!(
                                "Checksum was not equal! Given: {}, but calculated: {}", // sucks because metrics get screwed
                                ip_header_and_data.ip_header_checksum, calculated_checksum,
                            ),
                        }))
                        .unwrap();
                    continue;
                }

                if ip_header_and_data.protocol == TransportLayerProtocol::TCP {
                    let tcp_object = tcp::map_tcp(&ip_header_and_data);

                    let a_number = ip_header_and_data.total_length as u32
                        - ip_header_and_data.ihl as u32
                        + payload[9] as u32;
                    match compare_tcp_checksum(
                        &payload[12..16],
                        &payload[16..20],
                        &payload[ip_header_and_data.ihl as usize..],
                        a_number,
                        tcp_object.check_sum,
                    ) {
                        ChecksumStatus::FullyMatched => println!("It fully matches!"),
                        ChecksumStatus::PartialMatch => println!("It partially matches!"),
                        ChecksumStatus::NoMatch(i) => {
                            eprintln!(
                                "ERROR - packet somehow received despite checksum not matching, expect {}, but got {}",
                                tcp_object.check_sum, i
                            )
                        }
                    };

                    println!(
                        "IPv{}: {}:{} -> {}:{} {} using {}, content: {:?}",
                        ip_header_and_data.version,
                        ip_header_and_data.source_ip,
                        tcp_object.source_port,
                        ip_header_and_data.destination_ip,
                        tcp_object.destination_port,
                        tcp_object.flag,
                        ip_header_and_data.protocol,
                        tcp_object.content,
                    );
                    successful_sender
                        .send(PacketSuccessMetric::Success(SuccessfulPacketParsed {
                            ip_version: ip_header_and_data.version,
                            protocol: ip_header_and_data.protocol,
                            source_location: format!(
                                "{}:{}",
                                ip_header_and_data.source_ip, tcp_object.source_port
                            ),
                            destination_location: format!(
                                "{}:{}",
                                ip_header_and_data.destination_ip, tcp_object.destination_port
                            ),
                            content_size: tcp_object.content.len(),
                            tcp_flag: tcp_object.flag,
                            tcp_ttl: ip_header_and_data.ttl,
                        }))
                        .unwrap();
                } else if ip_header_and_data.protocol == TransportLayerProtocol::UDP {
                    //// udp header
                    let source_port = convert_binary_to_decimal(&payload[20..22]);
                    let destination_port = convert_binary_to_decimal(&payload[22..24]);
                    let _length = convert_binary_to_decimal(&payload[24..26]);
                    let _check_sum = convert_binary_to_decimal(&payload[26..28]); // which can be optional
                    let content = &payload[28..].iter().map(|c| *c as char).collect::<String>();
                    println!(
                        "IPv{}: {}:{} -> {}:{} {}, content: {:?}",
                        ip_header_and_data.version,
                        ip_header_and_data.source_ip,
                        source_port,
                        ip_header_and_data.destination_ip,
                        destination_port,
                        ip_header_and_data.protocol,
                        content,
                    );
                    successful_sender
                        .send(PacketSuccessMetric::Success(SuccessfulPacketParsed {
                            ip_version: ip_header_and_data.version,
                            protocol: ip_header_and_data.protocol,
                            source_location: format!(
                                "{}:{}",
                                ip_header_and_data.source_ip, source_port
                            ),
                            destination_location: format!(
                                "{}:{}",
                                ip_header_and_data.destination_ip, destination_port
                            ),
                            content_size: content.len(),

                            tcp_flag: String::new(),
                            tcp_ttl: 0,
                        }))
                        .unwrap();
                } else {
                    successful_sender
                        .send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: ip_header_and_data.version,
                            protocol: ip_header_and_data.protocol.clone(),
                            source_location: ip_header_and_data.source_ip.to_string(),
                            destination_location: ip_header_and_data.destination_ip.to_string(),
                            reason_for_failure: format!(
                                "Unhandled protocol occurred: {}",
                                ip_header_and_data.protocol
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

fn calculate_ip_header_checksum(payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in 0..10 {
        if i == 5 {
            continue; // skip checksum number
        }
        sum = sum.wrapping_add((payload[i * 2] as u32) << 8 | (payload[i * 2 + 1] as u32));
    }
    // One odd bit (carry) - could do during loop instead
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16) //1s complement
}

fn compare_tcp_checksum(
    source_ip: &[u8],
    destination_ip: &[u8],
    data: &[u8],
    a_number: u32,
    given_checksum: u16,
) -> ChecksumStatus {
    let mut sum: u32 = a_number; // supposed to be total length - ihl * 5

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
