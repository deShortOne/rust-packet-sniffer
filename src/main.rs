extern crate pnet;

mod checksum_status;
mod cli;
mod helper;
mod ip_headers;
mod locator;
mod packet_event;
mod tcp;
mod transport_layer_protocol;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::checksum_status::ChecksumStatus;
use crate::cli::TcpObjectValidation;
use crate::ip_headers::ip_header::{IpObject, IpVersions};
use crate::ip_headers::ip_header_v4::IpV4Header;
use crate::ip_headers::ip_header_v6::IpV6Header;
use crate::locator::custom_ip_address::IpAddressVariant;
use crate::locator::mac_address::MacAddress;
use crate::packet_event::{
    ArpPacketSuccess, FailedPacketParsed, NotHandledPacket, PacketSuccessMetric,
    SuccessfulPacketParsed,
};
use crate::tcp::arp::ArpOperation;
use crate::transport_layer_protocol::TransportLayerProtocol;

fn main() {
    let validation_object = match TcpObjectValidation::new() {
        Ok(i) => i,
        Err(reason) => {
            eprintln!("{}", reason);
            return;
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("Received Ctrl+C, shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let (tx, rx) = mpsc::channel::<PacketSuccessMetric>();
    let running1 = running.clone();
    let producer = thread::spawn(move || {
        handle_receiving_packets(
            &validation_object.interface,
            &validation_object,
            tx,
            running1,
        );
    });
    let running2 = running.clone();
    let consumer = thread::spawn(move || {
        handle_summary(rx, running2);
    });

    match producer.join() {
        Ok(_) => println!("producer joined successfully"),
        Err(i) => eprintln!("Producer joined fail: {:?}", i),
    };
    match consumer.join() {
        Ok(_) => println!("consumer joined successfully"),
        Err(i) => eprintln!("consumer joined fail: {:?}", i),
    };

    println!("Clean exit");
}

fn handle_summary(receiver: Receiver<PacketSuccessMetric>, running: Arc<AtomicBool>) {
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

    let mut number_of_successful_arp_packets: usize = 0;
    let mut ip_address_to_mac_address: HashMap<IpAddressVariant, MacAddress> = HashMap::new();
    let mut number_of_failed_arp_packets: usize = 0;
    let mut reasons_for_arp_failure: HashMap<String, usize> = HashMap::new();

    let seperator = "========================================";

    let mut last_print = Instant::now();

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Try receiving with timeout so we can check time periodically
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(metric) => match metric {
                PacketSuccessMetric::ArpSuccess(a) => {
                    number_of_successful_arp_packets += 1;
                    ip_address_to_mac_address
                        .entry(a.sender_address.ip_address)
                        .or_insert(a.sender_address.mac_address);
                    if a.operation == ArpOperation::Reply {
                        ip_address_to_mac_address
                            .entry(a.target_address.ip_address)
                            .or_insert(a.target_address.mac_address);
                    }
                }
                PacketSuccessMetric::ArpFailure(r) => {
                    number_of_failed_arp_packets += 1;
                    reasons_for_arp_failure
                        .entry(r.reason)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
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

            println!(
                "Received {} arp packets out of a total of {}",
                number_of_successful_arp_packets,
                number_of_successful_arp_packets + number_of_failed_arp_packets
            );
            // Could look to output ip address to mac addresses
            if reasons_for_arp_failure.len() != 0 {
                print_biggest_value_for_key(
                    &reasons_for_arp_failure,
                    "is the biggest reason for arp failure with count",
                );
            }

            println!("{0}\n{0}\n{0}", seperator);
            last_print = Instant::now();
        }
    }

    println!("Summary handling is now shut down");
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

fn handle_receiving_packets(
    interface_name: &str,
    validation_object: &TcpObjectValidation,
    successful_sender: Sender<PacketSuccessMetric>,
    running: Arc<AtomicBool>,
) {
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
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match rx.next() {
            Ok(packet) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let packet = match EthernetPacket::new(packet) {
                    Some(i) => i,
                    None => {
                        println!("Failed to create ethernet packet");
                        continue;
                    }
                };

                let payload = packet.payload();
                if packet.get_ethertype() == EtherTypes::Arp && validation_object.is_arp_allowed {
                    let send_packet_res = match tcp::map_arp(payload) {
                        Ok(i) => {
                            if i.op_code == ArpOperation::Request {
                                println!(
                                    "Arp request: {} ({}) is asking for {}",
                                    i.sender_ip_address.to_string(),
                                    i.sender_mac_address.to_string(),
                                    i.target_ip_address.to_string()
                                );
                            } else if i.op_code == ArpOperation::Reply {
                                println!(
                                    "Arp reply: {} ({}) is replying to {} ({})",
                                    i.sender_ip_address.to_string(),
                                    i.sender_mac_address.to_string(),
                                    i.target_ip_address.to_string(),
                                    i.target_mac_address.to_string()
                                );
                            } else {
                                println!(
                                    "!!! Arp Unhandled: {} ({}) to {} ({})",
                                    i.sender_ip_address.to_string(),
                                    i.sender_mac_address.to_string(),
                                    i.target_ip_address.to_string(),
                                    i.target_mac_address.to_string()
                                );
                            }

                            successful_sender.send(PacketSuccessMetric::ArpSuccess(
                                ArpPacketSuccess {
                                    operation: i.op_code,
                                    sender_address: packet_event::ArpPacketAddress {
                                        mac_address: i.sender_mac_address,
                                        ip_address: i.sender_ip_address,
                                    },
                                    target_address: packet_event::ArpPacketAddress {
                                        mac_address: i.target_mac_address,
                                        ip_address: i.target_ip_address,
                                    },
                                },
                            ))
                        }
                        Err(reason) => successful_sender.send(PacketSuccessMetric::ArpFailure(
                            packet_event::ArpPacketFailure { reason },
                        )),
                    };
                    if let Err(i) = send_packet_res {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                    continue;
                }

                let ip_header_and_data: IpVersions;
                if packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ip_header_and_data_internal = match IpV4Header::new(payload) {
                        Ok(obj) => obj,
                        Err(msg) => {
                            eprintln!("failed to parse ip header due to {}", msg);
                            continue;
                        }
                    };
                    ip_header_and_data = IpVersions::V4(ip_header_and_data_internal);
                } else if packet.get_ethertype() == EtherTypes::Ipv6 {
                    let ip_header_and_data_internal = match IpV6Header::new(payload) {
                        Ok(obj) => obj,
                        Err(msg) => {
                            eprintln!("failed to parse ip header due to {}", msg);
                            continue;
                        }
                    };
                    ip_header_and_data = IpVersions::V6(ip_header_and_data_internal);
                } else {
                    if let Err(i) =
                        successful_sender.send(PacketSuccessMetric::NotHandled(NotHandledPacket {
                            not_handled_ethertype: packet.get_ethertype().to_string(),
                        }))
                    {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                    continue;
                }

                if let TransportLayerProtocol::Unknown(protocol_number) =
                    ip_header_and_data.get_protocol()
                {
                    if let Err(i) =
                        successful_sender.send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: ip_header_and_data.get_version(),
                            protocol: ip_header_and_data.get_protocol(),
                            source_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_source(),
                                port: 0,
                            },
                            destination_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_destination(),
                                port: 0,
                            },
                            reason_for_failure: format!(
                                "Unknown protocol occurred: {}",
                                protocol_number
                            ),
                        }))
                    {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                    continue;
                }

                if let Err(reason) = ip_header_and_data.is_valid() {
                    if let Err(i) =
                        successful_sender.send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: ip_header_and_data.get_version(),
                            protocol: ip_header_and_data.get_protocol(),
                            source_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_source(),
                                port: 0,
                            },
                            destination_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_destination(),
                                port: 0,
                            },
                            reason_for_failure: reason,
                        }))
                    {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                    continue;
                }

                if ip_header_and_data.get_protocol() == TransportLayerProtocol::TCP {
                    let tcp_object = match tcp::map_tcp(&ip_header_and_data) {
                        Ok(i) => i,
                        Err(reason) => {
                            if let Err(i) = successful_sender.send(PacketSuccessMetric::Fail(
                                FailedPacketParsed {
                                    ip_version: ip_header_and_data.get_version(),
                                    protocol: ip_header_and_data.get_protocol(),
                                    source_location: packet_event::APacketAddress {
                                        ip_address: ip_header_and_data.get_source(),
                                        port: 0,
                                    },
                                    destination_location: packet_event::APacketAddress {
                                        ip_address: ip_header_and_data.get_destination(),
                                        port: 0,
                                    },
                                    reason_for_failure: format!(
                                        "Unable to create tcp object due to {}",
                                        reason
                                    ),
                                },
                            )) {
                                eprintln!("Failed to send packet success metric due to: {}", i)
                            }
                            continue;
                        }
                    };

                    if !validation_object
                        .should_packet_be_processed(&ip_header_and_data, &tcp_object)
                    {
                        continue;
                    }

                    match tcp_object.is_valid() {
                        ChecksumStatus::FullyMatched => println!("It fully matches!"),
                        ChecksumStatus::PartialMatch => println!("It partially matches!"),
                        ChecksumStatus::NoMatch(i) => {
                            eprintln!(
                                "ERROR - packet somehow received despite checksum not matching, expect {}, but got {}",
                                tcp_object.check_sum, i
                            )
                        }
                    }

                    println!(
                        "IPv{}: {}:{} -> {}:{} {} using {}, content: {:?}",
                        ip_header_and_data.get_version(),
                        ip_header_and_data.get_source_ip(),
                        tcp_object.source_port,
                        ip_header_and_data.get_destination_ip(),
                        tcp_object.destination_port,
                        tcp_object.flag,
                        ip_header_and_data.get_protocol(),
                        tcp_object.content,
                    );
                    if let Err(i) = successful_sender.send(PacketSuccessMetric::Success(
                        SuccessfulPacketParsed {
                            ip_version: ip_header_and_data.get_version(),
                            protocol: ip_header_and_data.get_protocol(),
                            source_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_source(),
                                port: tcp_object.source_port,
                            },
                            destination_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_destination(),
                                port: tcp_object.destination_port,
                            },
                            content_size: tcp_object.content.len(),
                            tcp_flag: tcp_object.flag,
                            tcp_ttl: ip_header_and_data.get_ttl(),
                        },
                    )) {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                } else if ip_header_and_data.get_protocol() == TransportLayerProtocol::UDP {
                    let udp_object = match tcp::map_udp(&ip_header_and_data) {
                        Ok(i) => i,
                        Err(reason) => {
                            if let Err(i) = successful_sender.send(PacketSuccessMetric::Fail(
                                FailedPacketParsed {
                                    ip_version: ip_header_and_data.get_version(),
                                    protocol: ip_header_and_data.get_protocol(),
                                    source_location: packet_event::APacketAddress {
                                        ip_address: ip_header_and_data.get_source(),
                                        port: 0,
                                    },
                                    destination_location: packet_event::APacketAddress {
                                        ip_address: ip_header_and_data.get_destination(),
                                        port: 0,
                                    },
                                    reason_for_failure: format!(
                                        "Unable to create udp object due to {}",
                                        reason
                                    ),
                                },
                            )) {
                                eprintln!("Failed to send packet success metric due to: {}", i)
                            }
                            continue;
                        }
                    };

                    if !validation_object
                        .should_packet_be_processed(&ip_header_and_data, &udp_object)
                    {
                        continue;
                    }

                    match udp_object.is_valid() {
                        ChecksumStatus::FullyMatched => println!("It fully matches!"),
                        ChecksumStatus::PartialMatch => println!("It partially matches!"),
                        ChecksumStatus::NoMatch(i) => {
                            if udp_object.check_sum == 0 {
                                // http://www.faqs.org/rfcs/rfc768.html "An all zero transmitted checksum value means that
                                // the transmitter generated no checksum (for debugging or for higher level protocols that don't care)."
                                println!(
                                    "Packet checksum is 0 so something is being lazy for reasons, but should be {}",
                                    i
                                )
                            } else {
                                eprintln!(
                                    "ERROR - packet somehow received despite checksum not matching, expect {}, but got {}",
                                    udp_object.check_sum, i
                                )
                            }
                        }
                    }

                    println!(
                        "IPv{}: {}:{} -> {}:{} {}, content: {:?}",
                        ip_header_and_data.get_version(),
                        ip_header_and_data.get_source_ip(),
                        udp_object.source_port,
                        ip_header_and_data.get_destination_ip(),
                        udp_object.destination_port,
                        ip_header_and_data.get_protocol(),
                        udp_object.content,
                    );
                    if let Err(i) = successful_sender.send(PacketSuccessMetric::Success(
                        SuccessfulPacketParsed {
                            ip_version: ip_header_and_data.get_version(),
                            protocol: ip_header_and_data.get_protocol(),
                            source_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_source(),
                                port: udp_object.source_port,
                            },
                            destination_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_destination(),
                                port: udp_object.destination_port,
                            },
                            content_size: udp_object.content.len(),

                            tcp_flag: String::new(),
                            tcp_ttl: 0,
                        },
                    )) {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                } else {
                    if let Err(i) =
                        successful_sender.send(PacketSuccessMetric::Fail(FailedPacketParsed {
                            ip_version: ip_header_and_data.get_version(),
                            protocol: ip_header_and_data.get_protocol(),
                            source_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_source(),
                                port: 0,
                            },
                            destination_location: packet_event::APacketAddress {
                                ip_address: ip_header_and_data.get_destination(),
                                port: 0,
                            },
                            reason_for_failure: format!(
                                "Unhandled protocol occurred: {}",
                                ip_header_and_data.get_protocol()
                            ),
                        }))
                    {
                        eprintln!("Failed to send packet success metric due to: {}", i)
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }

    println!("Handle receiving packets is now shut down");
}
