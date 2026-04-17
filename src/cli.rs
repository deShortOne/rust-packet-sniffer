use clap::Parser;

use crate::{
    ip_header::{IpObject, IpVersions},
    tcp::PacketBodyObject,
    transport_layer_protocol::TransportLayerProtocol,
};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // examples: eth0, docker0
    #[clap(long)]
    pub interface: String,

    // examples: TCP, UDP
    #[clap(long)]
    pub protocol: Option<Vec<String>>,

    // inclusive range
    // expect structure like: 5000-6000
    #[clap(long, value_parser)]
    pub source_port_range: Option<Vec<String>>,

    // singular port value
    #[clap(long, value_parser)]
    pub source_port: Option<Vec<String>>,

    // inclusive range
    // expect structure like: 5000-6000
    #[clap(long, value_parser)]
    pub destination_port_range: Option<Vec<String>>,

    // singular port value
    #[clap(long, value_parser)]
    pub destination_port: Option<Vec<String>>,
}

pub struct TcpObjectValidation {
    pub interface: String,
    protocols: Box<[TransportLayerProtocol]>,
    source_port: Box<[u16]>,
    source_port_range: Box<[(u16, u16)]>,
    destination_port: Box<[u16]>,
    destination_port_range: Box<[(u16, u16)]>,
}

impl TcpObjectValidation {
    pub fn new() -> Result<Self, String> {
        Self::internal_new(Args::parse())
    }

    fn internal_new(args: Args) -> Result<Self, String> {
        let mut protocols_to_accept: Vec<TransportLayerProtocol> = Vec::new();
        if let Some(protocols) = args.protocol {
            for protocol in protocols {
                match protocol.as_str() {
                    "TCP" => protocols_to_accept.push(TransportLayerProtocol::TCP),
                    "UDP" => protocols_to_accept.push(TransportLayerProtocol::UDP),
                    _ => {}
                };
            }
        }

        let mut source_port_ranges_to_accept: Vec<(u16, u16)> = Vec::new();
        if let Some(source_port_ranges) = args.source_port_range {
            for source_port_range in source_port_ranges {
                let ranges: Vec<&str> = source_port_range.split("-").collect();
                source_port_ranges_to_accept.push((
                    ranges[0].parse::<u16>().unwrap(),
                    ranges[1].parse::<u16>().unwrap(),
                ));
            }
        }
        let mut source_port_to_accept: Vec<u16> = Vec::new();
        if let Some(source_ports) = args.source_port {
            for source_port_range in source_ports {
                source_port_to_accept.push(source_port_range.parse::<u16>().unwrap());
            }
        }

        let mut destination_port_ranges_to_accept: Vec<(u16, u16)> = Vec::new();
        if let Some(destination_port_ranges) = args.destination_port_range {
            for destination_port_range in destination_port_ranges {
                let ranges: Vec<&str> = destination_port_range.split("-").collect();
                destination_port_ranges_to_accept.push((
                    ranges[0].parse::<u16>().unwrap(),
                    ranges[1].parse::<u16>().unwrap(),
                ));
            }
        }
        let mut destination_port_to_accept: Vec<u16> = Vec::new();
        if let Some(destination_ports) = args.destination_port {
            for destination_port_range in destination_ports {
                destination_port_to_accept.push(destination_port_range.parse::<u16>().unwrap());
            }
        }

        Ok(Self {
            interface: args.interface,
            protocols: protocols_to_accept.into_boxed_slice(),
            source_port: source_port_to_accept.into_boxed_slice(),
            source_port_range: source_port_ranges_to_accept.into_boxed_slice(),
            destination_port: destination_port_to_accept.into_boxed_slice(),
            destination_port_range: destination_port_ranges_to_accept.into_boxed_slice(),
        })
    }

    pub fn should_packet_be_processed<'a, T: PacketBodyObject>(
        &self,
        ip_header: &IpVersions<'a>,
        packet: &T,
    ) -> bool {
        let mut should_continue = self.protocols.is_empty();
        for protocol in &self.protocols {
            if ip_header.get_protocol() == *protocol {
                should_continue = true;
                break;
            }
        }
        if !should_continue {
            return false;
        }

        let mut should_continue =
            self.destination_port.is_empty() && self.destination_port_range.is_empty();
        for destination_port_ranges in &self.destination_port_range {
            if packet.get_destination_port() >= destination_port_ranges.0
                && packet.get_destination_port() <= destination_port_ranges.1
            {
                should_continue = true;
                break;
            }
        }
        for destination_ports in &self.destination_port {
            if packet.get_destination_port() == *destination_ports {
                should_continue = true;
                break;
            }
        }
        if !should_continue {
            return false;
        }

        let mut should_continue = self.source_port.is_empty() && self.source_port_range.is_empty();
        for source_port_ranges in &self.source_port_range {
            if packet.get_source_port() >= source_port_ranges.0
                && packet.get_source_port() <= source_port_ranges.1
            {
                should_continue = true;
                break;
            }
        }
        for source_ports in &self.source_port {
            if packet.get_source_port() == *source_ports {
                should_continue = true;
                break;
            }
        }

        should_continue
    }
}

// #[cfg(test)]
// mod source_port_test {
//     use crate::{custom_ip_address::IpV4Address, ip_header::IpHeader};

//     use super::*;

//     #[test]
//     fn with_a_singular_source_port() {
//         let validator = TcpObjectValidation::internal_new(Args {
//             interface: String::new(),
//             protocol: Some(Vec::new()),
//             source_port_range: Some(Vec::new()),
//             source_port: Some(vec!["1024".to_string()]),
//             destination_port_range: Some(Vec::new()),
//             destination_port: Some(Vec::new()),
//         })
//         .unwrap();

//         assert_eq!(
//             validator.should_packet_be_processed(
//                 &IpVersions::V4(IpHeader {
//                     version: -1,
//                     ihl: -1,
//                     _tos: -1,
//                     total_length: -1,
//                     _fragment: &[u8; 0],
//                     _fragment_offset: &[u8; 0],
//                     _options: &[u8; 0],
//                     data: nil,
//                     destination_ip: IpV4Address::new(&[u8; 0]),
//                     ip_header_checksum: -1,
//                     protocol: TransportLayerProtocol::TCP,
//                     source_ip: IpV4Address::new(&[u8; 0]),
//                     ttl: -1,
//                 }),
//                 packet
//             ),
//             true
//         );
//     }
// }
