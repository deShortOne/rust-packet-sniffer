use clap::Parser;

use crate::ip_headers::ip_header::IpObject;
use crate::tcp::PacketBodyObject;
use crate::transport_layer_protocol::TransportLayerProtocol;

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
    pub is_arp_allowed: bool,
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
                match protocol.to_uppercase().as_str() {
                    "TCP" => protocols_to_accept.push(TransportLayerProtocol::TCP),
                    "UDP" => protocols_to_accept.push(TransportLayerProtocol::UDP),
                    "ARP" => protocols_to_accept.push(TransportLayerProtocol::ARP),
                    _ => {}
                };
            }
        }

        let mut source_port_ranges_to_accept: Vec<(u16, u16)> = Vec::new();
        if let Some(source_port_ranges) = args.source_port_range {
            for source_port_range in source_port_ranges {
                let ranges = source_port_range
                    .split("-")
                    .map(str::parse::<u16>)
                    .collect::<Result<Vec<_>, _>>();
                match ranges {
                    Ok(range) if range.len() == 2 => {
                        if range[0] > range[1] {
                            return Err(format!(
                                "--source-port-range expects left value to be smaller or equal to right number but for ({}, {})",
                                range[0], range[1]
                            ));
                        }
                        source_port_ranges_to_accept.push((range[0], range[1]));
                    }
                    _ => {
                        return Err(
                            "--source-port-range expects a range of port numbers in the format of \"1000-2000\"".to_string()
                        );
                    }
                }
            }
        }
        let mut source_port_to_accept: Vec<u16> = Vec::new();
        if let Some(source_ports) = args.source_port {
            for source_port_range in source_ports {
                match source_port_range.parse::<u16>() {
                    Ok(i) => source_port_to_accept.push(i),
                    Err(_) => {
                        return Err("--source-port expects a singular port number".to_string());
                    }
                }
            }
        }

        let mut destination_port_ranges_to_accept: Vec<(u16, u16)> = Vec::new();
        if let Some(destination_port_ranges) = args.destination_port_range {
            for destination_port_range in destination_port_ranges {
                let ranges = destination_port_range
                    .split("-")
                    .map(str::parse::<u16>)
                    .collect::<Result<Vec<_>, _>>();
                match ranges {
                    Ok(range) if range.len() == 2 => {
                        if range[0] > range[1] {
                            return Err(format!(
                                "--destination-port-range expects left value to be smaller or equal to right number but for ({}, {})",
                                range[0], range[1]
                            ));
                        }
                        destination_port_ranges_to_accept.push((range[0], range[1]))
                    }
                    _ => 
                        return Err(
                            "--destination-port-range expects a range of port numbers in the format of \"1000-2000\"".to_string()
                        )
                }
            }
        }
        let mut destination_port_to_accept: Vec<u16> = Vec::new();
        if let Some(destination_ports) = args.destination_port {
            for destination_port_range in destination_ports {
                match destination_port_range.parse::<u16>() {
                    Ok(i) => destination_port_to_accept.push(i),
                    Err(_) => {
                        return Err("--destination-port expects a singular port number".to_string());
                    }
                }
            }
        }

        Ok(Self {
            interface: args.interface,
            is_arp_allowed: protocols_to_accept.contains(&TransportLayerProtocol::ARP),
            protocols: protocols_to_accept.into_boxed_slice(),
            source_port: source_port_to_accept.into_boxed_slice(),
            source_port_range: source_port_ranges_to_accept.into_boxed_slice(),
            destination_port: destination_port_to_accept.into_boxed_slice(),
            destination_port_range: destination_port_ranges_to_accept.into_boxed_slice(),
        })
    }

    pub fn should_packet_be_processed<T: IpObject, U: PacketBodyObject>(
        &self,
        ip_header: &T,
        packet: &U,
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

#[cfg(test)]
mod source_port_test {
    use crate::ip_headers::ip_header_test::_IpHeaderTestObject;
    use crate::tcp::fake::_FakePacketBody;

    use super::*;

    #[test]
    fn with_a_singular_source_port() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(Vec::new()),
            source_port: Some(vec!["1024".to_string()]),
            destination_port_range: Some(Vec::new()),
            destination_port: Some(Vec::new()),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1024, 3000)
            ),
            true
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2024, 3000)
            ),
            false
        );
    }

    #[test]
    fn with_multiple_singular_source_ports() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(Vec::new()),
            source_port: Some(vec![
                "1024".to_string(),
                "1025".to_string(),
                "1090".to_string(),
            ]),
            destination_port_range: Some(Vec::new()),
            destination_port: Some(Vec::new()),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1024, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1025, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1090, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1080, 3000)
            ),
            false
        );
    }

    #[test]
    fn with_a_ranged_source_port() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(vec!["1024-1090".to_string()]),
            source_port: Some(Vec::new()),
            destination_port_range: Some(Vec::new()),
            destination_port: Some(Vec::new()),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1024, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1080, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1090, 3000)
            ),
            true
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2024, 3000)
            ),
            false
        );
    }

    #[test]
    fn with_multiple_ranged_source_port() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(vec!["1024-1090".to_string(), "2024-2090".to_string()]),
            source_port: Some(Vec::new()),
            destination_port_range: Some(Vec::new()),
            destination_port: Some(Vec::new()),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1024, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1080, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1090, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2023, 3000)
            ),
            false
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2024, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2080, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2090, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3023, 3000)
            ),
            false
        );
    }

    #[test]
    fn with_multiple_ranged_source_port_and_multiple_singular_ports() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(vec!["1024-1090".to_string(), "2024-2090".to_string()]),
            source_port: Some(vec!["2000".to_string()]),
            destination_port_range: Some(Vec::new()),
            destination_port: Some(Vec::new()),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2000, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1999, 3000)
            ),
            false
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2001, 3000)
            ),
            false
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1024, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1080, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1090, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2023, 3000)
            ),
            false
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2024, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2080, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(2090, 3000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3023, 3000)
            ),
            false
        );
    }
}

#[cfg(test)]
mod destination_port_test {
    use crate::ip_headers::ip_header_test::_IpHeaderTestObject;
    use crate::tcp::fake::_FakePacketBody;

    use super::*;

    #[test]
    fn with_multiple_ranged_destination_port_and_multiple_destination_ports() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(Vec::new()),
            source_port: Some(Vec::new()),
            destination_port_range: Some(vec!["1024-1090".to_string(), "2024-2090".to_string()]),
            destination_port: Some(vec!["2000".to_string()]),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 2000)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 1999)
            ),
            false
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 2001)
            ),
            false
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 1024)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 1080)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 1090)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 2023)
            ),
            false
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 2024)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 2080)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 2090)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(3000, 3023)
            ),
            false
        );
    }
}

#[cfg(test)]
mod mixture_of_source_and_destination_ports_test {
    use super::*;
    use crate::cli::TcpObjectValidation;
     use crate::ip_headers::ip_header_test::_IpHeaderTestObject;
    use crate:: tcp::fake::_FakePacketBody;

    #[test]
    fn when_one_matches_but_not_the_other() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(vec!["1020-1040".to_string(), "1060-1080".to_string()]),
            source_port: Some(vec!["1050".to_string()]),
            destination_port_range: Some(vec!["2020-2040".to_string(), "2060-2080".to_string()]),
            destination_port: Some(vec!["2050".to_string()]),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1030, 2000)
            ),
            false
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1050, 2000)
            ),
            false
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1070, 2000)
            ),
            false
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1000, 2030)
            ),
            false
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1000, 2050)
            ),
            false
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1000, 2070)
            ),
            false
        );
    }

    #[test]
    fn when_both_matches() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(vec!["1020-1040".to_string(), "1060-1080".to_string()]),
            source_port: Some(vec!["1050".to_string()]),
            destination_port_range: Some(vec!["2020-2040".to_string(), "2060-2080".to_string()]),
            destination_port: Some(vec!["2050".to_string()]),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1030, 2030)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1050, 2030)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1070, 2070)
            ),
            true
        );

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1030, 2030)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1030, 2050)
            ),
            true
        );
        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1070, 2070)
            ),
            true
        );
    }

    #[test]
    fn when_neither_matches() {
        let validator = TcpObjectValidation::internal_new(Args {
            interface: String::new(),
            protocol: Some(Vec::new()),
            source_port_range: Some(vec!["1020-1040".to_string(), "1060-1080".to_string()]),
            source_port: Some(vec!["1050".to_string()]),
            destination_port_range: Some(vec!["2020-2040".to_string(), "2060-2080".to_string()]),
            destination_port: Some(vec!["2050".to_string()]),
        })
        .unwrap();

        assert_eq!(
            validator.should_packet_be_processed(
                &_IpHeaderTestObject::_new(TransportLayerProtocol::Unknown(1)),
                &_FakePacketBody::_new(1000, 2000)
            ),
            false
        );
    }
}
