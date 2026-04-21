use std::fmt;

use crate::locator::{
    custom_ip_address::{IpAddress, IpAddressVariant, IpV4Address, IpV6Address},
    mac_address::MacAddress,
};

pub struct ArpObject<'a> {
    pub _hardware_type: u16,
    pub _protocol_type: u16,
    pub _hardware_size: u8,
    pub _protocol_size: u8,
    pub op_code: ArpOperation,
    pub sender_mac_address: MacAddress<'a>,
    pub sender_ip_address: IpAddressVariant<'a>,
    pub target_mac_address: MacAddress<'a>,
    pub target_ip_address: IpAddressVariant<'a>,
}

impl<'a> ArpObject<'a> {
    pub fn new(arp_payload: &'a [u8]) -> Result<Self, String> {
        let hardware_type = (arp_payload[0] as u16) << 8 | arp_payload[1] as u16;
        let protocol_type = (arp_payload[2] as u16) << 8 | arp_payload[3] as u16;
        let hardware_size = arp_payload[4];
        let protocol_size = arp_payload[5];
        let op_code = (arp_payload[6] as u16) << 8 | arp_payload[7] as u16;
        let op_code = match op_code {
            0x1 => ArpOperation::Request,
            0x2 => ArpOperation::Reply,
            _ => return Err(format!("Invalid op code: {}", op_code)),
        };

        let sender_mac_address = MacAddress::new(&arp_payload[8..14]);
        let target_mac_address = MacAddress::new(&arp_payload[18..24]);

        let sender_ip_address = match protocol_type {
            0x0800 => IpAddressVariant::V4(IpV4Address::new(&arp_payload[14..18])),
            0x86dd => IpAddressVariant::V6(IpV6Address::new(&arp_payload[14..18])), // ipv6 should be longer?
            _ => IpAddressVariant::V4(IpV4Address::new(&arp_payload[14..18])),
        };

        let target_ip_address = match protocol_type {
            0x0800 => IpAddressVariant::V4(IpV4Address::new(&arp_payload[24..28])),
            0x86dd => IpAddressVariant::V6(IpV6Address::new(&arp_payload[24..28])), // ipv6 should be longer?
            _ => IpAddressVariant::V4(IpV4Address::new(&arp_payload[24..28])),
        };

        Ok(Self {
            _hardware_type: hardware_type,
            _protocol_type: protocol_type,
            _hardware_size: hardware_size,
            _protocol_size: protocol_size,
            op_code,
            sender_mac_address,
            sender_ip_address,
            target_mac_address,
            target_ip_address,
        })
    }
}

pub enum ArpOperation {
    Request,
    Reply,
}

impl<'a> fmt::Display for ArpOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ArpOperation::Request => write!(f, "Request"),
            ArpOperation::Reply => write!(f, "Reply"),
        }
    }
}
