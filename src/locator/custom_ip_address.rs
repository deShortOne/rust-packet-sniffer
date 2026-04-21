use std::fmt;

// use std::net::Ipv4Addr; could look to use this instead
use crate::helper::join_nums;

pub trait IpAddress {
    fn new(address: &[u8]) -> Self
    where
        Self: Sized;
    fn get_raw_bytes(&self) -> &Vec<u8>;
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct IpV4Address {
    address: String,
    address_raw: Vec<u8>,
}

impl IpAddress for IpV4Address {
    fn new(address: &[u8]) -> Self {
        Self {
            address: join_nums(address, "."),
            address_raw: address.to_vec(),
        }
    }

    fn get_raw_bytes(&self) -> &Vec<u8> {
        &self.address_raw
    }
}

impl fmt::Display for IpV4Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct IpV6Address {
    address: String,
    address_raw: Vec<u8>,
}

impl IpAddress for IpV6Address {
    fn new(address: &[u8]) -> Self {
        Self {
            address: join_nums(address, ":"),
            address_raw: address.to_vec(),
        }
    }

    fn get_raw_bytes(&self) -> &Vec<u8> {
        &self.address_raw
    }
}

impl fmt::Display for IpV6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[derive(Eq, Hash, PartialEq)]
pub enum IpAddressVariant {
    V4(IpV4Address),
    V6(IpV6Address),
}

impl fmt::Display for IpAddressVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddressVariant::V4(i) => i.fmt(f),
            IpAddressVariant::V6(i) => i.fmt(f),
        }
    }
}
