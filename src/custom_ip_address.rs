use std::fmt;

// use std::net::Ipv4Addr; could look to use this instead
use crate::helper::join_nums;

pub trait IpAddress {
    fn get_raw_bytes(&self) -> &[u8];
}

pub struct IpV4Address<'a> {
    address: String,
    address_raw: &'a [u8],
}

impl<'a> IpV4Address<'a> {
    pub fn new(address: &'a [u8]) -> Self {
        Self {
            address: join_nums(address, "."),
            address_raw: address,
        }
    }
}

impl<'a> IpAddress for IpV4Address<'a> {
    fn get_raw_bytes(&self) -> &[u8] {
        self.address_raw
    }
}

impl<'a> fmt::Display for IpV4Address<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

pub struct IpV6Address<'a> {
    address: String,
    address_raw: &'a [u8],
}

impl<'a> IpV6Address<'a> {
    pub fn new(address: &'a [u8]) -> Self {
        Self {
            address: join_nums(address, ":"),
            address_raw: address,
        }
    }
}

impl<'a> IpAddress for IpV6Address<'a> {
    fn get_raw_bytes(&self) -> &[u8] {
        self.address_raw
    }
}

impl<'a> fmt::Display for IpV6Address<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}
