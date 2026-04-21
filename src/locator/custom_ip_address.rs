use std::fmt;

// use std::net::Ipv4Addr; could look to use this instead
use crate::helper::join_nums;

pub trait IpAddress<'a> {
    fn new(address: &'a [u8]) -> Self
    where
        Self: Sized;
    fn get_raw_bytes(&self) -> &[u8];
}

pub struct IpV4Address<'a> {
    address: String,
    address_raw: &'a [u8],
}

impl<'a> IpAddress<'a> for IpV4Address<'a> {
    fn new(address: &'a [u8]) -> Self {
        Self {
            address: join_nums(address, "."),
            address_raw: address,
        }
    }

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

impl<'a> IpAddress<'a> for IpV6Address<'a> {
    fn new(address: &'a [u8]) -> Self {
        Self {
            address: join_nums(address, ":"),
            address_raw: address,
        }
    }

    fn get_raw_bytes(&self) -> &[u8] {
        self.address_raw
    }
}

impl<'a> fmt::Display for IpV6Address<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

pub enum IpAddressVariant<'a> {
    V4(IpV4Address<'a>),
    V6(IpV6Address<'a>),
}

impl<'a> fmt::Display for IpAddressVariant<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddressVariant::V4(i) => i.fmt(f),
            IpAddressVariant::V6(i) => i.fmt(f),
        }
    }
}
