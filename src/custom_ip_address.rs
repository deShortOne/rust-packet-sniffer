use std::fmt;

// use std::net::Ipv4Addr; could look to use this instead
use crate::helper::join_nums;

pub struct IpV4Address {
    address: String,
}

impl IpV4Address {
    pub fn new(address: &[u8]) -> Self {
        Self {
            address: join_nums(address, "."),
        }
    }
}

impl fmt::Display for IpV4Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}
