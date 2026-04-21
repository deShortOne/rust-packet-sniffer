use std::fmt;

use crate::helper::join_nums;

pub struct MacAddress {
    address: String,
    _address_raw: Vec<u8>,
}

impl MacAddress {
    pub fn new(address: &[u8]) -> Self {
        Self {
            address: join_nums(address, ":"),
            _address_raw: address.to_vec(),
        }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}
