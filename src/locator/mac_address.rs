use std::fmt;

use crate::helper::join_nums;

pub struct MacAddress<'a> {
    address: String,
    _address_raw: &'a [u8],
}

impl<'a> MacAddress<'a> {
    pub fn new(address: &'a [u8]) -> Self {
        Self {
            address: join_nums(address, ":"),
            _address_raw: address,
        }
    }
}

impl<'a> fmt::Display for MacAddress<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}
