use crate::ip_header::{IpObject, IpVersions};

pub struct UdpObject<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub check_sum: u16,
    pub content: String,

    based_off: &'a IpVersions<'a>,
}

impl<'a> UdpObject<'a> {
    pub fn new(ip_header: &'a IpVersions) -> Result<Self, String> {
        let tcp_payload = ip_header.get_data();
        let source_port = (tcp_payload[0] as u16) << 8 | tcp_payload[1] as u16;
        let destination_port = (tcp_payload[2] as u16) << 8 | tcp_payload[3] as u16;
        let length = (tcp_payload[4] as u16) << 8 | tcp_payload[5] as u16;
        let check_sum = (tcp_payload[6] as u16) << 8 | tcp_payload[7] as u16;
        let content = tcp_payload[8..]
            .iter()
            .map(|c| *c as char)
            .collect::<String>();

        Ok(Self {
            source_port,
            destination_port,
            length,
            check_sum,
            content: content,
            based_off: ip_header,
        })
    }
}
