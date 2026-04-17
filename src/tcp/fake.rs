use crate::tcp::PacketBodyObject;

pub struct FakePacketBody {
    source_port: u16,
    destination_port: u16,
}

impl FakePacketBody {
    pub fn new(source_port: u16, destination_port: u16) -> Self {
        Self {
            source_port,
            destination_port,
        }
    }
}

impl PacketBodyObject for FakePacketBody {
    fn get_destination_port(&self) -> u16 {
        self.destination_port
    }

    fn get_source_port(&self) -> u16 {
        self.source_port
    }
}
