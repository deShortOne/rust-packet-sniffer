use crate::tcp::PacketBodyObject;

pub struct _FakePacketBody {
    source_port: u16,
    destination_port: u16,
}

impl _FakePacketBody {
    pub fn _new(source_port: u16, destination_port: u16) -> Self {
        Self {
            source_port,
            destination_port,
        }
    }
}

impl PacketBodyObject for _FakePacketBody {
    fn get_destination_port(&self) -> u16 {
        self.destination_port
    }

    fn get_source_port(&self) -> u16 {
        self.source_port
    }
}
