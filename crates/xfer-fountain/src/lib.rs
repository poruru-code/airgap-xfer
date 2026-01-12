pub use raptorq::{EncodingPacket, ObjectTransmissionInformation, PayloadId};

#[derive(Debug, Clone)]
pub struct RaptorqEncoder {
    config: ObjectTransmissionInformation,
    block_encoders: Vec<raptorq::SourceBlockEncoder>,
    source_packets: Vec<Vec<EncodingPacket>>,
    source_offsets: Vec<usize>,
    repair_offsets: Vec<u32>,
    next_block: usize,
}

impl RaptorqEncoder {
    pub fn new(data: &[u8], config: ObjectTransmissionInformation) -> Self {
        let encoder = raptorq::Encoder::new(data, config);
        let block_encoders = encoder.get_block_encoders().clone();
        if block_encoders.is_empty() {
            panic!("raptorq encoder created with zero source blocks");
        }
        let source_packets = block_encoders
            .iter()
            .map(|block| block.source_packets())
            .collect::<Vec<_>>();
        let block_count = block_encoders.len();
        RaptorqEncoder {
            config,
            block_encoders,
            source_packets,
            source_offsets: vec![0; block_count],
            repair_offsets: vec![0; block_count],
            next_block: 0,
        }
    }

    pub fn with_defaults(data: &[u8], max_packet_size: u16) -> Self {
        let config =
            ObjectTransmissionInformation::with_defaults(data.len() as u64, max_packet_size);
        Self::new(data, config)
    }

    pub fn config(&self) -> ObjectTransmissionInformation {
        self.config
    }

    pub fn block_count(&self) -> usize {
        self.block_encoders.len()
    }

    pub fn source_packet_count(&self) -> usize {
        self.source_packets.iter().map(|packets| packets.len()).sum()
    }

    pub fn source_packets_per_block(&self) -> Vec<usize> {
        self.source_packets.iter().map(|packets| packets.len()).collect()
    }

    pub fn encode_all_packets(&self, repair_packets_per_block: u32) -> Vec<EncodingPacket> {
        let mut packets = Vec::new();
        for block in &self.block_encoders {
            packets.extend(block.source_packets());
            if repair_packets_per_block > 0 {
                packets.extend(block.repair_packets(0, repair_packets_per_block));
            }
        }
        packets
    }

    pub fn next_packet(&mut self) -> EncodingPacket {
        let block_count = self.block_encoders.len();
        for _ in 0..block_count {
            let idx = self.next_block;
            self.next_block = (self.next_block + 1) % block_count;
            let source_index = self.source_offsets[idx];
            if source_index < self.source_packets[idx].len() {
                let packet = self.source_packets[idx][source_index].clone();
                self.source_offsets[idx] += 1;
                return packet;
            }
        }

        let idx = self.next_block;
        self.next_block = (self.next_block + 1) % block_count;
        let start_repair_symbol_id = self.repair_offsets[idx];
        self.repair_offsets[idx] += 1;
        self.block_encoders[idx]
            .repair_packets(start_repair_symbol_id, 1)
            .into_iter()
            .next()
            .expect("repair_packets returned empty")
    }
}

#[derive(Debug, Clone)]
pub struct RaptorqDecoder {
    config: ObjectTransmissionInformation,
    inner: raptorq::Decoder,
}

impl RaptorqDecoder {
    pub fn new(config: ObjectTransmissionInformation) -> Self {
        RaptorqDecoder {
            config,
            inner: raptorq::Decoder::new(config),
        }
    }

    pub fn config(&self) -> ObjectTransmissionInformation {
        self.config
    }

    pub fn push_packet(&mut self, packet: EncodingPacket) -> Option<Vec<u8>> {
        self.inner.decode(packet)
    }

    pub fn add_packet(&mut self, packet: EncodingPacket) {
        self.inner.add_new_packet(packet);
    }

    pub fn recover(&self) -> Option<Vec<u8>> {
        self.inner.get_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raptorq_roundtrip_small() {
        let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
        let config = ObjectTransmissionInformation::with_defaults(data.len() as u64, 1024);
        let mut encoder = RaptorqEncoder::new(&data, config);
        let mut decoder = RaptorqDecoder::new(config);

        let mut recovered = None;
        for _ in 0..2000 {
            let packet = encoder.next_packet();
            recovered = decoder.push_packet(packet);
            if recovered.is_some() {
                break;
            }
        }

        let recovered = recovered.or_else(|| decoder.recover());
        assert_eq!(recovered.as_deref(), Some(&data[..]));
    }
}
