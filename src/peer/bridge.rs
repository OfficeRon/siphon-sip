//! PCM copy between two peers. Each peer keeps its own payload type.
//! Telephone-event is not audio: the end packet of a digit is reported up.

use super::codec;

#[derive(Debug)]
pub struct Bridge {
    pub a: String,
    pub b: String,
    pub a_to_b: u64,
    pub b_to_a: u64,
}

impl Bridge {
    pub fn other(&self, id: &str) -> Option<&str> {
        if id == self.a {
            Some(&self.b)
        } else if id == self.b {
            Some(&self.a)
        } else {
            None
        }
    }

    pub fn count(&mut self, from: &str) {
        if from == self.a {
            self.a_to_b += 1;
        } else if from == self.b {
            self.b_to_a += 1;
        }
    }
}

pub fn forward(in_codec: &str, payload: &[u8], out_codec: &str) -> Vec<u8> {
    codec::transcode(in_codec, payload, out_codec)
}

/// RFC 4733. Only the packet with the end bit set is a digit, so a
/// repeating event does not surface once per frame.
pub fn dtmf_end(payload: &[u8]) -> Option<char> {
    if payload.len() < 2 || payload[1] & 0x80 == 0 {
        return None;
    }
    Some(match payload[0] {
        0..=9 => (b'0' + payload[0]) as char,
        10 => '*',
        11 => '#',
        12..=15 => (b'A' + (payload[0] - 12)) as char,
        _ => return None,
    })
}
