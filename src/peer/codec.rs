//! G.711 and Opus, the two audio codecs a peer actually has to bridge.
//!
//! PCMU and PCMA are 8 kHz. Opus is 48 kHz. The bridge speaks PCM between them.

use opus::{Application, Channels, Encoder, Decoder};

pub fn silence(codec: &str) -> Vec<u8> {
    match codec {
        "pcmu" => vec![0xff; 160],
        "pcma" => vec![0xd5; 160],
        _ => opus_silence(),
    }
}

pub fn opus_silence() -> Vec<u8> {
    let pcm = [0i16; 960];
    encode_opus(&pcm).unwrap_or_else(|_| vec![0xf8, 0xff, 0xfe])
}

pub fn transcode(in_codec: &str, payload: &[u8], out_codec: &str) -> Vec<u8> {
    if in_codec == out_codec {
        return payload.to_vec();
    }
    let pcm48 = match decode(in_codec, payload) {
        Some(pcm) => pcm,
        None => return Vec::new(),
    };
    encode(out_codec, &pcm48).unwrap_or_default()
}

fn decode(codec: &str, payload: &[u8]) -> Option<Vec<i16>> {
    match codec {
        "pcmu" => Some(upsample(&payload.iter().copied().map(pcmu_decode).collect::<Vec<_>>())),
        "pcma" => Some(upsample(&payload.iter().copied().map(pcma_decode).collect::<Vec<_>>())),
        "opus" => decode_opus(payload).ok(),
        _ => None,
    }
}

fn encode(codec: &str, pcm48: &[i16]) -> Result<Vec<u8>, String> {
    match codec {
        "pcmu" => Ok(downsample(pcm48).into_iter().map(pcmu_encode).collect()),
        "pcma" => Ok(downsample(pcm48).into_iter().map(pcma_encode).collect()),
        "opus" => encode_opus(pcm48),
        other => Err(format!("no codec {other}")),
    }
}

fn encode_opus(pcm48: &[i16]) -> Result<Vec<u8>, String> {
    let mut enc = Encoder::new(48_000, Channels::Mono, Application::Voip)
        .map_err(|err| err.to_string())?;
    let mut frame = [0i16; 960];
    let n = pcm48.len().min(960);
    frame[..n].copy_from_slice(&pcm48[..n]);
    let mut out = vec![0u8; 4000];
    let written = enc.encode(&frame, &mut out).map_err(|err| err.to_string())?;
    out.truncate(written);
    Ok(out)
}

fn decode_opus(payload: &[u8]) -> Result<Vec<i16>, String> {
    let mut dec = Decoder::new(48_000, Channels::Mono).map_err(|err| err.to_string())?;
    let mut pcm = vec![0i16; 960];
    let n = dec.decode(payload, &mut pcm, false).map_err(|err| err.to_string())?;
    pcm.truncate(n);
    Ok(pcm)
}

fn upsample(pcm8: &[i16]) -> Vec<i16> {
    if pcm8.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(pcm8.len() * 6);
    for (index, sample) in pcm8.iter().enumerate() {
        let next = pcm8.get(index + 1).copied().unwrap_or(*sample);
        for step in 0..6 {
            let sample = *sample as i32;
            let delta = (next as i32 - sample) * step / 6;
            out.push((sample + delta) as i16);
        }
    }
    out
}

fn downsample(pcm48: &[i16]) -> Vec<i16> {
    pcm48.chunks(6).map(|chunk| chunk[0]).collect()
}

fn pcmu_decode(byte: u8) -> i16 {
    let byte = !byte;
    let sign = byte & 0x80;
    let exp = (byte >> 4) & 0x07;
    let mant = byte & 0x0f;
    let mut sample = (((mant as i32) << 3) + 0x84) << exp;
    sample -= 0x84;
    if sign != 0 { -sample as i16 } else { sample as i16 }
}

fn pcmu_encode(sample: i16) -> u8 {
    let mut sample = sample as i32;
    let sign = if sample < 0 { 0x80 } else { 0 };
    if sample < 0 {
        sample = -sample;
    }
    sample += 0x84;
    if sample > 0x7fff {
        sample = 0x7fff;
    }
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && (sample & mask) == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = (sample >> (exp + 3)) & 0x0f;
    !(sign | (exp << 4) | mant as u8)
}

fn pcma_decode(byte: u8) -> i16 {
    let byte = byte ^ 0x55;
    let sign = byte & 0x80;
    let exp = (byte >> 4) & 0x07;
    let mant = byte & 0x0f;
    let mut sample = ((mant as i32) << 4) + 8;
    if exp != 0 {
        sample = (sample + 0x100) << (exp - 1);
    }
    if sign != 0 { -sample as i16 } else { sample as i16 }
}

fn pcma_encode(sample: i16) -> u8 {
    let mut sample = sample as i32;
    let sign = if sample < 0 { 0x80 } else { 0 };
    if sample < 0 {
        sample = -sample;
    }
    if sample > 0x7fff {
        sample = 0x7fff;
    }
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && (sample & mask) == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = if exp == 0 { (sample >> 4) & 0x0f } else { (sample >> (exp + 3)) & 0x0f };
    (sign | (exp << 4) | mant as u8) ^ 0x55
}
