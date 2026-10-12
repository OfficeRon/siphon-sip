//! One peer. One [`Rtc`](str0m::Rtc), so a later offer that adds audio stays
//! on the ICE agent and the DTLS association that are already up.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{Pt, RtpWrite, SeqNo};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

#[derive(Debug, Clone)]
pub struct Packet {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub contents: Vec<u8>,
}

#[derive(Debug)]
pub enum ScriptEvent {
    ChannelOpen,
    ChannelClose,
    ChannelData(String),
    Connection(String),
    Ice(String),
    Dtls(String),
    Dtmf(char),
    Audio { codec: String, payload: Vec<u8> },
}

pub struct Drain {
    pub transmits: Vec<Packet>,
    pub events: Vec<ScriptEvent>,
}

pub struct Peer {
    rtc: Rtc,
    now: Instant,
    pending: Option<SdpPendingOffer>,
    answer: Option<String>,
    local_sdp: String,
    channel: Option<ChannelId>,
    audio_mid: Option<Mid>,
    send_pt: Option<Pt>,
    pub send_codec: String,
    te_pts: Vec<u8>,
    pub candidates: Vec<String>,
    pub connected: bool,
    pub ice: String,
    pub dtls: String,
    seq: u64,
    ts: u32,
    pub want_audio: bool,
    pub host: SocketAddr,
    relay: Option<SocketAddr>,
}

impl Peer {
    pub fn new(host: SocketAddr, want_audio: bool) -> Result<Self, String> {
        let now = Instant::now();
        let mut rtc = Rtc::builder().build(now);
        let candidate = Candidate::host(host, "udp").map_err(|err| err.to_string())?;
        let line = candidate.to_sdp_string();
        rtc.add_local_candidate(candidate);
        Ok(Self {
            rtc,
            now,
            pending: None,
            answer: None,
            local_sdp: String::new(),
            channel: None,
            audio_mid: None,
            send_pt: None,
            send_codec: String::new(),
            te_pts: Vec::new(),
            candidates: vec![line],
            connected: false,
            ice: "new".into(),
            dtls: "new".into(),
            seq: 1,
            ts: 0,
            want_audio,
            host,
            relay: None,
        })
    }

    pub fn ufrag(&mut self) -> String {
        self.rtc.direct_api().local_ice_credentials().ufrag
    }

    pub fn add_host_like(&mut self, candidate: Candidate) {
        let line = candidate.to_sdp_string();
        if candidate.kind() == str0m::CandidateKind::Relayed {
            self.relay = Some(candidate.addr());
        }
        if self.rtc.add_local_candidate(candidate).is_some() && !self.candidates.contains(&line) {
            self.candidates.push(line);
        }
    }

    pub fn relay(&self) -> Option<SocketAddr> {
        self.relay
    }

    pub fn create_offer(&mut self) -> Result<String, String> {
        let mut change = self.rtc.sdp_api();
        if self.channel.is_none() {
            self.channel = Some(change.add_channel("chat".to_string()));
        }
        if self.want_audio && self.audio_mid.is_none() {
            self.audio_mid = Some(change.add_media(
                MediaKind::Audio,
                Direction::SendRecv,
                None,
                None,
                None,
            ));
        }
        match change.apply() {
            Some((offer, pending)) => {
                self.pending = Some(pending);
                let sdp = offer.to_sdp_string();
                self.note_sdp(&sdp);
                self.local_sdp = sdp.clone();
                Ok(sdp)
            }
            None => {
                if self.local_sdp.is_empty() {
                    Err("offer had nothing to add".into())
                } else {
                    Ok(self.local_sdp.clone())
                }
            }
        }
    }

    pub fn set_remote(&mut self, kind: &str, sdp: &str) -> Result<(), String> {
        self.note_sdp(sdp);
        if kind == "offer" {
            self.pending = None;
            let offer = SdpOffer::from_sdp_string(sdp).map_err(|err| err.to_string())?;
            let answer = self.rtc.sdp_api().accept_offer(offer).map_err(|err| err.to_string())?;
            let text = answer.to_sdp_string();
            self.note_sdp(&text);
            self.local_sdp = text.clone();
            self.answer = Some(text);
            Ok(())
        } else {
            let answer = SdpAnswer::from_sdp_string(sdp).map_err(|err| err.to_string())?;
            let pending = self.pending.take().ok_or("no pending offer for this answer")?;
            self.rtc.sdp_api().accept_answer(pending, answer).map_err(|err| err.to_string())?;
            Ok(())
        }
    }

    pub fn take_answer(&self) -> Option<String> {
        self.answer.clone()
    }

    pub fn add_remote_candidate(&mut self, line: &str) -> Result<(), String> {
        let line = line.trim().trim_start_matches("a=").trim();
        if line.is_empty() || line.eq_ignore_ascii_case("end-of-candidates") {
            return Ok(());
        }
        let candidate = Candidate::from_sdp_string(line).map_err(|err| err.to_string())?;
        self.rtc.add_remote_candidate(candidate);
        Ok(())
    }

    pub fn rotate_ssrc(&mut self) -> Result<(), String> {
        let mid = self.audio_mid.ok_or("no audio mid")?;
        let (ssrc, rtx) = {
            let api = self.rtc.direct_api();
            (api.new_ssrc(), api.new_ssrc())
        };
        if self.rtc.direct_api().reset_stream_tx(mid, None, ssrc, Some(rtx)).is_none() {
            return Err("ssrc reset found no audio stream".into());
        }
        Ok(())
    }

    pub fn tx_ssrc_label(&mut self) -> Option<String> {
        let mid = self.audio_mid?;
        let api = self.rtc.direct_api();
        let tx = api.stream_tx_by_mid(mid, None)?;
        Some(format!("{:?}", tx.ssrc()))
    }

    pub fn send_text(&mut self, text: &str) -> Result<(), String> {
        let id = self.channel.ok_or("no data channel")?;
        let mut channel = self.rtc.channel(id).ok_or("data channel is not open")?;
        channel.write(false, text.as_bytes()).map_err(|err| err.to_string())?;
        Ok(())
    }

    pub fn write_audio(&mut self, payload: &[u8]) -> Result<(), String> {
        let mid = self.audio_mid.ok_or("no audio mid")?;
        let pt = self.send_pt.ok_or("no send payload type")?;
        let writer = self.rtc.writer(mid).ok_or("audio is not sending")?;
        let time = MediaTime::new(self.ts as u64, Frequency::FORTY_EIGHT_KHZ);
        writer.write(pt, self.now, time, payload).map_err(|err| err.to_string())?;
        self.ts = self.ts.wrapping_add(960);
        Ok(())
    }

    pub fn inject_dtmf(&mut self, digit: char) -> Result<(), String> {
        let event = match digit {
            '0'..='9' => digit as u8 - b'0',
            '*' => 10,
            '#' => 11,
            'A'..='D' => digit as u8 - b'A' + 12,
            _ => return Err(format!("not a dtmf digit: {digit}")),
        };
        let pt = Pt::from(*self.te_pts.first().ok_or("telephone-event was not negotiated")?);
        let mid = self.audio_mid.ok_or("no audio mid")?;
        let payload = [event, 0x8a, 0x00, 0xa0];
        let seq = SeqNo::from(self.seq);
        self.seq += 1;
        let write = RtpWrite::new(pt, seq, self.ts, self.now, payload.to_vec()).marker(true);
        self.rtc.direct_api().stream_tx_by_mid(mid, None).ok_or("no audio stream")?.write_rtp(write);
        self.ts = self.ts.wrapping_add(160);
        Ok(())
    }

    pub fn receive(&mut self, source: SocketAddr, destination: SocketAddr, contents: &[u8]) -> Result<(), String> {
        let contents = contents.try_into().map_err(|_| "datagram too large".to_string())?;
        self.rtc.handle_input(Input::Receive(
            self.now,
            Receive { proto: Protocol::Udp, source, destination, contents },
        )).map_err(|err| err.to_string())
    }

    pub fn advance(&mut self, by: Duration) -> Result<(), String> {
        self.now += by;
        self.rtc.handle_input(Input::Timeout(self.now)).map_err(|err| err.to_string())
    }

    pub fn close(&mut self) {
        self.rtc.disconnect();
        self.connected = false;
        self.ice = "closed".into();
        self.dtls = "closed".into();
    }

    pub fn drain(&mut self) -> Result<Drain, String> {
        let mut transmits = Vec::new();
        let mut events = Vec::new();
        loop {
            match self.rtc.poll_output().map_err(|err| err.to_string())? {
                Output::Timeout(_) => break,
                Output::Transmit(packet) => transmits.push(Packet {
                    source: packet.source,
                    destination: packet.destination,
                    contents: packet.contents.to_vec(),
                }),
                Output::Event(event) => {
                    if let Some(script) = self.on_event(event) {
                        events.push(script);
                    }
                }
            }
        }
        Ok(Drain { transmits, events })
    }

    fn on_event(&mut self, event: Event) -> Option<ScriptEvent> {
        match event {
            Event::Connected => {
                self.connected = true;
                self.dtls = "connected".into();
                Some(ScriptEvent::Dtls("connected".into()))
            }
            Event::IceConnectionStateChange(state) => {
                self.ice = ice_name(state).into();
                if matches!(state, IceConnectionState::Connected | IceConnectionState::Completed) {
                    self.connected = true;
                }
                Some(ScriptEvent::Ice(self.ice.clone()))
            }
            Event::ChannelOpen(id, _label) => {
                self.channel = Some(id);
                Some(ScriptEvent::ChannelOpen)
            }
            Event::ChannelClose(_) => {
                self.channel = None;
                Some(ScriptEvent::ChannelClose)
            }
            Event::ChannelData(data) => {
                let text = String::from_utf8_lossy(&data.data).into_owned();
                Some(ScriptEvent::ChannelData(text))
            }
            Event::MediaAdded(added) => {
                if added.kind == MediaKind::Audio {
                    self.audio_mid = Some(added.mid);
                }
                None
            }
            Event::MediaData(media) => {
                let pt = *media.pt;
                if self.te_pts.contains(&pt) {
                    return super::bridge::dtmf_end(&media.data).map(ScriptEvent::Dtmf);
                }
                Some(ScriptEvent::Audio {
                    codec: codec_name(pt, &self.send_codec),
                    payload: media.data.as_ref().to_vec(),
                })
            }
            _ => None,
        }
    }

    fn note_sdp(&mut self, sdp: &str) {
        let mut best: Option<(u8, String, u8)> = None;
        for line in sdp.lines() {
            let Some(rest) = line.trim().strip_prefix("a=rtpmap:") else { continue };
            let mut parts = rest.split_whitespace();
            let Ok(pt) = parts.next().unwrap_or("").parse::<u8>() else { continue };
            let codec = parts.next().unwrap_or("").to_ascii_lowercase();
            if codec.starts_with("telephone-event/8000") && !self.te_pts.contains(&pt) {
                self.te_pts.push(pt);
            }
            let rank = codec_rank(&codec);
            if rank == 0 {
                continue;
            }
            if best.as_ref().map(|(_, _, have)| rank > *have).unwrap_or(true) {
                best = Some((pt, codec_key(&codec).to_string(), rank));
            }
        }
        if let Some((pt, name, _)) = best {
            self.send_pt = Some(Pt::from(pt));
            self.send_codec = name;
        }
    }
}

fn codec_rank(codec: &str) -> u8 {
    if codec.starts_with("pcmu/") { 3 }
    else if codec.starts_with("pcma/") { 2 }
    else if codec.starts_with("opus/") { 1 }
    else { 0 }
}

fn codec_key(codec: &str) -> &'static str {
    if codec.starts_with("pcmu/") { "pcmu" }
    else if codec.starts_with("pcma/") { "pcma" }
    else { "opus" }
}

fn codec_name(pt: u8, fallback: &str) -> String {
    match pt {
        0 => "pcmu".into(),
        8 => "pcma".into(),
        _ => fallback.to_string(),
    }
}

fn ice_name(state: IceConnectionState) -> &'static str {
    match state {
        IceConnectionState::New => "new",
        IceConnectionState::Checking => "checking",
        IceConnectionState::Connected => "connected",
        IceConnectionState::Completed => "completed",
        IceConnectionState::Disconnected => "disconnected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(a: &mut Peer, b: &mut Peer) -> Result<(), String> {
        let left = a.drain()?;
        let right = b.drain()?;
        for packet in left.transmits {
            b.receive(packet.source, packet.destination, &packet.contents)?;
        }
        for packet in right.transmits {
            a.receive(packet.source, packet.destination, &packet.contents)?;
        }
        Ok(())
    }

    fn pump(a: &mut Peer, b: &mut Peer, rounds: usize) -> Result<(), String> {
        for _ in 0..rounds {
            exchange(a, b)?;
            a.advance(Duration::from_millis(20))?;
            b.advance(Duration::from_millis(20))?;
            exchange(a, b)?;
        }
        Ok(())
    }

    fn audio_mids(events: &[ScriptEvent]) -> Vec<String> {
        events.iter().filter_map(|event| match event {
            ScriptEvent::Audio { .. } => Some("audio".into()),
            _ => None,
        }).collect()
    }

    #[test]
    fn bundled_audio_stays_on_the_same_ice_agent() {
        let mut phone = Peer::new("1.1.1.1:1000".parse().unwrap(), false).unwrap();
        let mut edge = Peer::new("2.2.2.2:2000".parse().unwrap(), false).unwrap();
        let ufrag = phone.ufrag();

        let offer = phone.create_offer().unwrap();
        assert!(offer.contains("webrtc-datachannel"), "{offer}");
        assert!(!offer.contains("m=audio"), "{offer}");
        edge.set_remote("offer", &offer).unwrap();
        let answer = edge.take_answer().unwrap();
        phone.set_remote("answer", &answer).unwrap();

        let mut dtls_dest = None;
        for _ in 0..40 {
            let left = phone.drain().unwrap();
            dtls_dest = left.transmits.last().map(|packet| packet.destination).or(dtls_dest);
            for packet in left.transmits {
                edge.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            let right = edge.drain().unwrap();
            for packet in right.transmits {
                phone.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            phone.advance(Duration::from_millis(20)).unwrap();
            edge.advance(Duration::from_millis(20)).unwrap();
            if phone.connected && edge.connected && edge.channel.is_some() {
                break;
            }
        }
        assert!(phone.connected && edge.connected, "dtls did not come up");
        assert!(edge.channel.is_some(), "data channel did not open");

        phone.want_audio = true;
        let audio_offer = phone.create_offer().unwrap();
        assert_eq!(phone.ufrag(), ufrag, "renegotiation opened a new ice agent");
        assert!(audio_offer.contains("m=audio"), "{audio_offer}");
        edge.set_remote("offer", &audio_offer).unwrap();
        let audio_answer = edge.take_answer().unwrap();
        phone.set_remote("answer", &audio_answer).unwrap();
        pump(&mut phone, &mut edge, 10).unwrap();
        assert!(phone.audio_mid.is_some() && edge.audio_mid.is_some(), "audio mid missing");

        let payload = super::super::codec::silence(&phone.send_codec);
        phone.write_audio(&payload).unwrap();
        let mut saw_audio = false;
        let mut rtp_dest = None;
        for _ in 0..10 {
            let drain = phone.drain().unwrap();
            rtp_dest = drain.transmits.last().map(|packet| packet.destination).or(rtp_dest);
            for packet in drain.transmits {
                edge.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            let back = edge.drain().unwrap();
            if back.events.iter().any(|event| matches!(event, ScriptEvent::Audio { .. })) {
                saw_audio = true;
                break;
            }
            phone.advance(Duration::from_millis(20)).unwrap();
            edge.advance(Duration::from_millis(20)).unwrap();
        }
        assert!(saw_audio, "no rtp on the answerer");
        if let (Some(before), Some(after)) = (dtls_dest, rtp_dest) {
            assert_eq!(before, after, "audio left on a different socket than dtls");
        }

        let before = phone.tx_ssrc_label();
        let mid = phone.audio_mid;
        phone.rotate_ssrc().unwrap();
        assert_ne!(phone.tx_ssrc_label(), before, "ssrc did not change");
        assert_eq!(phone.audio_mid, mid);
        phone.write_audio(&payload).unwrap();
        let mut same_mid = false;
        for _ in 0..10 {
            let drain = phone.drain().unwrap();
            for packet in drain.transmits {
                edge.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            let back = edge.drain().unwrap();
            if audio_mids(&back.events).iter().any(|_| edge.audio_mid == mid || edge.audio_mid.is_some())
                && back.events.iter().any(|event| matches!(event, ScriptEvent::Audio { .. }))
            {
                same_mid = edge.audio_mid.is_some();
                break;
            }
            phone.advance(Duration::from_millis(20)).unwrap();
        }
        assert!(same_mid, "ssrc change was not delivered on the existing mid");
    }
}
