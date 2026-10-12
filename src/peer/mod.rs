//! WebRTC peers, off the SIP thread.
//!
//! The script talks to [`Handle`]. A dedicated thread owns every [`session::Peer`]
//! and the UDP sockets those peers transmit on. Nothing here knows which product
//! placed the call.

mod bridge;
mod codec;
mod ice;
mod session;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use ice::{IceInput, IceServer, ServerKind};
use session::{Packet, Peer, ScriptEvent};

pub use ice::IceInput as IceServerIn;

#[derive(Debug)]
pub struct ScriptMsg {
    pub session_id: String,
    pub leg: String,
    pub event: String,
    pub data: String,
    pub state: String,
    pub dtls: String,
    pub digit: String,
}

pub struct SdpOut {
    pub sdp: String,
    pub candidates: Vec<String>,
}

pub struct WaitOut {
    pub ok: bool,
    pub state: String,
    pub ice: String,
    pub dtls: String,
}

enum Cmd {
    Create {
        id: String,
        session_id: String,
        leg: String,
        want_audio: bool,
        ice: Vec<IceInput>,
        reply: oneshot::Sender<Result<u64, String>>,
    },
    SetRemote {
        id: String,
        kind: String,
        sdp: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    AddIce {
        id: String,
        candidates: Vec<String>,
        reply: oneshot::Sender<Result<usize, String>>,
    },
    CreateOffer {
        id: String,
        reply: oneshot::Sender<Result<SdpOut, String>>,
    },
    CreateAnswer {
        id: String,
        reply: oneshot::Sender<Result<SdpOut, String>>,
    },
    LocalIce {
        id: String,
        reply: oneshot::Sender<Vec<String>>,
    },
    WaitConnected {
        id: String,
        timeout: Duration,
        reply: oneshot::Sender<WaitOut>,
    },
    Send {
        id: String,
        text: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Rotate {
        id: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Dtmf {
        id: String,
        digit: char,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Bridge {
        a: String,
        b: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Unbridge {
        session_id: String,
        reply: oneshot::Sender<()>,
    },
    Close {
        id: String,
        reply: oneshot::Sender<()>,
    },
    Abandon {
        session_id: String,
        reply: oneshot::Sender<()>,
    },
}

struct Live {
    peer: Peer,
    sock: UdpSocket,
    session_id: String,
    leg: String,
    epoch: u64,
    gather: Vec<IceServer>,
    gather_at: usize,
    turn_server: Option<SocketAddr>,
    turn_auth: Option<(String, String)>,
    txid: [u8; 12],
}

struct Waiter {
    id: String,
    reply: oneshot::Sender<WaitOut>,
    deadline: std::time::Instant,
}

pub struct Handle {
    tx: mpsc::UnboundedSender<Cmd>,
    events: Arc<Mutex<std::sync::mpsc::Receiver<ScriptMsg>>>,
}

impl Handle {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("siphon-peer".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("peer runtime");
                runtime.block_on(run(rx, event_tx));
            })
            .expect("peer thread");
        Self { tx, events: Arc::new(Mutex::new(event_rx)) }
    }

    pub fn poll_event(&self, timeout: Duration) -> Option<ScriptMsg> {
        let rx = self.events.lock().ok()?;
        rx.recv_timeout(timeout).ok()
    }

    fn send(&self, cmd: Cmd) -> Result<(), String> {
        self.tx.send(cmd).map_err(|_| "peer thread is gone".into())
    }

    pub async fn create(&self, session_id: &str, leg: &str, want_audio: bool, ice: Vec<IceInput>) -> Result<u64, String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Create {
            id: key(session_id, leg),
            session_id: session_id.to_string(),
            leg: leg.to_string(),
            want_audio,
            ice,
            reply,
        })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn set_remote(&self, session_id: &str, leg: &str, kind: &str, sdp: &str) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::SetRemote {
            id: key(session_id, leg),
            kind: kind.to_string(),
            sdp: sdp.to_string(),
            reply,
        })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn add_ice(&self, session_id: &str, leg: &str, candidates: Vec<String>) -> Result<usize, String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::AddIce { id: key(session_id, leg), candidates, reply })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn create_offer(&self, session_id: &str, leg: &str) -> Result<SdpOut, String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::CreateOffer { id: key(session_id, leg), reply })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn create_answer(&self, session_id: &str, leg: &str) -> Result<SdpOut, String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::CreateAnswer { id: key(session_id, leg), reply })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn local_ice(&self, session_id: &str, leg: &str) -> Vec<String> {
        let (reply, rx) = oneshot::channel();
        if self.send(Cmd::LocalIce { id: key(session_id, leg), reply }).is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn wait_connected(&self, session_id: &str, leg: &str, timeout: Duration) -> WaitOut {
        let (reply, rx) = oneshot::channel();
        let missing = WaitOut { ok: false, state: "missing".into(), ice: "missing".into(), dtls: "missing".into() };
        if self.send(Cmd::WaitConnected { id: key(session_id, leg), timeout, reply }).is_err() {
            return missing;
        }
        rx.await.unwrap_or(missing)
    }

    pub async fn send_text(&self, session_id: &str, leg: &str, text: &str) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Send { id: key(session_id, leg), text: text.to_string(), reply })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn rotate(&self, session_id: &str, leg: &str) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Rotate { id: key(session_id, leg), reply })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn dtmf(&self, session_id: &str, leg: &str, digit: char) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Dtmf { id: key(session_id, leg), digit, reply })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn bridge(&self, session_id: &str, a: &str, b: &str) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Bridge {
            a: key(session_id, a),
            b: key(session_id, b),
            reply,
        })?;
        rx.await.map_err(|_| "peer dropped the reply".to_string())?
    }

    pub async fn unbridge(&self, session_id: &str) {
        let (reply, rx) = oneshot::channel();
        if self.send(Cmd::Unbridge { session_id: session_id.to_string(), reply }).is_err() {
            return;
        }
        let _ = rx.await;
    }

    pub async fn close(&self, session_id: &str, leg: &str) {
        let (reply, rx) = oneshot::channel();
        if self.send(Cmd::Close { id: key(session_id, leg), reply }).is_err() {
            return;
        }
        let _ = rx.await;
    }

    pub async fn abandon(&self, session_id: &str) {
        let (reply, rx) = oneshot::channel();
        if self.send(Cmd::Abandon { session_id: session_id.to_string(), reply }).is_err() {
            return;
        }
        let _ = rx.await;
    }
}

fn default_ipv4() -> std::net::Ipv4Addr {
    let fallback = std::net::Ipv4Addr::LOCALHOST;
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => sock,
        Err(_) => return fallback,
    };
    if sock.connect("1.1.1.1:443").is_err() {
        return fallback;
    }
    match sock.local_addr() {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) if !ip.is_unspecified() => ip,
            _ => fallback,
        },
        Err(_) => fallback,
    }
}

fn key(session_id: &str, leg: &str) -> String {
    format!("{session_id}\n{leg}")
}

async fn run(mut rx: mpsc::UnboundedReceiver<Cmd>, events: std::sync::mpsc::Sender<ScriptMsg>) {
    let mut peers: HashMap<String, Live> = HashMap::new();
    let mut bridges: Vec<bridge::Bridge> = Vec::new();
    let mut epochs: HashMap<String, u64> = HashMap::new();
    let mut waiters: Vec<Waiter> = Vec::new();

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                handle(cmd, &mut peers, &mut bridges, &mut epochs, &mut waiters, &events).await;
            }
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                drive(&mut peers, &mut bridges, &events).await;
                let now = std::time::Instant::now();
                let mut pending = Vec::new();
                for waiter in waiters.drain(..) {
                    let done = peers.get(&waiter.id).is_some_and(|live| live.peer.connected);
                    if done || now >= waiter.deadline {
                        if let Some(live) = peers.get(&waiter.id) {
                            let _ = waiter.reply.send(WaitOut {
                                ok: live.peer.connected,
                                state: if live.peer.connected { "connected" } else { "connecting" }.into(),
                                ice: live.peer.ice.clone(),
                                dtls: live.peer.dtls.clone(),
                            });
                        }
                    } else {
                        pending.push(waiter);
                    }
                }
                *waiters = pending;
            }
        }
    }
}

async fn handle(
    cmd: Cmd,
    peers: &mut HashMap<String, Live>,
    bridges: &mut Vec<bridge::Bridge>,
    epochs: &mut HashMap<String, u64>,
    waiters: &mut Vec<Waiter>,
    events: &std::sync::mpsc::Sender<ScriptMsg>,
) {
    match cmd {
        Cmd::Create { id, session_id, leg, want_audio, ice, reply } => {
            if let Some(mut old) = peers.remove(&id) {
                old.peer.close();
                let _ = flush_one(&mut old, events).await;
            }
            let epoch = epochs.entry(id.clone()).or_insert(0);
            *epoch += 1;
            let epoch = *epoch;
            let result = async {
                let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|err| err.to_string())?;
                let bound = sock.local_addr().map_err(|err| err.to_string())?;
                // 0.0.0.0 is not a legal host candidate. The port is the one we
                // bound; the address is the default route, so STUN/TURN and the
                // phone see a real interface.
                let host = SocketAddr::new(default_ipv4().into(), bound.port());
                let peer = Peer::new(host, want_audio)?;
                peers.insert(id, Live {
                    peer,
                    sock,
                    session_id,
                    leg,
                    epoch,
                    gather: ice::parse_servers(&ice),
                    gather_at: 0,
                    turn_server: None,
                    turn_auth: None,
                    txid: rand_txid(),
                });
                Ok(epoch)
            }.await;
            let _ = reply.send(result);
        }
        Cmd::SetRemote { id, kind, sdp, reply } => {
            let result = match peers.get_mut(&id) {
                Some(live) => live.peer.set_remote(&kind, &sdp),
                None => Err("no peer".to_string()),
            };
            let frames = if let Some(live) = peers.get_mut(&id) {
                flush_one(live, events).await.unwrap_or_default()
            } else {
                Vec::new()
            };
            forward_audio(&id, frames, peers, bridges, events).await;
            let _ = reply.send(result);
        }
        Cmd::AddIce { id, candidates, reply } => {
            let result = match peers.get_mut(&id) {
                Some(live) => {
                    let mut applied = 0;
                    let mut err = None;
                    for line in candidates {
                        match live.peer.add_remote_candidate(&line) {
                            Ok(()) => applied += 1,
                            Err(error) => err = Some(error),
                        }
                    }
                    match err {
                        Some(error) if applied == 0 => Err(error),
                        _ => Ok(applied),
                    }
                }
                None => Err("no peer".into()),
            };
            let _ = reply.send(result);
        }
        Cmd::CreateOffer { id, reply } => {
            let result = peers.get_mut(&id).ok_or("no peer".into()).and_then(|live| {
                let sdp = live.peer.create_offer()?;
                Ok(SdpOut { sdp, candidates: live.peer.candidates.clone() })
            });
            let frames = if let Some(live) = peers.get_mut(&id) {
                flush_one(live, events).await.unwrap_or_default()
            } else {
                Vec::new()
            };
            forward_audio(&id, frames, peers, bridges, events).await;
            let _ = reply.send(result);
        }
        Cmd::CreateAnswer { id, reply } => {
            let result = peers.get_mut(&id).ok_or("no peer".into()).and_then(|live| {
                let sdp = live.peer.take_answer().ok_or("set_remote did not produce an answer")?;
                Ok(SdpOut { sdp, candidates: live.peer.candidates.clone() })
            });
            let _ = reply.send(result);
        }
        Cmd::LocalIce { id, reply } => {
            let lines = peers.get(&id).map(|live| live.peer.candidates.clone()).unwrap_or_default();
            let _ = reply.send(lines);
        }
        Cmd::WaitConnected { id, timeout, reply } => {
            if peers.get(&id).is_some_and(|live| live.peer.connected) {
                let live = peers.get(&id).unwrap();
                let _ = reply.send(WaitOut { ok: true, state: "connected".into(), ice: live.peer.ice.clone(), dtls: live.peer.dtls.clone() });
            } else {
                waiters.push(Waiter { id, reply, deadline: std::time::Instant::now() + timeout });
            }
        }
        Cmd::Send { id, text, reply } => {
            let result = peers.get_mut(&id).ok_or("no peer".into()).and_then(|live| live.peer.send_text(&text));
            let frames = if let Some(live) = peers.get_mut(&id) {
                flush_one(live, events).await.unwrap_or_default()
            } else {
                Vec::new()
            };
            forward_audio(&id, frames, peers, bridges, events).await;
            let _ = reply.send(result);
        }
        Cmd::Rotate { id, reply } => {
            let result = peers.get_mut(&id).ok_or("no peer".into()).and_then(|live| live.peer.rotate_ssrc());
            let _ = reply.send(result);
        }
        Cmd::Dtmf { id, digit, reply } => {
            let result = peers.get_mut(&id).ok_or("no peer".into()).and_then(|live| live.peer.inject_dtmf(digit));
            let frames = if let Some(live) = peers.get_mut(&id) {
                flush_one(live, events).await.unwrap_or_default()
            } else {
                Vec::new()
            };
            forward_audio(&id, frames, peers, bridges, events).await;
            let _ = reply.send(result);
        }
        Cmd::Bridge { a, b, reply } => {
            bridges.retain(|bridge| bridge.a != a && bridge.b != a && bridge.a != b && bridge.b != b);
            bridges.push(bridge::Bridge { a, b, a_to_b: 0, b_to_a: 0 });
            let _ = reply.send(Ok(()));
        }
        Cmd::Unbridge { session_id, reply } => {
            let prefix = format!("{session_id}\n");
            bridges.retain(|bridge| !bridge.a.starts_with(&prefix) && !bridge.b.starts_with(&prefix));
            let _ = reply.send(());
        }
        Cmd::Close { id, reply } => {
            if let Some(mut live) = peers.remove(&id) {
                live.peer.close();
            }
            bridges.retain(|bridge| bridge.a != id && bridge.b != id);
            let _ = reply.send(());
        }
        Cmd::Abandon { session_id, reply } => {
            let prefix = format!("{session_id}\n");
            let ids: Vec<String> = peers.keys().filter(|id| id.starts_with(&prefix)).cloned().collect();
            for id in ids {
                if let Some(mut live) = peers.remove(&id) {
                    live.peer.close();
                }
            }
            bridges.retain(|bridge| !bridge.a.starts_with(&prefix) && !bridge.b.starts_with(&prefix));
            let _ = reply.send(());
        }
    }
}

async fn drive(
    peers: &mut HashMap<String, Live>,
    bridges: &mut Vec<bridge::Bridge>,
    events: &std::sync::mpsc::Sender<ScriptMsg>,
) {
    let ids: Vec<String> = peers.keys().cloned().collect();
    for id in ids {
        let frames = {
        let Some(live) = peers.get_mut(&id) else { continue };
        let mut buf = [0u8; 2000];
        if let Ok((n, source)) = live.sock.try_recv_from(&mut buf) {
            let packet = &buf[..n];
            if live.turn_server == Some(source) {
                if let Some((peer, data)) = ice::parse_data_indication(packet) {
                    if let Some(relay) = live.peer.relay() {
                        if let Err(err) = live.peer.receive(peer, relay, &data) {
                            warn!(%err, "peer turn input");
                        }
                    }
                } else if let Some(relay) = ice::xor_relayed(packet) {
                    remember_mapped(live, relay, true);
                } else if let Some(mapped) = ice::parse_xor_address(packet) {
                    remember_mapped(live, mapped, false);
                } else if ice::is_allocate_unauth(packet) {
                    if let (Some(server), Some((user, cred))) = (live.turn_server, live.turn_auth.clone()) {
                        if let Some(challenge) = ice::challenge(packet) {
                            let msg = ice::allocate_authorized(&live.txid, &user, &cred, &challenge);
                            let _ = live.sock.send_to(&msg, server).await;
                        }
                    }
                }
            } else if let Err(err) = live.peer.receive(source, live.peer.host, packet) {
                warn!(%err, "peer input");
            }
        }
        kick_gather(live).await;
        if let Err(err) = live.peer.advance(Duration::from_millis(5)) {
            warn!(%err, "peer timeout");
        }
        match flush_one(live, events).await {
            Ok(frames) => Some(frames),
            Err(err) => {
                warn!(%err, "peer drain");
                None
            }
        }
        };
        if let Some(frames) = frames {
            forward_audio(&id, frames, peers, bridges, events).await;
        }
    }
}

async fn forward_audio(
    from: &str,
    frames: Vec<(String, Vec<u8>)>,
    peers: &mut HashMap<String, Live>,
    bridges: &mut [bridge::Bridge],
    events: &std::sync::mpsc::Sender<ScriptMsg>,
) {
    let Some(other_id) = bridges.iter().find_map(|link| link.other(from).map(str::to_string)) else {
        return;
    };
    let out_codec = peers.get(&other_id).map(|live| live.peer.send_codec.clone()).unwrap_or_default();
    if out_codec.is_empty() {
        return;
    }
    for (codec, payload) in frames {
        if let Some(link) = bridges.iter_mut().find(|link| link.other(from).is_some()) {
            link.count(from);
        }
        let encoded = bridge::forward(&codec, &payload, &out_codec);
        if encoded.is_empty() {
            continue;
        }
        let Some(other) = peers.get_mut(&other_id) else { continue };
        if let Err(err) = other.peer.write_audio(&encoded) {
            warn!(%err, "bridge write");
            continue;
        }
        if let Ok(more) = flush_one(other, events).await {
            // A write does not come back as MediaData on the same peer, so
            // this drain only sends the RTP. Do not forward `more` again.
            let _ = more;
        }
    }
}

fn remember_mapped(live: &mut Live, mapped: SocketAddr, relayed: bool) {
    let candidate = if relayed {
        str0m::Candidate::relayed(mapped, live.peer.host, "udp")
    } else {
        str0m::Candidate::server_reflexive(mapped, live.peer.host, "udp")
    };
    if let Ok(candidate) = candidate {
        live.peer.add_host_like(candidate);
    }
}

async fn kick_gather(live: &mut Live) {
    if live.gather_at >= live.gather.len() || live.turn_server.is_some() && live.gather_at + 1 >= live.gather.len() {
        return;
    }
    let server = &live.gather[live.gather_at];
    let (host, port) = match &server.kind {
        ServerKind::Stun { host, port } | ServerKind::Turn { host, port } => (host.clone(), *port),
    };
    let Ok(mut addrs) = tokio::net::lookup_host((host.as_str(), port)).await else { return };
    let Some(addr) = addrs.find(|addr| addr.is_ipv4()) else { return };
    let msg = match server.kind {
        ServerKind::Stun { .. } => ice::binding_request(&live.txid),
        ServerKind::Turn { .. } => {
            live.turn_server = Some(addr);
            live.turn_auth = Some((server.username.clone(), server.credential.clone()));
            ice::allocate_request(&live.txid)
        }
    };
    if live.sock.send_to(&msg, addr).await.is_ok() {
        live.gather_at += 1;
    }
}

async fn flush_one(
    live: &mut Live,
    events: &std::sync::mpsc::Sender<ScriptMsg>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let drain = live.peer.drain()?;
    for packet in drain.transmits {
        send_packet(live, &packet).await;
    }
    let mut audio = Vec::new();
    for event in drain.events {
        match event {
            ScriptEvent::Audio { codec, payload } => audio.push((codec, payload)),
            ScriptEvent::Ice(state) => {
                let _ = events.send(ScriptMsg {
                    session_id: live.session_id.clone(),
                    leg: live.leg.clone(),
                    event: "iceConnection".into(),
                    data: String::new(),
                    state,
                    dtls: live.peer.dtls.clone(),
                    digit: String::new(),
                });
            }
            other => emit(events, &live.session_id, &live.leg, other),
        }
    }
    Ok(audio)
}

async fn send_packet(live: &mut Live, packet: &Packet) {
    if live.peer.relay() == Some(packet.source) {
        if let Some(server) = live.turn_server {
            if let Some(msg) = ice::send_indication(&rand_txid(), packet.destination, &packet.contents) {
                let _ = live.sock.send_to(&msg, server).await;
            }
            return;
        }
    }
    let _ = live.sock.send_to(&packet.contents, packet.destination).await;
}

fn emit(events: &std::sync::mpsc::Sender<ScriptMsg>, session_id: &str, leg: &str, event: ScriptEvent) {
    let (name, data, state, dtls, digit) = match event {
        ScriptEvent::ChannelOpen => ("dc.open", String::new(), String::new(), String::new(), String::new()),
        ScriptEvent::ChannelClose => ("dc.close", String::new(), String::new(), String::new(), String::new()),
        ScriptEvent::ChannelData(text) => ("dc.message", text, String::new(), String::new(), String::new()),
        ScriptEvent::Connection(state) => ("connection", String::new(), state, String::new(), String::new()),
        ScriptEvent::Ice(state) => ("iceConnection", String::new(), state, String::new(), String::new()),
        ScriptEvent::Dtls(state) => ("dtls", String::new(), String::new(), state, String::new()),
        ScriptEvent::Dtmf(digit) => ("dtmf", String::new(), String::new(), String::new(), digit.to_string()),
        ScriptEvent::Audio { .. } => return,
    };
    let _ = events.send(ScriptMsg {
        session_id: session_id.to_string(),
        leg: leg.to_string(),
        event: name.into(),
        data,
        state,
        dtls,
        digit,
    });
}

fn rand_txid() -> [u8; 12] {
    let mut txid = [0u8; 12];
    let ticks = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1);
    txid.copy_from_slice(&ticks.to_le_bytes()[..12]);
    txid
}
