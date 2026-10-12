//! Host candidates come from the socket we bind. STUN and TURN only discover
//! more addresses for that same agent. str0m does not gather them itself.

use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const COOKIE: u32 = 0x2112_a442;
const BINDING: u16 = 0x0001;
const ALLOCATE: u16 = 0x0003;
const SEND: u16 = 0x0016;
const DATA: u16 = 0x0017;
const ERR_RESP: u16 = 0x0113;

#[derive(Clone, Debug)]
pub struct IceServer {
    pub kind: ServerKind,
    pub username: String,
    pub credential: String,
}

#[derive(Clone, Debug)]
pub enum ServerKind {
    Stun { host: String, port: u16 },
    Turn { host: String, port: u16 },
}

pub fn parse_servers(raw: &[IceInput]) -> Vec<IceServer> {
    raw.iter().filter_map(parse_one).collect()
}

#[derive(Clone, Debug)]
pub struct IceInput {
    pub urls: String,
    pub username: String,
    pub credential: String,
}

fn parse_one(input: &IceInput) -> Option<IceServer> {
    let url = input.urls.trim();
    let (kind, rest) = if let Some(rest) = url.strip_prefix("stun:") {
        ("stun", rest)
    } else if let Some(rest) = url.strip_prefix("turn:") {
        ("turn", rest)
    } else {
        return None;
    };
    let rest = rest.split('?').next().unwrap_or(rest);
    let (host, port) = rest.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    let kind = if kind == "stun" {
        ServerKind::Stun { host: host.to_string(), port }
    } else {
        ServerKind::Turn { host: host.to_string(), port }
    };
    Some(IceServer {
        kind,
        username: input.username.clone(),
        credential: input.credential.clone(),
    })
}

pub fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    stun(BINDING, txid, &[])
}

pub fn parse_xor_address(buf: &[u8]) -> Option<SocketAddr> {
    let value = attr(buf, 0x0020)?;
    xor_addr(value)
}

pub struct TurnChallenge {
    pub realm: String,
    pub nonce: String,
}

pub fn is_allocate_unauth(buf: &[u8]) -> bool {
    stun_type(buf) == Some(ERR_RESP) && attr(buf, 0x0009).is_some_and(|v| v.len() >= 4 && u16::from_be_bytes([v[2], v[3]]) == 401)
}

pub fn challenge(buf: &[u8]) -> Option<TurnChallenge> {
    let realm = attr(buf, 0x0014)?;
    let nonce = attr(buf, 0x0015)?;
    Some(TurnChallenge {
        realm: String::from_utf8_lossy(realm).trim_end_matches('\0').to_string(),
        nonce: String::from_utf8_lossy(nonce).trim_end_matches('\0').to_string(),
    })
}

pub fn allocate_request(txid: &[u8; 12]) -> Vec<u8> {
    // REQUESTED-TRANSPORT UDP (17).
    let transport = attr(0x0019, &[0x11, 0, 0, 0]);
    stun(ALLOCATE, txid, &transport)
}

pub fn allocate_authorized(txid: &[u8; 12], username: &str, credential: &str, challenge: &TurnChallenge) -> Vec<u8> {
    let mut attrs = attr(0x0019, &[0x11, 0, 0, 0]);
    attrs.extend(attr(0x0006, username.as_bytes()));
    attrs.extend(attr(0x0014, challenge.realm.as_bytes()));
    attrs.extend(attr(0x0015, challenge.nonce.as_bytes()));
    let mut msg = stun(ALLOCATE, txid, &attrs);
    let key = long_term_key(username, &challenge.realm, credential);
    sign(&mut msg, &key);
    msg
}

pub fn send_indication(txid: &[u8; 12], peer: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let xor = xor_attr(0x0012, peer)?;
    let mut attrs = xor;
    attrs.extend(attr(0x0013, payload));
    Some(stun(SEND, txid, &attrs))
}

pub fn parse_data_indication(buf: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    if stun_type(buf)? != DATA {
        return None;
    }
    let peer = xor_addr(attr(buf, 0x0012)?)?;
    let data = attr(buf, 0x0013)?.to_vec();
    Some((peer, data))
}

pub fn xor_relayed(buf: &[u8]) -> Option<SocketAddr> {
    if stun_type(buf)? != 0x0103 {
        return None;
    }
    xor_addr(attr(buf, 0x0016)?)
}

fn long_term_key(username: &str, realm: &str, credential: &str) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(format!("{username}:{realm}:{credential}").as_bytes());
    hasher.finalize().to_vec()
}

fn sign(msg: &mut Vec<u8>, key: &[u8]) {
    let len = (msg.len() + 24 - 20) as u16;
    msg[2..4].copy_from_slice(&len.to_be_bytes());
    let mut mac = HmacSha1::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let digest = mac.finalize().into_bytes();
    msg.extend(attr(0x0008, &digest));
}

fn stun(typ: u16, txid: &[u8; 12], attrs: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20 + attrs.len());
    msg.extend_from_slice(&typ.to_be_bytes());
    msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    msg.extend_from_slice(&COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg.extend_from_slice(attrs);
    msg
}

fn attr(typ: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn xor_attr(typ: u16, addr: SocketAddr) -> Option<Vec<u8>> {
    let SocketAddr::V4(addr) = addr else { return None };
    let port = addr.port() ^ (COOKIE >> 16) as u16;
    let ip = u32::from(*addr.ip()) ^ COOKIE;
    let mut value = vec![0, 0x01];
    value.extend_from_slice(&port.to_be_bytes());
    value.extend_from_slice(&ip.to_be_bytes());
    Some(attr(typ, &value))
}

fn stun_type(buf: &[u8]) -> Option<u16> {
    if buf.len() < 20 || u32::from_be_bytes(buf[4..8].try_into().ok()?) != COOKIE {
        return None;
    }
    Some(u16::from_be_bytes([buf[0], buf[1]]))
}

fn attr<'a>(buf: &'a [u8], want: u16) -> Option<&'a [u8]> {
    if buf.len() < 20 {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= buf.len() {
        let typ = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let start = offset + 4;
        let end = start + len;
        if end > buf.len() {
            return None;
        }
        if typ == want {
            return Some(&buf[start..end]);
        }
        offset = start + len + (4 - len % 4) % 4;
    }
    None
}

fn xor_addr(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 || value[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (COOKIE >> 16) as u16;
    let ip = u32::from_be_bytes(value[4..8].try_into().ok()?) ^ COOKIE;
    Some(SocketAddr::from((ip.to_be_bytes(), port)))
}
