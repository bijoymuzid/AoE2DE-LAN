// lanhub — native lobby hub for AoE2LAN. Speaks the two JSON-over-TCP protocols
// of PLAN.md §5.1 (control, 127.0.0.1:47100) and §5.2 (node gossip, 0.0.0.0:47101).
// Framing: newline-delimited JSON (one object per line), both protocols.
// No broadcast, no multicast: discovery is unicast gossip between seeded peers.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const VER: u32 = 1;
const TTL_HOPS: u64 = 3; // PLAN §5.2: covers any realistic group

fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        mix_bytes(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// No /dev/urandom on Windows and std has no RNG, so the old code silently returned
// all-zero ids there: both hubs got nodeGUID 000..0 and every node dropped the
// other's ADVERT as its own (s49f, 9/11). Mix what the process already knows.
// shortcut: not a CSPRNG - fine for ids that must differ, weak for relayAuthToken;
// take the getrandom crate if that token ever guards anything.
fn mix_bytes(b: &mut [u8]) {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let ctr = CTR.fetch_add(1, Ordering::Relaxed);
    let sp = &ctr as *const _ as usize; // ASLR
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    let pid = std::process::id();
    let n = b.len();
    let mut i = 0;
    while i < n {
        let h = fnv1a64(&format!("{host}|{pid}|{now}|{sp}|{ctr}|{i}"));
        for x in h.to_be_bytes() {
            if i < n {
                b[i] = x;
                i += 1;
            }
        }
    }
}

fn own_tailnet_ip() -> String {
    // shortcut: shells out to tailscale once per HOST; if absent we are on
    // loopback-only test setups anyway. Upgrade if HOST latency ever matters.
    if let Ok(out) = std::process::Command::new("tailscale").args(["ip", "-4"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(ip) = s.lines().map(str::trim).find(|l| l.starts_with("100.")) {
            return ip.to_string();
        }
    }
    "127.0.0.1".to_string()
}

struct Member {
    profile_id: u64,
    slot: i64,
}

struct Lobby {
    origin: String,
    seq: u64,
    lobby: Value,
    relay_ip: String,
    relay_ports: Value,
    relay_token: String,
    local: bool,
    members: Vec<Member>,
}

struct State {
    guid: String,
    name: String,
    app_checksum: String,
    data_checksum: String,
    control_port: u16,
    node_port: u16,
    relay_ip: String,
    lobbies: HashMap<String, Lobby>,
    nodes: HashMap<String, Value>,               // nodeGUID -> last ANNOUNCE
    seen: HashSet<String>,                       // gossip dedup keys
    node_conns: HashMap<String, Sender<String>>, // remote addr -> write chan
    peer_subs: Vec<(u64, String, Sender<String>)>, // (conn id, advertisementID, chan)
}

struct PeerInfo {
    name: String,
    ip4: String,
    online: bool,
    path: &'static str, // direct | derp | unknown
}

// L2: peer enumeration from `tailscale status --json` (PLAN §3.7). Path rule:
// CurAddr set => direct WireGuard path; else Relay set => DERP relay (+100-200 ms, §3.5);
// else unknown (offline / never contacted).
fn tailscale_peers() -> Option<Vec<PeerInfo>> {
    let out = std::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let st: Value = serde_json::from_slice(&out.stdout).ok()?;
    let mut peers = vec![];
    for p in st["Peer"].as_object()?.values() {
        let ip4 = p["TailscaleIPs"]
            .as_array()
            .and_then(|a| a.iter().find_map(|i| i.as_str().map(str::to_string).filter(|s| s.starts_with("100."))))
            .unwrap_or_default();
        let online = p["Online"].as_bool().unwrap_or(false);
        // Relay keeps the last-used DERP region even for offline peers — don't report it as live
        let path = if !online {
            "unknown"
        } else if !p["CurAddr"].as_str().unwrap_or("").is_empty() {
            "direct"
        } else if !p["Relay"].as_str().unwrap_or("").is_empty() {
            "derp"
        } else {
            "unknown"
        };
        peers.push(PeerInfo {
            name: p["HostName"].as_str().unwrap_or("?").to_string(),
            ip4,
            online,
            path,
        });
    }
    peers.sort_by(|a, b| b.online.cmp(&a.online).then(a.name.cmp(&b.name)));
    Some(peers)
}

fn cmd_peers(ini_peers: &[String]) {
    match tailscale_peers() {
        Some(peers) => {
            println!("{:<22} {:<16} {:<8} {}", "PEER", "TAILNET-IP", "ONLINE", "PATH");
            for p in peers {
                let warn = if p.online && p.path == "derp" { "  WARN derp adds 100-200 ms (PLAN §3.5)" } else { "" };
                println!("{:<22} {:<16} {:<8} {}{}", p.name, p.ip4, p.online, p.path, warn);
            }
        }
        None => {
            // ini fallback for machines without the tailscale CLI (PLAN §5.4)
            println!("tailscale CLI unavailable - manual seeds from ini:");
            for p in ini_peers {
                println!("{:<22} {}", p, "unknown (ini seed)");
            }
        }
    }
}

fn relay_ports() -> Value {
    // PLAN §5.3
    json!({"bs": 47110, "webSocket": 47111, "outOfBand": 47112, "lobby": 47114})
}

fn advert_msg(origin: &str, id: &str, l: &Lobby) -> Value {
    // relayAuthToken rides along as an extension field: §5.2 doesn't list it, but
    // BattleServer treats secrets as unchecked lookup keys (PLAN M0.1 detail), so a
    // joining node needs no out-of-band token exchange.
    json!({"type":"ADVERT","advertisementID":id,"originGUID":origin,"seq":l.seq,
           "lobby":l.lobby,"relayIP":l.relay_ip,"relayPorts":l.relay_ports,
           "relayAuthToken":l.relay_token,"ttlHops":TTL_HOPS})
}

fn flood(s: &mut State, msg: &Value, exclude: Option<&str>) {
    let line = msg.to_string();
    for (k, tx) in &s.node_conns {
        if Some(k.as_str()) == exclude {
            continue;
        }
        let _ = tx.send(line.clone());
    }
}

fn spawn_writer(stream: TcpStream) -> Sender<String> {
    let (tx, rx) = channel::<String>();
    thread::spawn(move || {
        let mut s = stream;
        for mut line in rx {
            line.push('\n');
            if s.write_all(line.as_bytes()).is_err() {
                break;
            }
        }
    });
    tx
}

fn register_node_conn(st: &Arc<Mutex<State>>, key: String, stream: TcpStream) -> Option<Sender<String>> {
    let tx = spawn_writer(stream);
    let mut s = st.lock().unwrap();
    if s.node_conns.contains_key(&key) {
        return None;
    }
    s.node_conns.insert(key, tx.clone());
    let announce = json!({"type":"ANNOUNCE","nodeGUID":s.guid,"nodeName":s.name,"ver":VER,
        "appChecksum":s.app_checksum,"dataChecksum":s.data_checksum,
        "ports":{"control":s.control_port,"node":s.node_port},"ttlHops":TTL_HOPS});
    let _ = tx.send(announce.to_string());
    // catch the new peer up on lobbies it missed while disconnected
    for (id, l) in &s.lobbies {
        if l.local {
            let _ = tx.send(advert_msg(&s.guid, id, l).to_string());
        }
    }
    Some(tx)
}

fn handle_node(st: &Arc<Mutex<State>>, src: &str, v: &Value, tx: &Sender<String>) {
    match v["type"].as_str().unwrap_or("") {
        "ANNOUNCE" => {
            let g = v["nodeGUID"].as_str().unwrap_or("").to_string();
            if g.is_empty() {
                return;
            }
            let mut s = st.lock().unwrap();
            let id = format!("ANNOUNCE:{g}");
            if s.seen.insert(id) {
                s.nodes.insert(g, v.clone());
                let ttl = v["ttlHops"].as_u64().unwrap_or(0);
                if ttl > 1 {
                    let mut m = v.clone();
                    m["ttlHops"] = json!(ttl - 1);
                    flood(&mut s, &m, Some(src));
                }
            } else {
                s.nodes.insert(g, v.clone()); // refresh: checksums can arrive after a local HELLO
            }
        }
        "ADVERT" => {
            let id = v["advertisementID"].as_str().unwrap_or("").to_string();
            let origin = v["originGUID"].as_str().unwrap_or("").to_string();
            if id.is_empty() {
                return;
            }
            let mut s = st.lock().unwrap();
            if origin == s.guid {
                return; // our own advert coming back around the mesh
            }
            let seq = v["seq"].as_u64().unwrap_or(1);
            if !s.seen.insert(format!("ADVERT:{id}:{seq}")) {
                return;
            }
            let newer = s.lobbies.get(&id).map(|l| seq > l.seq).unwrap_or(true);
            if newer {
                s.lobbies.insert(
                    id.clone(),
                    Lobby {
                        origin,
                        seq,
                        lobby: v["lobby"].clone(),
                        relay_ip: v["relayIP"].as_str().unwrap_or("").into(),
                        relay_ports: v["relayPorts"].clone(),
                        relay_token: v["relayAuthToken"].as_str().unwrap_or("").into(),
                        local: false,
                        members: vec![],
                    },
                );
            }
            let ttl = v["ttlHops"].as_u64().unwrap_or(0);
            if ttl > 1 {
                let mut m = v.clone();
                m["ttlHops"] = json!(ttl - 1);
                flood(&mut s, &m, Some(src));
            }
        }
        "WITHDRAW" => {
            let id = v["advertisementID"].as_str().unwrap_or("").to_string();
            if id.is_empty() {
                return;
            }
            let mut s = st.lock().unwrap();
            if !s.seen.insert(format!("WITHDRAW:{id}")) {
                return;
            }
            s.lobbies.remove(&id);
            flood(&mut s, &v.clone(), Some(src));
        }
        "PINGNODE" => {
            // path=direct|derp comes from `tailscale status --json` — that is job L2.
            let _ = tx.send(json!({"reply":"PINGNODE","ok":true,"path":"unknown"}).to_string());
        }
        _ => {}
    }
}

fn notify_peers(s: &State, adv_id: &str) {
    let Some(l) = s.lobbies.get(adv_id) else { return };
    let peers: Vec<Value> = l
        .members
        .iter()
        .map(|m| json!({"profileID": m.profile_id, "slot": m.slot}))
        .collect();
    let msg = json!({"type":"PEERS","advertisementID":adv_id,"peers":peers}).to_string();
    for (_, id, tx) in &s.peer_subs {
        if id == adv_id {
            let _ = tx.send(msg.clone());
        }
    }
}

struct ConnCtx {
    profile_id: Option<u64>,
}

fn handle_control(st: &Arc<Mutex<State>>, conn_id: u64, ctx: &mut ConnCtx, tx: &Sender<String>, v: &Value) {
    let ty = v["type"].as_str().unwrap_or("").to_string();
    let reply = |mut r: Value| {
        r["reply"] = json!(ty);
        let _ = tx.send(r.to_string());
    };
    match ty.as_str() {
        "HELLO" => {
            let nick = v["nick"].as_str().unwrap_or("anon");
            let pid = fnv1a64(&format!("aoe2lan:{nick}")); // PLAN R3
            ctx.profile_id = Some(pid);
            let mut s = st.lock().unwrap();
            if let Some(c) = v["appChecksum"].as_str() {
                s.app_checksum = c.into();
            }
            if let Some(c) = v["dataChecksum"].as_str() {
                s.data_checksum = c.into();
            }
            s.name = nick.into(); // one player per machine
            let ports = json!({"control": s.control_port, "node": s.node_port, "relay": relay_ports()});
            drop(s);
            reply(json!({"ok":true,"profileID":pid,"sessionToken":rand_hex(16),"ports":ports}));
        }
        "HOST" => {
            let lobby = v["lobby"].clone();
            if !lobby.is_object() {
                reply(json!({"ok":false,"error":"lobby object required"}));
                return;
            }
            let id = rand_hex(16);
            let token = rand_hex(16);
            let mut s = st.lock().unwrap();
            let l = Lobby {
                origin: s.guid.clone(),
                seq: 1,
                lobby,
                relay_ip: s.relay_ip.clone(),
                relay_ports: relay_ports(),
                relay_token: token.clone(),
                local: true,
                members: vec![],
            };
            let relay_ip = l.relay_ip.clone();
            let rports = l.relay_ports.clone();
            let m = advert_msg(&s.guid.clone(), &id, &l);
            s.lobbies.insert(id.clone(), l);
            flood(&mut s, &m, None);
            drop(s);
            reply(json!({"ok":true,"advertisementID":id,"relayAuthToken":token,
                         "relayIP":relay_ip,"relayPorts":rports}));
        }
        "UPDATE" => {
            let id = v["advertisementID"].as_str().unwrap_or("").to_string();
            let mut s = st.lock().unwrap();
            let g = s.guid.clone();
            let m = match s.lobbies.get_mut(&id) {
                Some(l) if l.local => {
                    if let Some(p) = v["patch"].as_object() {
                        for (k, val) in p {
                            l.lobby[k] = val.clone();
                        }
                    }
                    l.seq += 1;
                    advert_msg(&g, &id, l)
                }
                Some(_) => {
                    reply(json!({"ok":false,"error":"not our lobby"}));
                    return;
                }
                None => {
                    reply(json!({"ok":false,"error":"unknown advertisementID"}));
                    return;
                }
            };
            flood(&mut s, &m, None);
            drop(s);
            reply(json!({"ok":true}));
        }
        "FIND" => {
            let s = st.lock().unwrap();
            let mut ads = vec![];
            let mut hidden = vec![];
            for (id, l) in &s.lobbies {
                let node_dc = s
                    .nodes
                    .get(&l.origin)
                    .and_then(|n| n["dataChecksum"].as_str())
                    .unwrap_or("");
                // PLAN §5.2: mismatched dataChecksum ⇒ hidden with reason, never silent
                if !s.data_checksum.is_empty() && !node_dc.is_empty() && node_dc != s.data_checksum {
                    hidden.push(json!({"advertisementID":id,"reason":"dataChecksum mismatch"}));
                    continue;
                }
                ads.push(json!({"advertisementID":id,"originGUID":l.origin,"lobby":l.lobby,
                                "relayIP":l.relay_ip,"relayPorts":l.relay_ports}));
            }
            drop(s);
            reply(json!({"ok":true,"advertisements":ads,"hidden":hidden}));
        }
        "JOIN" => {
            let id = v["advertisementID"].as_str().unwrap_or("").to_string();
            let pid = ctx.profile_id.unwrap_or(0);
            let mut s = st.lock().unwrap();
            let Some(l) = s.lobbies.get_mut(&id) else {
                reply(json!({"ok":false,"error":"unknown advertisementID"}));
                return;
            };
            if !l.local {
                // shortcut: remote joins are answered from the cached ADVERT; slot allocation
                // on the origin node needs a join round-trip §5.2 does not define yet.
                // Upgrade when M2 wires real cross-machine joins.
                reply(json!({"ok":true,"slot":null,"peers":[],"relayIP":l.relay_ip,
                             "relayAuthToken":l.relay_token,"relayPorts":l.relay_ports}));
                return;
            }
            let max = l.lobby["maxPlayers"].as_i64().unwrap_or(8);
            if !l.members.iter().any(|m| m.profile_id == pid) {
                let slot = (0..max).find(|i| !l.members.iter().any(|m| m.slot == *i));
                let Some(slot) = slot else {
                    reply(json!({"ok":false,"error":"lobby full"}));
                    return;
                };
                l.members.push(Member { profile_id: pid, slot });
            }
            let m = l.members.iter().find(|m| m.profile_id == pid).unwrap();
            let (slot, rip, rtok, rports) = (m.slot, l.relay_ip.clone(), l.relay_token.clone(), l.relay_ports.clone());
            let peers: Vec<Value> = l
                .members
                .iter()
                .map(|m| json!({"profileID":m.profile_id,"slot":m.slot}))
                .collect();
            notify_peers(&s, &id);
            drop(s);
            reply(json!({"ok":true,"slot":slot,"peers":peers,"relayIP":rip,
                         "relayAuthToken":rtok,"relayPorts":rports}));
        }
        "LEAVE" => {
            let id = v["advertisementID"].as_str().unwrap_or("").to_string();
            let pid = ctx.profile_id.unwrap_or(0);
            let mut s = st.lock().unwrap();
            let mut withdrawn = false;
            if let Some(l) = s.lobbies.get_mut(&id) {
                if l.local {
                    l.members.retain(|m| m.profile_id != pid);
                    withdrawn = l.members.is_empty();
                }
            }
            if withdrawn {
                s.lobbies.remove(&id);
                let m = json!({"type":"WITHDRAW","advertisementID":id,"originGUID":s.guid});
                flood(&mut s, &m, None);
            } else {
                notify_peers(&s, &id);
            }
            drop(s);
            reply(json!({"ok":true}));
        }
        "PEERS" => {
            let id = v["advertisementID"].as_str().unwrap_or("").to_string();
            let mut s = st.lock().unwrap();
            let peers: Vec<Value> = s
                .lobbies
                .get(&id)
                .map(|l| l.members.iter().map(|m| json!({"profileID":m.profile_id,"slot":m.slot})).collect())
                .unwrap_or_default();
            s.peer_subs.push((conn_id, id, tx.clone())); // push subscription
            drop(s);
            reply(json!({"ok":true,"peers":peers}));
        }
        "PING" => {
            let s = st.lock().unwrap();
            let name = s.name.clone();
            drop(s);
            reply(json!({"ok":true,"rttMs":0,"nodeName":name,"path":"loopback"}));
        }
        _ => reply(json!({"ok":false,"error":"unknown verb"})),
    }
}

static CONN_COUNTER: AtomicU64 = AtomicU64::new(1);

fn control_conn(st: Arc<Mutex<State>>, stream: TcpStream) {
    let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tx = spawn_writer(stream.try_clone().unwrap());
    let mut ctx = ConnCtx { profile_id: None };
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(t) {
            Ok(v) => handle_control(&st, conn_id, &mut ctx, &tx, &v),
            Err(_) => {
                let _ = tx.send(json!({"ok":false,"error":"bad json"}).to_string());
            }
        }
    }
    st.lock().unwrap().peer_subs.retain(|(c, _, _)| *c != conn_id);
}

fn node_reader(st: Arc<Mutex<State>>, stream: TcpStream, key: String) {
    let Some(tx) = register_node_conn(&st, key.clone(), stream.try_clone().unwrap()) else {
        return;
    };
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            handle_node(&st, &key, &v, &tx);
        }
    }
    st.lock().unwrap().node_conns.remove(&key);
}

fn seed_loop(st: Arc<Mutex<State>>, addr: String) {
    loop {
        if !st.lock().unwrap().node_conns.contains_key(&addr) {
            if let Ok(stream) = TcpStream::connect(&addr) {
                let st2 = st.clone();
                let key = addr.clone();
                thread::spawn(move || node_reader(st2, stream, key));
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn read_ini(
    path: &str,
    base_port: &mut Option<u16>,
    peers: &mut Vec<String>,
    name: &mut Option<String>,
    autodiscover: &mut bool,
) {
    let Ok(txt) = std::fs::read_to_string(path) else { return };
    let mut sec = String::new();
    for raw in txt.lines() {
        let l = raw.split(';').next().unwrap_or("").trim();
        if l.starts_with('[') {
            sec = l.trim_matches(['[', ']']).trim().to_string();
            continue;
        }
        let Some((k, val)) = l.split_once('=') else { continue };
        match (sec.as_str(), k.trim()) {
            ("hub", "basePort") => *base_port = val.trim().parse().ok(),
            ("tailscale", "autodiscover") => *autodiscover = val.trim() != "false",
            ("tailscale", "peers") => {
                for p in val.split(',') {
                    let p = p.trim();
                    if !p.is_empty() {
                        peers.push(p.into());
                    }
                }
            }
            ("nickname", "name") => *name = Some(val.trim().into()),
            _ => {}
        }
    }
}

fn main() {
    let mut control_port: Option<u16> = None;
    let mut node_port: Option<u16> = None;
    let mut nick: Option<String> = None;
    let mut peers: Vec<String> = vec![];
    let mut ini_path = "aoe2lan.ini".to_string();

    if std::env::args().nth(1).as_deref() == Some("peers") {
        // subcommand: `lanhub peers` (L2 acceptance)
        let mut ini_base = None;
        let mut ini_peers = vec![];
        let mut ad = true;
        read_ini(&ini_path, &mut ini_base, &mut ini_peers, &mut None, &mut ad);
        cmd_peers(&ini_peers);
        return;
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut ini_base: Option<u16> = None;
    let mut ini_peers: Vec<String> = vec![];
    let mut ini_name: Option<String> = None;
    let mut autodiscover = true;
    while i < args.len() {
        match args[i].as_str() {
            "--no-autodiscover" => autodiscover = false,
            "--control-port" => control_port = args.get(i + 1).and_then(|s| s.parse().ok()),
            "--node-port" => node_port = args.get(i + 1).and_then(|s| s.parse().ok()),
            "--nick" => nick = args.get(i + 1).cloned(),
            "--peer" => {
                if let Some(p) = args.get(i + 1) {
                    peers.push(p.clone())
                }
            }
            "--ini" => ini_path = args.get(i + 1).cloned().unwrap_or(ini_path),
            a => eprintln!("lanhub: ignoring unknown arg {a}"),
        }
        i += if matches!(args[i].as_str(), "--control-port" | "--node-port" | "--nick" | "--peer" | "--ini") { 2 } else { 1 };
    }
    read_ini(&ini_path, &mut ini_base, &mut ini_peers, &mut ini_name, &mut autodiscover);

    let control_port = control_port.or(ini_base).unwrap_or(47100);
    let node_port = node_port.or(ini_base.map(|b| b + 1)).unwrap_or(47101);
    let nick = nick.or(ini_name).unwrap_or_else(|| std::env::var("USER").unwrap_or("Player".into()));
    peers.extend(ini_peers);
    if autodiscover {
        // PLAN §5.4: online tailnet peers become gossip seeds automatically
        if let Some(ts) = tailscale_peers() {
            for p in ts {
                if p.online && !p.ip4.is_empty() {
                    let addr = format!("{}:47101", p.ip4);
                    if !peers.contains(&addr) {
                        peers.push(addr);
                    }
                }
            }
        }
    }
    for p in &mut peers {
        if !p.contains(':') {
            p.push_str(":47101");
        }
    }

    let st = Arc::new(Mutex::new(State {
        guid: rand_hex(16),
        name: nick.clone(),
        app_checksum: String::new(),
        data_checksum: String::new(),
        control_port,
        node_port,
        relay_ip: own_tailnet_ip(),
        lobbies: HashMap::new(),
        nodes: HashMap::new(),
        seen: HashSet::new(),
        node_conns: HashMap::new(),
        peer_subs: vec![],
    }));

    let ctl = TcpListener::bind(("127.0.0.1", control_port)).expect("control bind");
    let node = TcpListener::bind(("0.0.0.0", node_port)).expect("node bind");
    {
        let s = st.lock().unwrap();
        println!(
            "lanhub {VER}: node={} name={nick} control=127.0.0.1:{control_port} node=0.0.0.0:{node_port} relayIP={}",
            s.guid, s.relay_ip
        );
    }

    {
        let st = st.clone();
        thread::spawn(move || {
            for c in ctl.incoming() {
                if let Ok(stream) = c {
                    let st = st.clone();
                    thread::spawn(move || control_conn(st, stream));
                }
            }
        });
    }
    {
        let st = st.clone();
        thread::spawn(move || {
            for c in node.incoming() {
                if let Ok(stream) = c {
                    let key = stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| rand_hex(4));
                    let st = st.clone();
                    thread::spawn(move || node_reader(st, stream, key));
                }
            }
        });
    }
    for p in peers {
        println!("lanhub: seeding peer {p}");
        let st = st.clone();
        thread::spawn(move || seed_loop(st, p));
    }
    thread::park();
}

#[cfg(test)]
mod tests {
    use super::*;

    // guards s49f: on Windows there is no /dev/urandom, and the all-zero ids that
    // resulted made every hub drop the other's ADVERT as its own.
    #[test]
    fn mix_bytes_is_nonzero_and_distinct() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        mix_bytes(&mut a);
        mix_bytes(&mut b);
        assert!(a.iter().any(|x| *x != 0), "mix_bytes returned an all-zero id");
        assert_ne!(a, b, "two mix_bytes calls in one process collided");
        assert_eq!(rand_hex(16).len(), 32);
        assert_eq!(rand_hex(4).len(), 8);
    }
}
