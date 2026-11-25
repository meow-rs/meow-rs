use std::env;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::exit;
use std::time::Duration;

fn main() {
    if let Err(e) = run() {
        eprintln!("udp-e2e-helper: {e}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        "echo" if args.len() == 4 => echo(parse_ip(&args[2])?, parse_port(&args[3])?),
        "client" if args.len() >= 7 => client(
            parse_ip(&args[2])?,
            parse_port(&args[3])?,
            parse_ip(&args[4])?,
            parse_port(&args[5])?,
            &args[6..],
        ),
        "client-no-reply" if args.len() == 7 => client_no_reply(
            parse_ip(&args[2])?,
            parse_port(&args[3])?,
            parse_ip(&args[4])?,
            parse_port(&args[5])?,
            &args[6],
        ),
        "dns-fixture" if args.len() == 4 => dns_fixture(parse_ip(&args[2])?, parse_port(&args[3])?),
        "dns-query" if args.len() == 6 => dns_query(
            parse_ip(&args[2])?,
            parse_port(&args[3])?,
            &args[4],
            parse_qtype(&args[5])?,
        ),
        _ => Err(format!(
            "usage: {} echo <bind-ip> <port> | \
             client <bind-ip> <bind-port> <target-ip> <target-port> <payload>... | \
             client-no-reply <bind-ip> <bind-port> <target-ip> <target-port> <payload> | \
             dns-fixture <bind-ip> <port> | \
             dns-query <server-ip> <port> <name> <A|AAAA>",
            args.first().map(String::as_str).unwrap_or("udp-e2e-helper")
        )),
    }
}

fn parse_ip(s: &str) -> Result<IpAddr, String> {
    s.parse::<IpAddr>()
        .map_err(|e| format!("bad IP '{s}': {e}"))
}

fn parse_port(s: &str) -> Result<u16, String> {
    s.parse::<u16>().map_err(|e| format!("bad port '{s}': {e}"))
}

fn parse_qtype(s: &str) -> Result<u16, String> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(1),
        "AAAA" => Ok(28),
        other => Err(format!("unsupported qtype '{other}'")),
    }
}

fn echo(ip: IpAddr, port: u16) -> Result<(), String> {
    let socket = UdpSocket::bind(SocketAddr::new(ip, port))
        .map_err(|e| format!("echo bind {ip}:{port}: {e}"))?;
    println!("ECHO_READY {ip}:{port}");
    let _ = std::io::stdout().flush();
    let mut buf = [0u8; 65535];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("echo recv: {e}"))?;
        socket
            .send_to(&buf[..n], peer)
            .map_err(|e| format!("echo send to {peer}: {e}"))?;
    }
}

fn client(
    bind_ip: IpAddr,
    bind_port: u16,
    target_ip: IpAddr,
    target_port: u16,
    payloads: &[String],
) -> Result<(), String> {
    let target = SocketAddr::new(target_ip, target_port);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, bind_port))
        .map_err(|e| format!("client bind {bind_ip}:{bind_port}: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .map_err(|e| format!("client timeout setup: {e}"))?;
    let mut buf = [0u8; 65535];
    for payload in payloads {
        socket
            .send_to(payload.as_bytes(), target)
            .map_err(|e| format!("send {payload} to {target}: {e}"))?;
        let (n, source) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("reply for {payload} from {target}: {e}"))?;
        if source != target {
            return Err(format!(
                "reply for {payload} came from {source}, expected {target}"
            ));
        }
        if &buf[..n] != payload.as_bytes() {
            return Err(format!(
                "reply payload mismatch: got {:?}, expected {:?}",
                String::from_utf8_lossy(&buf[..n]),
                payload
            ));
        }
        println!("RX {source} {payload}");
    }
    println!(
        "CLIENT_OK local={} target={target}",
        socket
            .local_addr()
            .map_err(|e| format!("client local_addr: {e}"))?
    );
    Ok(())
}

fn client_no_reply(
    bind_ip: IpAddr,
    bind_port: u16,
    target_ip: IpAddr,
    target_port: u16,
    payload: &str,
) -> Result<(), String> {
    let target = SocketAddr::new(target_ip, target_port);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, bind_port))
        .map_err(|e| format!("client bind {bind_ip}:{bind_port}: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .map_err(|e| format!("client timeout setup: {e}"))?;
    socket
        .send_to(payload.as_bytes(), target)
        .map_err(|e| format!("send {payload} to {target}: {e}"))?;
    let mut buf = [0u8; 2048];
    match socket.recv_from(&mut buf) {
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            println!("NO_REPLY_OK target={target}");
            Ok(())
        }
        Ok((n, source)) => Err(format!(
            "unexpected reply from {source}: {:?}",
            String::from_utf8_lossy(&buf[..n])
        )),
        Err(e) => Err(format!("recv while expecting silence from {target}: {e}")),
    }
}

fn dns_fixture(ip: IpAddr, port: u16) -> Result<(), String> {
    let socket = UdpSocket::bind(SocketAddr::new(ip, port))
        .map_err(|e| format!("dns fixture bind {ip}:{port}: {e}"))?;
    println!("DNS_FIXTURE_READY {ip}:{port}");
    let _ = std::io::stdout().flush();
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("dns fixture recv: {e}"))?;
        if let Some(response) = fixture_response(&buf[..n]) {
            socket
                .send_to(&response, peer)
                .map_err(|e| format!("dns fixture send to {peer}: {e}"))?;
        }
    }
}

fn fixture_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (name, question_end, qtype) = parse_question(query)?;
    let mut answers = Vec::new();
    if name == "echo6.test" {
        match qtype {
            1 => answers.push(Ipv4Addr::new(10, 89, 0, 1).octets().to_vec()),
            28 => answers.push(Ipv6Addr::new(0xfd89, 0, 0, 0, 0, 0, 0, 1).octets().to_vec()),
            _ => {}
        }
    }

    let mut out = Vec::with_capacity(question_end + 32);
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..question_end]);
    for rdata in answers {
        out.extend_from_slice(&0xc00cu16.to_be_bytes());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&30u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}

fn parse_question(packet: &[u8]) -> Option<(String, usize, u16)> {
    let mut pos = 12;
    let mut labels = Vec::new();
    for _ in 0..128 {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            let end = pos.checked_add(4)?;
            if end > packet.len() {
                return None;
            }
            let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            return Some((labels.join("."), end, qtype));
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        pos += 1;
        let label = packet.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    None
}

fn dns_query(server_ip: IpAddr, port: u16, name: &str, qtype: u16) -> Result<(), String> {
    let server = SocketAddr::new(server_ip, port);
    let bind_ip = if server_ip.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let socket =
        UdpSocket::bind(SocketAddr::new(bind_ip, 0)).map_err(|e| format!("dns query bind: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("dns query timeout setup: {e}"))?;
    let query = build_query(0x4d42, name, qtype)?;
    socket
        .send_to(&query, server)
        .map_err(|e| format!("dns query send to {server}: {e}"))?;
    let mut buf = [0u8; 4096];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("dns query reply from {server}: {e}"))?;
    let ip = parse_query_response(&buf[..n], 0x4d42, qtype)?;
    println!("{ip}");
    Ok(())
}

fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(name.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(format!("bad DNS name '{name}'"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn parse_query_response(packet: &[u8], id: u16, qtype: u16) -> Result<IpAddr, String> {
    if packet.len() < 12 {
        return Err("short DNS response".into());
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err("DNS response id mismatch".into());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS response rcode {rcode}"));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(packet, pos).ok_or_else(|| "bad DNS question name".to_string())?;
        pos = pos
            .checked_add(4)
            .filter(|p| *p <= packet.len())
            .ok_or_else(|| "truncated DNS question".to_string())?;
    }
    for _ in 0..ancount {
        pos = skip_name(packet, pos).ok_or_else(|| "bad DNS answer name".to_string())?;
        if pos + 10 > packet.len() {
            return Err("truncated DNS answer".into());
        }
        let rr_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let class = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        let end = pos
            .checked_add(rdlen)
            .filter(|p| *p <= packet.len())
            .ok_or_else(|| "truncated DNS rdata".to_string())?;
        if rr_type == qtype && class == 1 {
            match (rr_type, rdlen) {
                (1, 4) => {
                    return Ok(IpAddr::V4(Ipv4Addr::new(
                        packet[pos],
                        packet[pos + 1],
                        packet[pos + 2],
                        packet[pos + 3],
                    )))
                }
                (28, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[pos..end]);
                    return Ok(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => return Err(format!("qtype {qtype} answer has rdlen {rdlen}")),
            }
        }
        pos = end;
    }
    Err("DNS response carried no matching answer".into())
}

fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        pos = pos.checked_add(1 + len)?;
    }
    None
}
