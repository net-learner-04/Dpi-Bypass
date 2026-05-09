use crate::{forge, injector::Injector, parser};
use nfq::{Queue, Verdict};
use std::io;

pub fn start_control() -> io::Result<()> {
    let domain_list = ["youtube.com"];

    let injector = Injector::new()?;

    let mut queue = Queue::open()?;
    queue.bind(0)?;

    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload();

        if payload.len() < 20 {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        let ip_ver = payload[0] >> 4;
        let proto = payload[9];

        if ip_ver != 4 || proto != 6 {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        let ip_header_len = (payload[0] & 0x0F) as usize * 4;

        if payload.len() < ip_header_len + 20 {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        let tcp_header_len = (payload[ip_header_len + 12] >> 4) as usize * 4;
        if tcp_header_len < 20 {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        let tls_start_idx = ip_header_len + tcp_header_len;

        if payload.len() <= tls_start_idx {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        let tls_data = &payload[tls_start_idx..];

        if tls_data[0] != 0x16 {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

        if let Some(domain) = parser::extract_sni(tls_data) {
            println!("domain: {}",domain);
            if domain_list.iter().any(|&target| domain.contains(target)) {
                if let Some((target_ip, frag_1, frag_2)) = forge::split(payload) {
                    injector.shoot(target_ip, &frag_1)?;
                    injector.shoot(target_ip, &frag_2)?;
                    println!("dpi success: {}", domain);

                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                    continue;
                }
            }
        }

        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}
