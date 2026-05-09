use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use std::net::Ipv4Addr;

struct PacketInfo {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    ttl: u8,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    window_size: u16,
}

pub fn split(raw_packet: &[u8]) -> Option<(Ipv4Addr, Vec<u8>, Vec<u8>)> {
    let parsed = SlicedPacket::from_ip(raw_packet).ok()?;

    let (ip_slice, tcp_slice) = match (&parsed.net, &parsed.transport) {
        (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Tcp(tcp))) => (ip, tcp),
        _ => return None,
    };

    let ip_header = ip_slice.header();

    let pkt_info = PacketInfo {
        src_ip: ip_header.source(),
        dst_ip: ip_header.destination(),
        ttl: ip_header.ttl(),
        src_port: tcp_slice.source_port(),
        dst_port: tcp_slice.destination_port(),
        seq_num: tcp_slice.sequence_number(),
        ack_num: tcp_slice.acknowledgment_number(),
        window_size: tcp_slice.window_size(),
    };

    let ip_header_len = (ip_header.ihl() as usize) * 4;
    let tcp_header_len = (tcp_slice.data_offset() as usize) * 4;
    let payload_offset = ip_header_len + tcp_header_len;

    let target_ip = Ipv4Addr::new(
        pkt_info.dst_ip[0],
        pkt_info.dst_ip[1],
        pkt_info.dst_ip[2],
        pkt_info.dst_ip[3],
    );

    let payload = &raw_packet[payload_offset..];

    if payload.is_empty() {
        return None;
    }

    if payload.len() < 2 {
        return None;
    }

    let payload_f1 = &payload[0..1];
    let payload_f2 = &payload[1..];

    let builder1 = PacketBuilder::ipv4(pkt_info.src_ip, pkt_info.dst_ip, pkt_info.ttl)
        .tcp(
            pkt_info.src_port,
            pkt_info.dst_port,
            pkt_info.seq_num,
            pkt_info.window_size,
        )
        .psh()
        .ack(pkt_info.ack_num);

    let mut frag_1 = Vec::<u8>::with_capacity(builder1.size(payload_f1.len()));

    builder1.write(&mut frag_1, payload_f1).unwrap();

    let new_seq_num = pkt_info.seq_num.wrapping_add(payload_f1.len() as u32);

    let builder2 = PacketBuilder::ipv4(pkt_info.src_ip, pkt_info.dst_ip, pkt_info.ttl)
        .tcp(
            pkt_info.src_port,
            pkt_info.dst_port,
            new_seq_num,
            pkt_info.window_size,
        )
        .psh()
        .ack(pkt_info.ack_num);

    let mut frag_2 = Vec::<u8>::with_capacity(builder2.size(payload_f2.len()));
    builder2.write(&mut frag_2, payload_f2).unwrap();

    Some((target_ip, frag_1, frag_2))
}
