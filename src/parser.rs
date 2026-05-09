pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // tls record header check
    if buf.len() < 5 {return None;}

    if buf[0] != 0x16 || buf[1] != 0x03 {return None;}

    if buf.len() < 5 || buf[0] != 0x16 {return None;}
    
    // tls record length check -> fragment packet detect
    let record_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    if buf.len() < 5 + record_len {return None;}

    let mut index = 5;
    
    // handshake type check (0x01 = ClientHello)
    if index >= buf.len() || buf[index] != 0x01 {return None;}
    index += 1;

    // handshake length check
    if index + 3 > buf.len() {return None;}

    if index >= buf.len() {return None;}
    index += 3;

    // client version (2byte) + random (32byte) check
    if index + 32 > buf.len() {return None;}
    index += 34;

    // session id check
    if index >= buf.len() {return None;}
    let session_id_len = buf[index] as usize;
    index += 1;
    if index + session_id_len > buf.len() {return None;}
    index += session_id_len;

    // cipher length check
    let cipher_len = ((buf[index] as usize) << 8) | (buf[index + 1] as usize);
    index += 2 + cipher_len;

    // compression methods
    if index >= buf.len() {return None;}
    let compression_len = buf[index] as usize;
    index += 1 + compression_len;

    // extensions check
    if index + 2 > buf.len() {return None;}
    let extension_end = index + 2 + (((buf[index] as usize) << 8) | (buf[index + 1] as usize));
    index += 2;

    while index + 4 <= buf.len() && index < extension_end {
        let ext_type = ((buf[index] as usize) << 8) | (buf[index + 1] as usize);
        let ext_len = ((buf[index + 2] as usize) << 8) | (buf[index + 3] as usize);

        if ext_type == 0 {
            // SNI extension: [list_len(2)][name_type(1)][name_len(2)][name]
            let sni_header_start = index + 4;
            if sni_header_start + 5 > buf.len() {
                return None;
            }
            // name_type == 0x00 (host_name)
            if buf[sni_header_start + 2] != 0x00 {
                return None;
            }
            let name_len = ((buf[sni_header_start + 3] as usize) << 8)
                | (buf[sni_header_start + 4] as usize);
            let name_start = sni_header_start + 5;
            if name_start + name_len > buf.len() {
                return None;
            }
            return Some(
                String::from_utf8_lossy(&buf[name_start..name_start + name_len]).to_string(),
            );
        }
        index += 4 + ext_len;
    }
    None
}
