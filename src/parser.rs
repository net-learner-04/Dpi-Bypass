fn tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == 0x16 && buf[1] == 0x03
}

pub fn extract_sni(buf: &[u8]) -> Option<String> {
    if !(tls_client_hello(buf)) {
        return None;
    }

    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }

    let mut index = 5;

    if index >= buf.len() || buf[index] != 0x01 {
        return None;
    }
    index += 38;
    if index >= buf.len() {
        return None;
    }

    let session_id_len = buf[index] as usize;
    if index + 1 + session_id_len > buf.len() {
        return None;
    }

    index += 1 + session_id_len;

    if index + 1 >= buf.len() {
        return None;
    }
    let cipher_len = ((buf[index] as usize) << 8) | (buf[index + 1] as usize);
    index += 2 + cipher_len;

    if index >= buf.len() {
        return None;
    }
    let compression_len = buf[index] as usize;
    if index + 1 + compression_len > buf.len() {
        return None;
    }

    index += 1 + compression_len;
    if index + 1 >= buf.len() {
        return None;
    }
    let extension_len = ((buf[index] as usize) << 8) | (buf[index + 1] as usize);
    index += 2;
    let extension_len_end_index = index + extension_len;

    while index < extension_len_end_index {
        if index + 4 > buf.len() {
            return None;
        }

        let ext_type = ((buf[index] as usize) << 8) | (buf[index + 1] as usize);
        let ext_len = ((buf[index + 2] as usize) << 8) | (buf[index + 3] as usize);

        if ext_type == 0 {
            if index + 8 >= buf.len() {
                break;
            }

            if buf[index + 6] != 0x00 {
                break;
            }
            let sni_name_len = ((buf[index + 7] as usize) << 8) | (buf[index + 8] as usize);
            let sni_start = index + 9;

            if sni_start + sni_name_len > buf.len() {
                break;
            }

            let sni =
                String::from_utf8_lossy(&buf[sni_start..sni_start + sni_name_len]).to_string();

            return Some(sni);
        } else {
            index += 4 + ext_len;
        }
    }

    None
}
