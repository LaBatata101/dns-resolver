use std::io::{Cursor, Read, Seek, SeekFrom};

use bincode::{
    config::{AllowTrailing, BigEndian, FixintEncoding, WithOtherEndian, WithOtherIntEncoding, WithOtherTrailing},
    Options,
};

use super::{
    types::{TYPE_A, TYPE_NS},
    DNSPacket, ParsedData,
};

fn decode_compressed_name(length: u8, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
    let mut pointer_bytes = vec![length & 0b0011_1111];
    let mut buffer = [0u8; 1];

    cursor.read_exact(&mut buffer).unwrap();
    pointer_bytes.extend(buffer);

    let pointer: u16 = get_bincode_options().deserialize(&pointer_bytes).unwrap();
    let current_pos = cursor.stream_position().unwrap();

    cursor.seek(SeekFrom::Start(pointer as u64)).unwrap();
    let name = decode_name(cursor);
    cursor.seek(SeekFrom::Start(current_pos)).unwrap();

    name
}

pub fn get_bincode_options() -> WithOtherEndian<
    WithOtherTrailing<WithOtherIntEncoding<bincode::DefaultOptions, FixintEncoding>, AllowTrailing>,
    BigEndian,
> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_big_endian()
}

pub fn encode_dns_name(domain_name: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    // Split the domain name at the "." (0x2E in hex)
    for part in domain_name.as_bytes().split(|&byte| byte == 0x2E) {
        encoded.push(part.len().try_into().expect("Failed converting `part`'s length to u8"));
        encoded.extend_from_slice(part);
    }

    encoded.push(0x00);

    encoded
}

pub fn decode_name(cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
    let mut parts = Vec::new();
    let mut part_length = [0u8; 1];

    let mut index = 0;
    loop {
        cursor.read_exact(&mut part_length).unwrap();

        let length = part_length[0];
        // avoid adding the "." at the beginning and the end of the vector
        if index > 0 && length > 0 {
            parts.push(0x2E);
        }

        if length == 0 {
            break;
        } else if length & 0b1100_0000 != 0 {
            parts.extend(decode_compressed_name(length, cursor));
            break;
        } else {
            let mut part = vec![0u8; part_length[0] as usize];
            cursor.read_exact(&mut part).unwrap();
            parts.extend(part);
        }

        index += 1;
    }

    parts
}

pub fn get_answer(packet: &DNSPacket) -> Option<ParsedData> {
    // return the first A record in the Answer section
    packet
        .answers
        .iter()
        .find(|answer| answer.type_ == TYPE_A)
        .map(|answer| answer.parsed_data.clone())
}

pub fn get_nameserver_ip(packet: &DNSPacket) -> Option<ParsedData> {
    // return the first A record in the Additional section
    packet
        .additionals
        .iter()
        .find(|additional| additional.type_ == TYPE_A)
        .map(|additional| additional.parsed_data.clone())
}

pub fn get_nameserver(packet: &DNSPacket) -> Option<ParsedData> {
    // return the first NS record in the Authority section
    packet
        .authorities
        .iter()
        .find(|authority| authority.type_ == TYPE_NS)
        .map(|authority| authority.parsed_data.clone())
}
