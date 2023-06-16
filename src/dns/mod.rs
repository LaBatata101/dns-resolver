use bincode::Options;
use rand::Rng;
use std::{
    fmt::Debug,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
};

use serde::{Deserialize, Serialize};

mod helpers;
pub mod types;

use crate::dns::{
    helpers::{get_answer, get_nameserver, get_nameserver_ip},
    types::TYPE_A,
};

use self::{
    helpers::{decode_name, encode_dns_name, get_bincode_options},
    types::{CLASS_IN, TYPE_NS},
};

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

#[derive(Default, Deserialize, Serialize)]
pub struct DNSQuestion {
    #[serde(with = "serde_bytes")]
    pub q_name: Vec<u8>,
    pub q_type: u16,
    pub q_class: u16,
}

#[derive(Default, Debug, Clone)]
pub enum ParsedData {
    Domain(String),
    IP(IpAddr),

    #[default]
    None,
}

#[derive(Default, Deserialize, Serialize)]
pub struct DNSRecord {
    pub name: Vec<u8>,
    pub type_: u16,
    pub class: u16,
    pub ttl: u32,
    pub raw_data: Vec<u8>,

    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    pub parsed_data: ParsedData,
}

#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

impl DNSHeader {
    pub fn new(
        id: u16,
        flags: u16,
        num_questions: u16,
        num_answers: u16,
        num_authorities: u16,
        num_additionals: u16,
    ) -> Self {
        Self {
            id,
            flags,
            num_questions,
            num_answers,
            num_authorities,
            num_additionals,
        }
    }

    /// Encode `DNSHeader` into a vector of bytes.
    /// Note: The byte order is big endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        helpers::get_bincode_options().serialize(self).unwrap()
    }
}

impl DNSQuestion {
    pub fn new(q_name: Vec<u8>, q_type: u16, q_class: u16) -> Self {
        Self {
            q_name,
            q_type,
            q_class,
        }
    }

    /// Encode `DNSQuestion` into a vector of bytes.
    /// Note: The byte order is big endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        helpers::get_bincode_options()
            .serialize(self)
            .map(|mut bytes| {
                // removes the size of the string encoded into the vector
                bytes.drain(0..8);
                bytes
            })
            .unwrap()
    }
}

impl DNSRecord {
    pub fn new(name: Vec<u8>, q_type: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        Self {
            name,
            type_: q_type,
            class,
            ttl,
            raw_data: data,
            parsed_data: ParsedData::None,
        }
    }
}

impl DNSPacket {
    pub fn new(
        header: DNSHeader,
        questions: Vec<DNSQuestion>,
        answers: Vec<DNSRecord>,
        authorities: Vec<DNSRecord>,
        additionals: Vec<DNSRecord>,
    ) -> Self {
        Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }
}

impl From<[u8; 12]> for DNSHeader {
    fn from(value: [u8; 12]) -> Self {
        helpers::get_bincode_options().deserialize(&value).unwrap()
    }
}

impl TryFrom<&[u8]> for DNSHeader {
    type Error = Box<bincode::ErrorKind>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        helpers::get_bincode_options().deserialize(value)
    }
}

impl Debug for DNSQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let q_name = String::from_utf8_lossy(&self.q_name);

        f.debug_struct("DNSQuestion")
            .field("q_name", &q_name)
            .field("q_type", &self.q_type)
            .field("q_class", &self.q_class)
            .finish()
    }
}

impl Debug for DNSRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.name);
        f.debug_struct("DNSRecord")
            .field("name", &name)
            .field("type_", &self.type_)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("data", &self.raw_data)
            .field("parsed_data", &self.parsed_data)
            .finish()
    }
}

fn build_query(id: u16, domain_name: &str, record_type: u16) -> Vec<u8> {
    let mut query = Vec::new();

    let encoded_name = encode_dns_name(domain_name);

    let header = DNSHeader::new(id, 0, 1, 0, 0, 0);
    let question = DNSQuestion::new(encoded_name, record_type, CLASS_IN);

    query.extend(header.to_bytes());
    query.extend(question.to_bytes());

    query
}

fn parse_header<R: Read>(mut reader: R) -> DNSHeader {
    let mut buffer = [0u8; 12];
    reader.read_exact(&mut buffer).unwrap();

    DNSHeader::from(buffer)
}

fn parse_question(cursor: &mut Cursor<&[u8]>) -> DNSQuestion {
    let name = decode_name(cursor);

    let mut buffer = [0u8; 4];
    cursor.read_exact(&mut buffer).unwrap();

    let (q_type, q_class): (u16, u16) = get_bincode_options().deserialize(&buffer).unwrap();

    DNSQuestion::new(name, q_type, q_class)
}

fn parse_record(cursor: &mut Cursor<&[u8]>) -> DNSRecord {
    let name = decode_name(cursor);

    let mut buffer = [0u8; 10];
    cursor.read_exact(&mut buffer).unwrap();

    let (q_type, class, ttl, data_len): (u16, u16, u32, u16) = get_bincode_options().deserialize(&buffer).unwrap();
    let mut data_buffer = vec![0u8; data_len as usize];

    let raw_data: Vec<u8>;
    let parsed_data: ParsedData;

    if q_type == TYPE_NS {
        raw_data = decode_name(cursor);
        parsed_data = ParsedData::Domain(String::from_utf8(raw_data.clone()).unwrap());
    } else if q_type == TYPE_A {
        cursor.read_exact(&mut data_buffer).unwrap();

        let data: [u8; 4] = data_buffer[..4].try_into().unwrap();
        let ip = Ipv4Addr::from(data);

        raw_data = data_buffer;
        parsed_data = ParsedData::IP(IpAddr::V4(ip));
    } else {
        cursor.read_exact(&mut data_buffer).unwrap();

        raw_data = data_buffer;

        let data: [u8; 16] = raw_data[..16].try_into().unwrap();
        let ip = Ipv6Addr::from(data);

        parsed_data = ParsedData::IP(IpAddr::V6(ip));
    }

    DNSRecord {
        name,
        type_: q_type,
        ttl,
        class,
        raw_data,
        parsed_data,
    }
}

fn parse_dns_packet(data: &[u8]) -> DNSPacket {
    let mut cursor = Cursor::new(data);
    let header = parse_header(&mut cursor);

    let questions: Vec<DNSQuestion> = (0..header.num_questions).map(|_| parse_question(&mut cursor)).collect();
    let answers: Vec<DNSRecord> = (0..header.num_answers).map(|_| parse_record(&mut cursor)).collect();
    let authorities: Vec<DNSRecord> = (0..header.num_authorities).map(|_| parse_record(&mut cursor)).collect();
    let additionals: Vec<DNSRecord> = (0..header.num_additionals).map(|_| parse_record(&mut cursor)).collect();

    DNSPacket::new(header, questions, answers, authorities, additionals)
}

fn send_query(ip_addr: IpAddr, domain_name: &str, record_type: u16) -> DNSPacket {
    let query = build_query(
        rand::thread_rng().gen_range(u16::MIN..=u16::MAX),
        domain_name,
        record_type,
    );
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket!");
    let server_addr = SocketAddr::new(ip_addr, 53);

    socket.send_to(&query, server_addr).expect("Failed to send data!");
    let mut buffer = [0u8; 1024];
    socket
        .recv_from(&mut buffer)
        .expect("Failed to receive data from server!");

    parse_dns_packet(&buffer)
}

pub fn resolve(domain_name: &str, record_type: u16) -> Result<IpAddr, &'static str> {
    let mut nameserver = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));

    loop {
        println!("Querying {nameserver} for {domain_name}");
        let response = send_query(nameserver, domain_name, record_type);
        if let Some(ParsedData::IP(ip)) = get_answer(&response) {
            return Ok(ip);
        } else if let Some(ParsedData::IP(ns_ip)) = get_nameserver_ip(&response) {
            nameserver = ns_ip;
        } else if let Some(ParsedData::Domain(ns_domain)) = get_nameserver(&response) {
            nameserver = resolve(&ns_domain, TYPE_A).unwrap();
        } else {
            break Err("Something went wrong");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_build_query() {
        let query = build_query(0x8298, "www.example.com", TYPE_A);

        assert_eq!(
            hex::encode(query),
            "82980100000100000000000003777777076578616d706c6503636f6d0000010001"
        );
    }
}
