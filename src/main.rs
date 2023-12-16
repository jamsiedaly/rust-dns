use std::net::UdpSocket;
use nom::AsBytes;

pub struct DNSHeader {
    id: u16,
    qr: u8,
    opcode:u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSHeader {
    pub fn serialize(&self) -> [u8; 12] {
        let mut buffer = [0; 12];
        buffer[0] = (self.id >> 8) as u8;
        buffer[1] = self.id as u8;
        buffer[2] = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        buffer[3] = (self.ra << 7) | (self.z << 4) | self.rcode;
        buffer[4] = (self.qdcount >> 8) as u8;
        buffer[5] = self.qdcount as u8;
        buffer[6] = (self.ancount >> 8) as u8;
        buffer[7] = self.ancount as u8;
        buffer[8] = (self.nscount >> 8) as u8;
        buffer[9] = self.nscount as u8;
        buffer[10] = (self.arcount >> 8) as u8;
        buffer[11] = self.arcount as u8;
        return buffer;
    }

    pub fn deserialize(buffer: &[u8]) -> DNSHeader {
        let id = ((buffer[0] as u16) << 8) | buffer[1] as u16;
        let qr = buffer[2] >> 7;
        let opcode = (buffer[2] >> 3) & 0b1111;
        let aa = (buffer[2] >> 2) & 0b1;
        let tc = (buffer[2] >> 1) & 0b1;
        let rd = buffer[2] & 0b1;
        let ra = buffer[3] >> 7;
        let z = (buffer[3] >> 4) & 0b111;
        let rcode = buffer[3] & 0b1111;
        let qdcount = ((buffer[4] as u16) << 8) | buffer[5] as u16;
        let ancount = ((buffer[6] as u16) << 8) | buffer[7] as u16;
        let nscount = ((buffer[8] as u16) << 8) | buffer[9] as u16;
        let arcount = ((buffer[10] as u16) << 8) | buffer[11] as u16;
        return DNSHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        };
    }
}

pub struct Question {
    labels: Vec<String>,
    qtype: u16,
    qclass: u16,
}

impl Question {
    pub fn deserialize(buffer: &[u8]) -> Question {
        let mut pos = 0;
        let mut labels = Vec::new();
        loop {
            let len = buffer[pos] as usize;
            if len == 0 {
                break;
            }
            let label = String::from_utf8_lossy(&buffer[pos + 1..pos + len + 1]);
            labels.push(label.into_owned());
            pos += len + 1;
        }
        pos += 1;
        let qtype = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
        pos += 2;
        let qclass = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
        return Question {
            labels,
            qtype,
            qclass,
        };
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for label in &self.labels {
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0);
        buffer.push((self.qtype >> 8) as u8);
        buffer.push(self.qtype as u8);
        buffer.push((self.qclass >> 8) as u8);
        buffer.push(self.qclass as u8);
        return buffer.as_bytes().to_owned();
    }
}

pub struct ResourceRecord {
    name: Vec<String>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl ResourceRecord {

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for label in &self.name {
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0);
        buffer.push((self.rtype >> 8) as u8);
        buffer.push(self.rtype as u8);
        buffer.push((self.class >> 8) as u8);
        buffer.push(self.class as u8);
        buffer.push((self.ttl >> 24) as u8);
        buffer.push((self.ttl >> 16) as u8);
        buffer.push((self.ttl >> 8) as u8);
        buffer.push(self.ttl as u8);
        buffer.push((self.rdlength >> 8) as u8);
        buffer.push(self.rdlength as u8);
        buffer.extend_from_slice(&self.rdata);
        return buffer;
    }
}


fn main() {
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let request_header = DNSHeader::deserialize(&buf[..12]);

                let question = Question::deserialize(&buf[12..size]);

                let answer = ResourceRecord {
                    name: question.labels.clone(),
                    rtype: question.qtype,
                    class: question.qclass,
                    ttl: 60,
                    rdlength: 4,
                    rdata: vec![8, 8, 8, 8],
                };

                let response_header = DNSHeader {
                    id: request_header.id,
                    qr: 1,
                    opcode: request_header.opcode,
                    aa: 0,
                    tc: 0,
                    rd: request_header.rd,
                    ra: 0,
                    z: 0,
                    rcode: 4,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                };

                let mut response = vec![];
                response.extend_from_slice(&response_header.serialize());
                response.extend_from_slice(&question.serialize());
                response.extend_from_slice(&answer.serialize());

                println!("Received {} bytes from {}", size, source);
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}