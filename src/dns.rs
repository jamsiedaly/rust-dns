use byteorder::{BigEndian, ByteOrder};
use nom::AsBytes;

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub header: DNSHeader,
    pub questions: Vec<Question>,
}

#[derive(Debug)]
pub struct DnsResponse {
    pub header: DNSHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
}

impl DnsQuery {
    pub fn deserialize(buffer: &[u8]) -> DnsQuery {
        let header = DNSHeader::deserialize(&buffer[..12]);
        let (questions, _) = Question::deserialize(&buffer[12..], header.qdcount);
        return DnsQuery { header, questions };
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.header.serialize());
        for question in &self.questions {
            buffer.extend_from_slice(&question.serialize());
        }
        return buffer
    }

    pub fn split_questions(&mut self) -> Vec<DnsQuery> {
        let mut queries = Vec::new();
        for question in &self.questions {
            let mut query = self.clone();
            query.header.qdcount = 1;
            query.questions = vec![question.clone()];
            queries.push(query);
        }
        return queries;
    }
}

impl DnsResponse {
    pub fn deserialize(buffer: &[u8]) -> DnsResponse {
        let header = DNSHeader::deserialize(&buffer[..12]);
        let (questions, new_pos) = Question::deserialize(&buffer[12..], header.qdcount);
        let answers = if header.ancount > 0 {
            ResourceRecord::deserialize(&buffer[12+new_pos..], header.ancount)
        } else {
            Vec::new()
        };
        return DnsResponse {
            header,
            questions,
            answers,
        };
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.header.serialize());
        for question in &self.questions {
            buffer.extend_from_slice(&question.serialize());
        }
        for answer in &self.answers {
            buffer.extend_from_slice(&answer.serialize());
        }
        return buffer
    }
}

#[derive(Debug, Clone)]
pub struct DNSHeader {
    pub id: u16,
    pub qr: u8,
    pub opcode: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub z: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
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
        let id = BigEndian::read_u16(&buffer[0..2]);
        let qr = buffer[2] >> 7;
        let opcode = (buffer[2] >> 3) & 0b1111;
        let aa = (buffer[2] >> 2) & 0b1;
        let tc = (buffer[2] >> 1) & 0b1;
        let rd = buffer[2] & 0b1;
        let ra = buffer[3] >> 7;
        let z = (buffer[3] >> 4) & 0b111;
        let rcode = buffer[3] & 0b1111;
        let qdcount = BigEndian::read_u16(&buffer[4..6]);
        let ancount = BigEndian::read_u16(&buffer[6..8]);
        let nscount = BigEndian::read_u16(&buffer[8..10]);
        let arcount = BigEndian::read_u16(&buffer[10..12]);
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

#[derive(Debug, Clone)]
pub struct Question {
    pub labels: Vec<String>,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn deserialize(buffer: &[u8], qcount: u16) -> (Vec<Question>, usize) {
        let mut pos = 0;
        let mut questions = Vec::new();
        for _ in 0..qcount {
            let mut labels = Vec::new();
            'label: loop {
                let len = buffer[pos] as usize;
                if len == 0 {
                    break 'label;
                }
                if (pos + len) > buffer.len() {
                    println!("len 1: {}", buffer[pos]);
                    println!("len 2: {}", buffer[pos-1]);
                    println!("len 3: {}", buffer[pos+1]);
                    let l = String::from_utf8_lossy(&buffer[pos..]);
                    println!("Remaining buffer: {}", l);
                }

                let label = String::from_utf8_lossy(&buffer[pos + 1..pos + len + 1]);
                println!("label: {}", label);
                labels.push(label.into_owned());
                pos += len + 1;
            }
            pos += 1;
            let qtype = BigEndian::read_u16(&buffer[pos..pos + 2]);
            pos += 2;
            let qclass = BigEndian::read_u16(&buffer[pos..pos + 2]);
            pos += 2;
            questions.push(Question {
                labels,
                qtype,
                qclass,
            });
        }
        return (questions, pos);
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

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: Vec<String>,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
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

    pub fn deserialize(buffer: &[u8], rcount: u16) -> Vec<ResourceRecord> {
        let mut pos = 0;
        let mut records = Vec::new();
        for _ in 0..rcount {
            let mut labels = Vec::new();
            'label: loop {
                let len = buffer[pos] as usize;
                if len == 0 {
                    break 'label;
                }
                let label = String::from_utf8_lossy(&buffer[pos + 1..pos + len + 1]);
                labels.push(label.into_owned());
                pos += len + 1;
            }
            pos += 1;
            let rtype = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
            pos += 2;
            let class = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
            pos += 2;
            let ttl = ((buffer[pos] as u32) << 24)
                | ((buffer[pos + 1] as u32) << 16)
                | ((buffer[pos + 2] as u32) << 8)
                | buffer[pos + 3] as u32;
            pos += 4;
            let rdlength = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
            pos += 2;
            let rdata = buffer[pos..].to_vec();
            records.push(ResourceRecord {
                name: labels,
                rtype,
                class,
                ttl,
                rdlength,
                rdata,
            });
        }
        return records;
    }
}
