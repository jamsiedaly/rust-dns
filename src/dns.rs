use nom::AsBytes;

pub enum DNSPacket {
    Query(DnsQuery),
    Response(DnsResponse),
}

pub struct DnsQuery {
    pub header: DNSHeader,
    pub questions: Vec<Question>,
}

pub struct DnsResponse {
    pub header: DNSHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
}

impl DNSPacket {
    pub fn deserialize_query(buffer: &[u8]) -> DNSPacket {
        let header = DNSHeader::deserialize(&buffer[..12]);
        let questions = Question::deserialize(&buffer[12..], header.qdcount);
        return DNSPacket::Query(DnsQuery { header, questions });
    }

    pub fn deserialize_response(buffer: &[u8]) -> DNSPacket {
        let header = DNSHeader::deserialize(&buffer[..12]);
        let questions = Question::deserialize(&buffer[12..], header.qdcount);
        let answers = ResourceRecord::deserialize(&buffer[12..], header.ancount);
        return DNSPacket::Response(DnsResponse {
            header,
            questions,
            answers,
        });
    }

    pub fn set_header_id(&mut self, header_id: u16) {
        match self {
            DNSPacket::Query(query) => query.header.id = header_id,
            DNSPacket::Response(response) => response.header.id = header_id,
        }
    }

    pub fn get_question(&self) -> String {
        return match self {
            DNSPacket::Query(query) => query.questions[0].labels.join("."),
            DNSPacket::Response(response) => response.questions[0].labels.join("."),
        };
    }

    pub fn get_answer(self) -> Result<String, DnsQuery> {
        return match self {
            DNSPacket::Response(response) => Ok(response
                .answers
                .iter()
                .map(|answer| answer.to_string())
                .collect::<Vec<String>>()
                .join(".")),
            DNSPacket::Query(query) => Err(query),
        };
    }

    pub fn serialize(&self) -> Vec<u8> {
        return match self {
            DNSPacket::Query(query) => {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&query.header.serialize());
                for question in &query.questions {
                    buffer.extend_from_slice(&question.serialize());
                }
                buffer
            }
            DNSPacket::Response(response) => {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&response.header.serialize());
                for question in &response.questions {
                    buffer.extend_from_slice(&question.serialize());
                }
                for answer in &response.answers {
                    buffer.extend_from_slice(&answer.serialize());
                }
                buffer
            }
        };
    }
}

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
    pub labels: Vec<String>,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn deserialize(buffer: &[u8], qcount: u16) -> Vec<Question> {
        let mut pos = 0;
        let mut questions = Vec::new();
        for _ in 0..qcount {
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
            let qtype = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
            pos += 2;
            let qclass = ((buffer[pos] as u16) << 8) | buffer[pos + 1] as u16;
            questions.push(Question {
                labels,
                qtype,
                qclass,
            });
        }
        return questions;
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
            let rdata = buffer[pos..pos + rdlength as usize].to_vec();
            pos += rdlength as usize;
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

    fn to_string(&self) -> String {
        let mut string = String::new();
        for label in &self.name {
            string.push_str(label);
            string.push('.');
        }
        string.pop();
        return string;
    }
}
