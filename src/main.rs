use crate::dns::DNSPacket;
use clap::Parser;
use nom::AsBytes;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;

mod dns;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    resolver: String,
}

impl From<Args> for SocketAddr {
    fn from(value: Args) -> Self {
        let parts = value.resolver.split(":").collect::<Vec<&str>>();
        if parts.len() == 2 {
            return SocketAddr::new(
                IpAddr::from_str(parts[0]).expect("Invalid IP address"),
                u16::from_str(parts[1]).expect("Invalid port number"),
            );
        } else {
            panic!("Invalid resolver address. Resolver address must be in the format IP:PORT");
        }
    }
}

fn main() {
    println!("Logs from your program will appear here!");
    let args = Args::parse();
    let resolver: SocketAddr = args.into();

    let udp_socket =
        UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to localhost address");
    let resolver_socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to resolver address");

    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, request_source)) => {
                let dns_packet = DNSPacket::deserialize_query(&buf[..size]);

                resolver_socket
                    .send_to(dns_packet.serialize().as_ref(), resolver)
                    .expect("Failed to send request to resolver");

                match udp_socket.recv(&mut buf) {
                    Ok(size) => {
                        let mut response = DNSPacket::deserialize_response(&buf[..size]);
                        response.set_header_id(1234);
                        udp_socket
                            .send_to(&response.serialize(), request_source)
                            .expect("Failed to send response");
                    }
                    Err(e) => {
                        eprintln!("Error receiving data: {}", e);
                        break;
                    }
                }

                // let answers = dns_packet.questions
                //     .iter()
                //     .map(|question| ResourceRecord {
                //         name: question.labels.clone(),
                //         rtype: question.qtype,
                //         class: question.qclass,
                //         ttl: 60,
                //         rdlength: 4,
                //         rdata: vec![8, 8, 8, 8],
                //     })
                //     .collect::<Vec<ResourceRecord>>();
                //
                // let response_header = DNSHeader {
                //     id: request_header.id,
                //     qr: 1,
                //     opcode: request_header.opcode,
                //     aa: 0,
                //     tc: 0,
                //     rd: request_header.rd,
                //     ra: 0,
                //     z: 0,
                //     rcode: 4,
                //     qdcount: questions.len() as u16,
                //     ancount: answers.len() as u16,
                //     nscount: 0,
                //     arcount: 0,
                // };
                //
                // let mut response = vec![];
                // response.extend_from_slice(&response_header.serialize());
                // for question in questions.into_iter() {
                //     response.extend_from_slice(&question.serialize());
                // }
                // for answer in answers.into_iter() {
                //     response.extend_from_slice(&answer.serialize());
                // }
                //
                // println!("Received {} bytes from {}", size, source);
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
