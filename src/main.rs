use crate::dns::{DnsResponse, DnsQuery};
use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use std::str::FromStr;
use std::sync::Arc;
use futures::future::join_all;

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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let resolver: SocketAddr = args.into();

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").await.expect("Failed to bind to localhost address");
    let resolver_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind to resolver address"));

    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf).await {
            Ok((size, request_source)) => {
                let mut dns_query = DnsQuery::deserialize(&buf[..size]);
                println!("Request: {:?}", dns_query);

                let singular_queries = dns_query.split_questions();

                let mut tasks = vec![];

                for query in singular_queries {
                    let resolver_socket = resolver_socket.clone();
                    tasks.push(tokio::spawn(async move {
                        resolver_socket.send_to(&query.serialize(), resolver).await.expect("Failed to send request to resolver");
                        resolver_socket.recv(&mut buf).await.unwrap();
                        DnsResponse::deserialize(&buf)
                    }));
                }

                let responses = join_all(tasks).await;
                let mut header = responses[0].as_ref().unwrap().header.clone();
                let mut answers = vec![];
                for response in responses {
                    for answer in response.unwrap().answers {
                        answers.push(answer);
                    }
                }
                header.qdcount = dns_query.questions.len() as u16;
                header.ancount = answers.len() as u16;
                let response = DnsResponse {
                    header,
                    questions: dns_query.questions,
                    answers,
                };

                println!("Response: {:?}", response);

                udp_socket.send_to(&response.serialize(), request_source).await.expect("Failed to send response to client");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
