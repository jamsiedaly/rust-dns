use std::fmt::Display;
use std::io::{Read, Write};
use crate::dns::{DnsQuery, DnsResponse};
use clap::Parser;
use futures::future::join_all;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;

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
    let connection = sqlite::open(":memory:").unwrap();
    let query = "
        CREATE TABLE queries (query TEXT, time TEXT);
    ";
    connection.execute(query).unwrap();

    let udp_socket = UdpSocket::bind("127.0.0.1:2053")
        .await
        .expect("Failed to bind to localhost address");
    let resolver_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("Failed to bind to resolver address"),
    );

    tokio::spawn(async move {
        let listener = TcpListener::bind("0.0.0.0:80").unwrap();

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    std::thread::spawn(move || {
                        let mut buf: [u8; 256] = [0; 256];
                        if let Ok(message_length) = stream.read(&mut buf) {
                            let message = parse_request(&buf, message_length);

                            if message.path == "/" {
                                let request_count: i64 = connection
                                    .prepare("SELECT COUNT(*) FROM queries")
                                    .unwrap()
                                    .read(0)
                                    .unwrap();

                                let response_body = format!("There have been {} requests", request_count);
                                let response = Response {
                                    status_code: 200,
                                    headers: vec![
                                        "Content-Type: text/plain".to_owned(),
                                        format!("Content-Length: {}", response_body.len()),
                                    ],
                                    body: response_body,
                                };
                                stream.write(response.to_string().as_bytes()).unwrap();
                            }
                        }
                    });
                }
                _ => {}
            }
        }
    });

    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf).await {
            Ok((_, request_source)) => {
                let mut dns_query = DnsQuery::deserialize(&buf);
                println!("Request: {:?}", dns_query);

                let singular_queries = dns_query.split_questions();

                let mut tasks = vec![];

                for query in singular_queries {
                    let resolver_socket = resolver_socket.clone();
                    tasks.push(tokio::spawn(async move {
                        resolver_socket
                            .send_to(&query.serialize(), resolver)
                            .await
                            .expect("Failed to send request to resolver");
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
                udp_socket
                    .send_to(&response.serialize(), request_source)
                    .await
                    .expect("Failed to send response to client");
                println!("Responded: {:?}", response);
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

fn parse_request(request: &[u8; 256], message_length: usize) -> Request {
    let request = &request[0..message_length];

    let header_section = String::from_utf8_lossy(request);

    let mut lines = header_section.lines();
    let first_line = lines.next().unwrap();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap().to_owned();
    let path = parts.next().unwrap().to_owned();
    let http_version = parts.next().unwrap().to_owned();

    let mut headers = Vec::new();

    let mut parsing_headers = true;
    let mut content_length: Option<usize> = None;
    let mut content = String::new();
    for line in lines {
        if parsing_headers {
            if line.is_empty() {
                parsing_headers = false;
            } else {
                if line.starts_with("Content-Length") {
                    content_length = line.split(":").collect::<Vec<&str>>()[1]
                        .trim()
                        .parse::<usize>()
                        .ok();
                }
                headers.push(line.to_owned());
            }
        } else if content_length.is_some() {
            content.push_str(line);
        }
    }

    return Request {
        method,
        headers,
        path,
        http_version,
        content: content.to_owned(),
    };
}

#[allow(dead_code)]
struct Request {
    method: String,
    headers: Vec<String>,
    path: String,
    http_version: String,
    content: String,
}

struct Response {
    status_code: u16,
    headers: Vec<String>,
    body: String,
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut response = format!("HTTP/1.1 {}\r\n", self.status_code);
        self.headers.iter().for_each(|header| {
            response.push_str(&format!("{}\r\n", header));
        });
        response.push_str("\r\n");
        response.push_str(&self.body);
        return write!(f, "{}", response);
    }
}