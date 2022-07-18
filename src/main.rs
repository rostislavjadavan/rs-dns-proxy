use dns_parser::{Builder, Packet, RData, ResponseCode};
use std::error::Error;
use std::io::{Read, Result, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
//use dns_parser::rdata::a::Record;
use dns_parser::{QueryClass, QueryType};
use signal_hook::flag;

fn udp_dns_query(
    packet_id: u16,
    udp_socket: &UdpSocket,
    domain: &str,
) -> core::result::Result<Vec<u8>, Box<dyn Error>> {
    println!("resolving {:?}", domain);

    let mut builder = Builder::new_query(packet_id, true);
    builder.add_question(domain, false, QueryType::A, QueryClass::IN);
    let packet = builder.build().map_err(|_| "truncated packet")?;
    udp_socket.send(&packet)?;

    let mut buf = vec![0u8; 4096];
    udp_socket.recv(&mut buf)?;

    println!("packet received");

    Ok(buf)
}

fn handle_udp(udp_socket: UdpSocket, udp_dns_socket: UdpSocket) -> Result<()> {
    let mut buf = [0; 1024];
    let (size, src_adr) = udp_socket.recv_from(&mut buf)?;

    //let fbuf = &mut buf[..nob];
    println!(
        "number_of_bytes={}, src_adr={:?}, data={:?}",
        size,
        src_adr,
        &buf[0..size]
    );

    let pkt = Packet::parse(&buf[0..size]).unwrap();

    //println!("{:?}", pkt);

    if pkt.questions.len() > 0 {
        println!("{:?}", pkt.questions[0].qname.to_string());

        match udp_dns_query(
            pkt.header.id,
            &udp_dns_socket,
            &pkt.questions[0].qname.to_string(),
        ) {
            Ok(buf) => {
                let resp_pkt = Packet::parse(&buf).unwrap();
                println!("packet={:?}", resp_pkt);

                match udp_socket.send_to(&buf, src_adr) {
                    Ok(_) => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            Err(e) => eprintln!("dns query error {:?}", e),
        }
    }
    Ok(())
}

fn handle_tcp(tcp_socket: TcpListener, tcp_dns_socket: Arc<Mutex<TcpStream>>) -> Result<()> {
    for stream in tcp_socket.incoming() {
        let dns_socket = tcp_dns_socket.clone();
        match stream {
            Ok(stream) => {
                println!("new connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move || handle_tcp_stream(stream, dns_socket));
            }
            Err(e) => eprintln!("error {:?}", e),
        }
    }
    Ok(())
}

fn handle_tcp_stream(mut stream: TcpStream, tcp_dns_socket: Arc<Mutex<TcpStream>>) {
    let mut buf = [0; 1024];

    while match stream.read(&mut buf) {
        Ok(size) => {
            println!("tcp data size={}, data={:?}", size, &buf[0..size]);

            let pkt = Packet::parse(&buf[2..]).unwrap();
            println!("{:?}", pkt);

            match build_query(pkt.header.id, &pkt.questions[0].qname.to_string()) {
                Ok(packet) => {
                    let mut shared = tcp_dns_socket.lock().unwrap();
                    //shared.write(&buf[2..]).unwrap();
                    shared.write(&packet).unwrap();

                    let mut data = [0; 1024];
                    match shared.read(&mut data) {
                        Ok(size) => {
                            println!(
                                "got response from dns upstream via tcp, response size={}",
                                size
                            );
                            stream.write(&buf).unwrap();
                        }
                        Err(e) => {
                            println!("error tcp connect to dns upstream: {}", e);
                            //shared.shutdown(Shutdown::Both).unwrap();
                        }
                    };
                }
                Err(e) => {
                    println!("unable to build tcp question packet: {}", e);
                }
            }

            true
        }
        Err(e) => {
            println!("error reading tcp stream: {:?}", e);
            //stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn build_query(packet_id: u16, domain: &str) -> core::result::Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = Builder::new_query(packet_id, true);
    builder.add_question(domain, false, QueryType::A, QueryClass::IN);

    return Ok(builder.build().map_err(|_| "truncated packet")?);
}

fn main() -> std::io::Result<()> {
    let term = Arc::new(AtomicBool::new(false));
    flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

    let udp_dns_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    udp_dns_socket.connect("8.8.8.8:53").expect("no no no");

    let udp_socket = UdpSocket::bind("127.0.0.1:5300")?;

    thread::spawn(move || match handle_udp(udp_socket, udp_dns_socket) {
        Ok(_) => println!("udp packet sent"),
        Err(e) => println!("udp error {:?}", e),
    });

    let tcp_dns_socket = Arc::new(Mutex::new(TcpStream::connect("8.8.8.8:53").unwrap()));
    let tcp_socket = TcpListener::bind("127.0.0.1:5300").unwrap();

    thread::spawn(move || match handle_tcp(tcp_socket, tcp_dns_socket) {
        Ok(_) => println!("tcp packet sent"),
        Err(e) => println!("tcp error {:?}", e),
    });

    while !term.load(Ordering::Relaxed) {
        thread::sleep(time::Duration::from_secs(1));
    }

    println!("goodbye! :)");
    Ok(())
}
