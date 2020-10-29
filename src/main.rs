
use std::str;
use std::error::Error;
use std::net::UdpSocket;
use dns_parser::{Builder, Packet, RData, ResponseCode};
use dns_parser::rdata::a::Record;
use dns_parser::{QueryType, QueryClass};

fn dns_query(packet_id: u16, socket: &std::net::UdpSocket, domain: &str ) -> Result<Vec<u8>, Box<dyn Error>> {
    println!("resolving {:?}", domain);

    let mut builder = Builder::new_query(packet_id, true);
    builder.add_question(domain, false, QueryType::A, QueryClass::IN);
    let packet = builder.build().map_err(|_| "truncated packet")?;
    socket.send(&packet)?;

    let mut buf = vec![0u8; 4096];
    socket.recv(&mut buf)?;

    println!("packet received");

    Ok(buf)
}

fn main() -> std::io::Result<()> {
    let req_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    req_socket.connect("8.8.8.8:53").expect("no no no");


    let socket = UdpSocket::bind("127.0.0.1:5353")?;
    //socket.connect("127.0.0.1:5353").expect("no no no");

    loop {
        let mut buf = [0; 1024];
        let (nob, src_adr) = socket.recv_from(&mut buf)?;

        //let fbuf = &mut buf[..nob];
        //println!("number_of_bytes={}, src_adr={:?}, rev={:?}", nob, src_adr, fbuf);
        
        let pkt = Packet::parse(&buf).unwrap();

        //println!("{:?}", pkt);        
        
        if pkt.questions.len() > 0 {
            println!("{:?}", pkt.questions[0].qname.to_string());

            match dns_query(pkt.header.id, &req_socket, &pkt.questions[0].qname.to_string()) {
                Ok(buf) => { 
                    let resp_pkt = Packet::parse(&buf).unwrap();
                    println!("packet={:?}", resp_pkt);                    

                    match socket.send_to(&buf, src_adr) {
                        Ok(_) => println!("response sent"),
                        Err(e) => println!("{:?}", e)
                    }
                }
                Err(e) => { 
                    println!("{:?}", e)
                }
            }
        }
    }

    Ok(())
}
