use argparse::{ArgumentParser, StoreTrue, Store};
use std::net::{TcpListener,TcpStream,Shutdown};
use std::io::prelude::*;
use std::io;
use std::fs;
use std::thread;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio, exit};
use std::time::Duration;
use libtor::{Tor, TorFlag, TorAddress, HiddenServiceVersion, log::LogLevel};

fn main() {
    if let Err(err_str) = run(){
        println!("[ERROR] {}", err_str);
        exit(1);
    }
}

fn run() -> Result<(), String>{
    let mut listen = false;
    let mut verbose = false;
    let mut hostname = String::new();
    let mut arg_port = String::new();
    let mut keepalive = false;
    let mut exec = String::new();
    let source_addr = "0.0.0.0";
    {
        {
            let mut base_ap = ArgumentParser::new();
            base_ap.set_description("netcat over TOR.");
            base_ap.refer(&mut listen).add_option(&["-l"], StoreTrue, "Listen for incoming connection");
            base_ap.refer(&mut verbose).add_option(&["-v"], StoreTrue, "Specify verbose output");
            base_ap.refer(&mut keepalive).add_option(&["-k"], StoreTrue, "Listen for another connection after the current connection closes");
            base_ap.refer(&mut exec).add_option(&["-e"], Store, "Execute external program after accepting a connection or making connection. Before the execution stdin,stdout,stderr is redirected to the network descriptor");
            base_ap.refer(&mut hostname).add_argument("hostname", Store, "hostname").required();
            base_ap.refer(&mut arg_port).add_argument("port", Store, "port");
            base_ap.stop_on_first_argument(true);
            base_ap.parse_args_or_exit();
        }
        if listen {
            let mut server_ap = ArgumentParser::new();
            server_ap.refer(&mut listen).add_option(&["-l"], StoreTrue, "Listen for incoming connection");
            server_ap.refer(&mut verbose).add_option(&["-v"], StoreTrue, "Specify verbose output");
            server_ap.refer(&mut keepalive).add_option(&["-k"], StoreTrue, "Listen for another connection after the current connection closes");
            server_ap.refer(&mut exec).add_option(&["-e"], Store, "Execute external program after accepting a connection or making connection. Before the execution stdin,stdout,stderr is redirected to the network descriptor");
            server_ap.refer(&mut arg_port).add_argument("port", Store, "port").required();
            server_ap.parse_args_or_exit();
        } else {
            let mut client_ap = ArgumentParser::new();
            client_ap.refer(&mut verbose).add_option(&["-v"], StoreTrue, "Specify verbose output");
            client_ap.refer(&mut keepalive).add_option(&["-k"], StoreTrue, "Listen for another connection after the current connection closes");
            client_ap.refer(&mut exec).add_option(&["-e"], Store, "Execute external program after accepting a connection or making connection. Before the execution stdin,stdout,stderr is redirected to the network descriptor");
            client_ap.refer(&mut hostname).add_argument("hostname", Store, "hostname").required();
            client_ap.refer(&mut arg_port).add_argument("port", Store, "port").required();
            client_ap.parse_args_or_exit();
        }

    }

    let port:u16 = arg_port.trim().parse().map_err(|_| "port is not a valid u16 integer")?;
    if port < 1 {
        return Err(String::from("invalid port number, range(1-65535)"));
    }

    if listen {
        let address = format!("{}:{}",source_addr,&port);
        let listener = TcpListener::bind(&address).map_err(|e| format!("bind error: {}",e))?;
        thread::spawn(move || {
            let _ = Tor::new()
                .flag(TorFlag::DataDirectory("/tmp/torcat2".into()))
                .flag(TorFlag::SocksPort(29050))
                .flag(TorFlag::Log(LogLevel::Err))
                .flag(TorFlag::Hush())
                .flag(TorFlag::HiddenServiceDir("/tmp/torcat/hs-dir".into()))
                .flag(TorFlag::HiddenServiceVersion(HiddenServiceVersion::V3))
                .flag(TorFlag::HiddenServicePort(TorAddress::Port(port), None.into()))
                .start();
            exit(0)
        });
        let mut contents = String::new();
        for i in 1..5 {
            match fs::read_to_string("/tmp/torcat/hs-dir/hostname"){
                Err(e) => {
                    if i < 5 {
                        thread::sleep(Duration::from_secs(1));
                    }else{
                        return Err(format!("file read error: {}", e))
                    }
                },
                Ok(x) => {contents = x; break},
            }
        }
        println!("Hostname:\n{}", contents);
thread::sleep(Duration::from_secs(10));
        loop{
            if verbose {
                println!("Listening for connections");
            }
            match listener.accept(){
                Ok((stream, _in_addr)) => {
                    if verbose {
                        println!("Connection from: {}", _in_addr);
                    }
                    match handle_connection(&stream, &exec){
                        Ok(x) => x,
                        Err(e) => println!("[ERROR] {}", e),
                    }
                    if verbose {
                        println!("Disconnected from: {}", _in_addr);
                    }
                },
                Err(e) => println!("[ERROR] accepting connection: {}", e),
            }
            if !keepalive {
                break;
            }
        }
    }else{
        Tor::new()
            .flag(TorFlag::Log(LogLevel::Err))
            .flag(TorFlag::Hush())
            .flag(TorFlag::DataDirectory("/tmp/torcat".into()))
            .flag(TorFlag::SocksPort(19050))
            .start_background();
        thread::sleep(Duration::from_secs(2));
        let stream = TcpStream::connect("127.0.0.1:19050").map_err(|e| format!("Tor local socket connection error: {}",e))?;
        loop{
            handle_socks5(&stream, &hostname, port)?;
	    if verbose{
		println!("Connected to: {}:{}", hostname, port)
	    }
            match handle_connection(&stream, &exec){
                Ok(x) => x,
                Err(e) => println!("[ERROR] {}", e),
            }
            if verbose{
                println!("Disconnected from: {}:{}", hostname, port);
            }
            if !keepalive {
                break;
            }
        }
    }
    Ok(())
}

fn handle_socks5(mut stream: &TcpStream, address: &str, port: u16) -> Result<(), String>{
    let mut buffer = [0; 10];
    //client greeting
    stream.write(&[0x05,0x01,0x00]).map_err(|e| format!("Can't write to tor local socket: {}",e))?;
    //server choice
    stream.read(&mut buffer).map_err(|e| format!("Can't read from tor local socket: {}",e))?;
    if buffer[0..2] != [0x05, 0x00]{
        return Err(String::from("SOCKS5 auth required"));
    }
    //connection request
    let mut data = vec![0x05u8, 0x01u8, 0x00u8];
    data.append(&mut to_socks5_addr(address));
    data.append(&mut to_sock5_port(&port));
    stream.write(&data).map_err(|e| format!("Can't write to tor local socket: {}",e))?;
    //server response
    stream.read(&mut buffer).map_err(|e| format!("Can't read from tor local socket: {}",e))?;
    if buffer[0..2] != [0x05, 0x00]{
        return Err(String::from("SOCKS5 connection error"));
    }
    Ok(())
}

fn to_socks5_addr(address: &str) -> Vec<u8>{
    let mut addr = vec![0x03u8, address.len() as u8];
    addr.extend_from_slice(address.as_bytes());
    addr
}

fn to_sock5_port( port: &u16) -> Vec<u8>{
   vec![((port>>8) & 0xff) as u8, (port & 0xff) as u8]
}

fn handle_connection(stream: &TcpStream, exec: &String) -> Result<(), String>{
    if exec == ""{
        stream.set_nonblocking(true).map_err(|e| format!("Can't set socket to non blocking: {}",e))?;
        let stream2 = stream.try_clone().map_err(|e| format!("Can't clone socket: {}",e))?;
        thread::spawn(||{
            handle_input(stream2);
        });
        handle_output(stream);
        stream.shutdown(Shutdown::Both).map_err(|e| format!("Can't close sockets: {}",e))?;
    }else{
        let fd = stream.as_raw_fd();
        Command::new(exec)
            .stdin(unsafe { Stdio::from_raw_fd(fd) })
            .stdout(unsafe { Stdio::from_raw_fd(fd) })
            .stderr(unsafe { Stdio::from_raw_fd(fd) })
            .spawn()
            .map_err(|e| format!("Can't spawn new thread: {}",e))?
            .wait()
            .map_err(|e| format!("Can't wait new thread: {}",e))?;
    }
    Ok(())
}

fn handle_output(mut stream: &TcpStream){
    loop{
        let mut buffer = [0; 1024];
        match stream.read(&mut buffer){
            Ok(len) if len == 0 => break,
            Ok(_) => print!("{}", String::from_utf8_lossy(&buffer[..])),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => break,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => println!("[ERROR] error reading buffer: {}",e),
        }
    }
}

fn handle_input(mut stream: TcpStream){
    loop{
        let mut input = String::new();
        match io::stdin().read_line(&mut input){
            Ok(_) => (),
            Err(e) => println!("[ERROR] can't read from stdin: {}", e),
        }
        match stream.write(&input.as_bytes()){
            Ok(_) => (),
            Err(e) => println!("[ERROR] can't write to socket: {}", e),
        }
    }
}
