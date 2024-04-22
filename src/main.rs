use std::{
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

use clap::Parser;
use cli::{
    Cli,
    ClientSubcommand::{Decrypt, Encrypt},
    Command::{Client, Server},
};
use md5::Digest;
use rand::Rng;
use soft_aes::aes::{aes_dec_ecb, aes_enc_ecb};

use crate::{block::Block, time::current_unix_timestamp};

mod block;
mod cli;
mod time;

fn bytes_to_md5_string(md5: &[u8]) -> String {
    let mut hex_string = Vec::new();
    for byte in md5 {
        write!(&mut hex_string, "{:02x}", byte).unwrap();
    }
    let md5 = String::from_utf8_lossy(&hex_string).into_owned();
    md5
}

fn distribute_key(
    md5: &Digest,
    password: &[u8; 16],
    time: &String,
    remote_servers: &Vec<SocketAddrV4>,
) {
    // Distribute the MD5 and part of key to server
    let server_len = remote_servers.len();
    let min_part_size = password.len() / server_len;
    // PART_NUM PART_SIZE PART_OF_AES
    for (i, server) in remote_servers.iter().enumerate() {
        println!("Trying distribute key to {:?}", server);
        let tcp_stream = TcpStream::connect(server);
        match tcp_stream {
            Ok(mut stream) => {
                println!(
                    "\tConnected, distributing to {:?}.",
                    stream.peer_addr().unwrap()
                );
                let mut buffer: Vec<u8> = Vec::new();

                // Opcode
                buffer.push(b'+');
                // The part number of AES key
                buffer.push(i as u8);

                // Part size
                buffer.push(min_part_size as u8);

                // Part of AES key
                if i == remote_servers.len() - 1 {
                    // For the last part
                    buffer.extend_from_slice(&password[min_part_size * i..]);
                } else {
                    // The start and middle part
                    buffer.extend_from_slice(&password[min_part_size * i..min_part_size * (i + 1)]);
                }

                // The MD5 of content
                buffer.extend_from_slice(&md5.0);

                // The time to decrypt
                buffer.extend_from_slice(time.as_bytes());

                stream.write_all(&mut buffer).unwrap();
                println!("\tdone!")
            }
            Err(e) => {
                panic!("Error occured when distribute keys: {:?}", e);
            }
        }
    }
}

fn check_parse_servers(servers: &Vec<String>) -> Vec<SocketAddrV4> {
    let mut remote_servers = Vec::new();

    // Check if the address is valid
    for server in servers.iter() {
        let address: Vec<&str> = server.split(":").collect();
        if address.len() != 2 {
            panic!("You should provide the correct address");
        }

        let ip_str = address[0];
        let port_str = address[1];

        // Parse the IP address
        let ip: Result<Ipv4Addr, _> = ip_str.parse();
        match ip {
            Ok(ip_addr) => {
                // Parse the port number
                if let Ok(port) = port_str.parse::<u16>() {
                    let socket_addr = SocketAddrV4::new(ip_addr, port);
                    remote_servers.push(socket_addr);
                } else {
                    println!("Invalid port number format: {}", port_str);
                }
            }
            Err(_) => {
                println!("Invalid IPv4 address: {}", ip_str);
            }
        }
    }
    remote_servers
}

fn bcrypt_password(password: &String) -> [u8; 16] {
    // From password to generate a bycrypt AES key
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);

    // Using the AES 128 ECB, so 16 bytes password is enough
    let bcrypted_password: [u8; 16] = bcrypt::bcrypt(10, salt, password.as_bytes())[0..16]
        .try_into()
        .unwrap();

    bcrypted_password
}

fn file_md5(content: &Vec<u8>) -> Digest {
    // Calculate MD5 for the file content
    let content_md5 = md5::compute(&content);

    println!(
        "file content: {:?}\nmd5: {:?}",
        String::from_utf8_lossy(&content),
        content_md5
    );
    content_md5
}

fn load_file(filename: &String) -> Vec<u8> {
    let path = Path::new(&filename);

    if !path.exists() {
        panic!("The path of file is incorrect");
    }

    let mut file = File::open(path).unwrap();
    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    content
}

fn encrypt_file(filename: &String, content: &Vec<u8>, content_md5: &Digest, password: &[u8; 16]) {
    // Encrypt the content with the bcrypted key
    let encrypted = aes_enc_ecb(&content, password, Some("PKCS7")).unwrap();

    // Write MD5 and encrypted content to new_file.tle
    let mut new_file = File::create(format!("{}.tle", filename)).unwrap();
    new_file.write_all(&content_md5.0).unwrap();
    new_file.write_all(&encrypted).unwrap();
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Client { command } => match command {
            Decrypt { input, servers } => {
                if servers.is_empty() {
                    panic!("The len of servers must not be zero");
                }

                let remote_servers = check_parse_servers(&servers);

                let content = load_file(&input);
                let md5 = bytes_to_md5_string(&content[0..16]);

                println!("File md5: {:?}", md5);

                let mut blocks = Vec::new();
                let mut key_size = 0;
                for server in remote_servers.iter() {
                    let mut stream = TcpStream::connect(server).unwrap();
                    let mut buffer = vec![];
                    buffer.push(b'-');
                    buffer.extend_from_slice(&content[0..16]);

                    println!("Buffer: {:?}", buffer);

                    stream.write_all(&mut buffer).unwrap();

                    println!("\tSend request key op");

                    // Reuse the buffer
                    buffer.clear();

                    let n = stream.read_to_end(&mut buffer).unwrap();
                    if n > 0 {
                        let opcode = buffer[0];
                        match opcode {
                            b'+' => {
                                let part_id = buffer[1];
                                let aes_key_size = buffer[2];

                                let part_aes_key = &buffer[3..];
                                key_size += aes_key_size;
                                let block = Block::new(part_id, &md5, &part_aes_key.into(), None);

                                blocks.push(block);
                            }
                            b'-' => {
                                panic!("Can't decrypt due to time");
                            }
                            _ => {
                                println!("Unknown opcode for: {}", opcode);
                            }
                        }
                    }
                }

                if key_size != 16 {
                    panic!("Key size is not equal to 16, panic!");
                }

                // Sort the aes key packet
                blocks.sort_by(|a, b| a.part_id.partial_cmp(&b.part_id).unwrap());
                println!("{:?}", blocks);

                let mut aes_key = vec![];
                for block in blocks.iter() {
                    aes_key.extend_from_slice(&block.part_aes);
                }

                let content = &content[16..];
                let decrypted_content = aes_dec_ecb(content, &aes_key, Some("PKCS7")).unwrap();

                let raw_filename: Vec<_> = input.split('.').collect();

                let mut new_file =
                    File::create(format!("dec_{}.{}", raw_filename[0], raw_filename[1])).unwrap();

                new_file.write_all(&decrypted_content).unwrap();
            }
            Encrypt {
                input,
                password,
                servers,
                time,
            } => {
                if servers.is_empty() {
                    panic!("The len of servers must not be zero");
                }

                if password.is_empty() {
                    panic!("You must provide the password");
                }

                let content = load_file(&input);

                let content_md5 = file_md5(&content);

                let bcrypted_password = bcrypt_password(&password);
                encrypt_file(&input, &content, &content_md5, &bcrypted_password);

                let remote_servers = check_parse_servers(&servers);
                distribute_key(&content_md5, &bcrypted_password, &time, &remote_servers);
            }
        },
        Server { port } => {
            let tcp_listener =
                TcpListener::bind(format!("0.0.0.0:{}", port.unwrap_or_default())).unwrap();

            let blocks = Arc::new(Mutex::new(Vec::new()));

            for incoming in tcp_listener.incoming() {
                let blocks = blocks.clone();
                thread::spawn(move || {
                    // Why I unwrap stream result in another thread?
                    let mut stream = incoming.unwrap();
                    println!("Client from {:?}", stream.peer_addr().unwrap());

                    let mut op_code = [0u8; 1];
                    stream.read_exact(&mut op_code).unwrap();
                    let op_code = op_code[0];

                    match op_code {
                        b'+' => {
                            println!("Matched Opcode: Receive key");
                            let mut buffer = vec![];
                            stream.read_to_end(&mut buffer).unwrap();

                            let part_id = buffer[0];
                            let aes_key_size = buffer[1];

                            let part_aes_key = &buffer[2..2 + aes_key_size as usize];
                            let md5 =
                                &buffer[2 + aes_key_size as usize..2 + aes_key_size as usize + 16];

                            let time = &buffer[2 + aes_key_size as usize + 16..];
                            let time = String::from_utf8_lossy(time).into_owned();

                            let md5 = bytes_to_md5_string(md5);

                            println!(
                                "Received {:?} part of {:?}, dec at: {:?}: {:?}",
                                part_id, md5, time, part_aes_key
                            );

                            let block = Block::new(part_id, &md5, &part_aes_key.into(), Some(time));

                            let mut blocks = blocks.lock().unwrap();
                            blocks.push(block);

                            println!("Blocks: {:?}", blocks);
                        }
                        b'-' => {
                            println!("Matched Opcode: Request key");
                            let mut buffer = [0u8; 16];
                            stream.read_exact(&mut buffer).unwrap();

                            println!("\tBuffer: {:?}", buffer);

                            let md5 = bytes_to_md5_string(&buffer);

                            println!("Block MD5: {}", md5);

                            let mut is_find = false;
                            for block in blocks.lock().unwrap().iter() {
                                if block.md5.eq(&md5) {
                                    let mut buffer = vec![];

                                    println!("Found key file for {}", md5);

                                    let timestamp: u64 =
                                        block.time.as_ref().unwrap().parse().unwrap();
                                    if current_unix_timestamp().unwrap() < timestamp {
                                        println!(
                                            "Current timestamp must large than {}",
                                            block.time.as_ref().unwrap()
                                        );
                                        buffer.push(b'-');
                                        stream.write_all(&mut buffer).unwrap();
                                        break;
                                    }

                                    buffer.push(b'+');
                                    buffer.push(block.part_id);
                                    buffer.push(block.part_aes.len() as u8);
                                    buffer.extend_from_slice(&block.part_aes);

                                    stream.write_all(&mut buffer).unwrap();

                                    is_find = true;
                                    break;
                                }
                            }

                            if !is_find {
                                stream.write_all(&[b'-']).unwrap();
                            }
                        }
                        _ => {
                            println!("Unknown Opcode: {:?}", op_code);
                        }
                    }
                });
            }
        }
    }
}
