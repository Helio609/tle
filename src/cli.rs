use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    author = "Zijun Fu",
    version = "0.1.0",
    about = "This is a TLE based server/client"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Start a server")]
    Server {
        #[arg(
            short,
            long,
            help = "The port to start server, empty will auto gen a port"
        )]
        port: Option<u16>,
    },
    #[command(about = "Start a client")]
    Client {
        #[command(subcommand)]
        command: ClientSubcommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClientSubcommand {
    Encrypt {
        #[arg(short, long, help = "file path")]
        input: String,
        #[arg(short, long, help = "the string to generate a AES key")]
        password: String,
        #[arg(
            short,
            long = "server",
            help = "Server address to store the part of key"
        )]
        servers: Vec<String>,
        #[arg(short, long, help = "Exact time to decrypt")]
        time: String,
    },
    Decrypt {
        #[arg(short, long, help = "file path")]
        input: String,
        #[arg(
            short,
            long = "server",
            help = "Server address to store the part of key"
        )]
        servers: Vec<String>,
    },
}
