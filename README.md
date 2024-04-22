## TLE Server

Start a server at port 8002, and wating for client to transform packet.

```bash
cargo run -- server -p <PORT>
```

## TLE Client

### Encrypt

```bash
cargo run -- client encrypt -i <INPUT_FILE_NAME> -s <IP:PORT> -s <IP:PORT> -p <YOUR_PASSWORD>
```

### Decrypt
```bash
cargo run -- client decrypt -i <INPUT_FILE_NAME> -s <IP:PORT> -s <IP:PORT>
```