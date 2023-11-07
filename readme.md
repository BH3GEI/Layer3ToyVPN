# VPN Server and Client

This repository contains a simple implementation of a VPN server and client using Python.

## Description

Both the server and the client utilize the UDP protocol for communication. The server supports multiple clients and can handle incoming connections asynchronously. The client can establish a connection with the server and maintain it using keepalive messages.

## Requirements

- Python 3.x
- Linux environment (due to the usage of `/dev/net/tun`)

## Usage

### Server

1. Clone the repository.
2. Navigate to the server's directory.
3. Run the server script: `python server.py`.

### Client

1. Clone the repository.
2. Navigate to the client's directory.
3. Run the client script with the server's address and port as arguments: `python client.py [remote_ip] [remote_port]`.

## Configuration

Both the server and client scripts can be configured by modifying the constants at the beginning of the scripts. Important parameters include:

- `PASSWORD`: The password for establishing a connection between the client and the server.
- `BIND_ADDRESS`: The IP address and port the server should listen on.
- `NETWORK`: The network range for the VPN.
- `BUFFER_SIZE`: The maximum size of the packets that can be sent or received.
- `MTU`: Maximum Transmission Unit.
- `KEEPALIVE`: The interval at which the client sends keepalive messages to the server.

## Disclaimer

This is a simple implementation meant for educational purposes and should not be used in production as it may have security vulnerabilities.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
