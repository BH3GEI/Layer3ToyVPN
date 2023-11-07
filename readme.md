# README

## VPN Server

This project is a Virtual Private Network (VPN) server that operates at the network layer (Layer 3) of the OSI model. It uses a TUN device to encapsulate and decapsulate IP packets, providing a secure and private connection between two networks.

The VPN server reads data from a UDP socket and writes it to a TUN device, or reads data from the TUN device and sends it via the UDP socket. This creates a virtual network connection between two networks.

### Features

- Works at the network layer (Layer 3), handling IP packets.
- Uses TUN device for data encapsulation and decapsulation.
- Supports multiple sessions.
- Session expiration handling.
- Simple authentication mechanism.

### Usage

To use the VPN server, simply run the Python script on your server:

```bash
python3 vpn_server.py
```

Make sure to replace the `PASSWORD` and `BIND_ADDRESS` constants in the script with your own values.

## Dependencies

- Python 3
- Linux system with `/dev/net/tun` support

---
