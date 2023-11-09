# Toy VPN Project

This project consists of three Python scripts that implement a basic VPN (Virtual Private Network). The VPN is created using a TUN interface, a network layer device that operates on layer 3 packets like IP packets. TUN interfaces are software loopback mechanisms that can be controlled by user-space programs.

## Script Overview

1. **ToyVPN.py:** This script can function as both a VPN server and a client. It can establish a VPN connection with a remote server or listen for incoming connections as a server. The script includes functions for encoding and decoding data using Base64. I tried to bypass the GFW using this technique, but my server quickly got banned for transferring big amount of data.

2. **ServerVPN.py:** This script is the server-side component of the VPN. It listens for incoming VPN connections, authenticates clients, and maintains the VPN sessions.

3. **ClientVPN.py:** This script is the client-side component. It is used to establish a VPN connection with the server. It sends a keepalive message to the server every few seconds to maintain the connection.

## Usage

To use these scripts, you need to run them with specific command-line arguments. 

For the `ToyVPN.py` script, run:

```
sudo python3 ToyVPN.py client [remote_ip] [remote_port]
```

Or

```
sudo python3 ToyVPN.py server
```


For the `ServerVPN.py` script, just run:

```
sudo python3 ServerVPN.py
```

This script doesn't require any command-line arguments. It will start a VPN server that listens for incoming connections.

For the `ClientVPN.py` script, run:

```
sudo python3 ClientVPN.py [remote_ip] [remote_port]
```

The `[remote_ip]` and `[remote_port]` arguments specify the VPN server's IP address and port.

## Configuration

The scripts use a password for authentication, which is defined as `PASSWORD` in the scripts. It's currently set to `b'4fb88ca224e'`. If you want to use a different password, you need to change this value in all three scripts.

The VPN network is defined by the `NETWORK` variable in the scripts, which is currently set to '10.0.0.0/24'. The `IPRANGE` variable is a list of the IP addresses in this network.

The server binds to the IP address and port specified by `BIND_ADDRESS`, which is currently set to '0.0.0.0',2003. This means that it listens on all available network interfaces and port 2003.

## Note

These scripts are basic implementations of a VPN and are likely not suitable for use in a production environment. They do not include many features that a full-featured VPN would have, such as encryption, compression, or support for multiple concurrent connections. However, they can serve as a starting point for learning about VPNs and network programming in Python.
