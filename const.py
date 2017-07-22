# TCP port to listen on for SOCKS4 connections by default
PORT = 1080

# Buffer size to use when calling socket.recv()
BUFSIZE = 4096

# Number of connections to keep in backlog when calling socket.listen()
BACKLOG = 10

# Timeout (in seconds) for connecting to application servers via a CONNECT request
# or waiting for a connection via a BIND request
SOCKS_TIMEOUT = 20

# Version code in server responses (Should always be 0 as specified in the SOCKS4 spec)
SERVER_VN = 0x00

# Version number specified by clients when connecting (Should always be 4 as specified in the SOCKS4 spec)
CLIENT_VN = 0x04

# SOCKS request codes as specified in the SOCKS4 spec
REQUEST_CD_CONNECT = 0x01
REQUEST_CD_BIND = 0x02

# SOCKS response codes as specified in the SOCKS4 spec
RESPONSE_CD_REQUEST_GRANTED = 90
RESPONSE_CD_REQUEST_REJECTED = 91
