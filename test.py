import unittest
import threading
import socksnake
import socket
import time
import ipaddress
import struct

import const


def start_mock_server(port, data):
    '''
    Start a mock server listening locally on the specified port. Upon receiving
    any data over a TCP connection, it will send the specified data, close the
    connection and return.
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.bind(('0.0.0.0', port))
    s.listen(1)

    conn, addr = s.accept()

    # Upon incoming data, send data and exit
    incoming_data = conn.recv(4096)
    conn.send(data)

    s.close()
    conn.close()


def build_socks4_ip_request(cd, dst_port, dst_ip):
    dst_ip_bytes = ipaddress.IPv4Address(dst_ip).packed
    dst_ip_raw = struct.unpack('>L', dst_ip_bytes)[0]

    return struct.pack('>BBHLB', 4, cd, dst_port, dst_ip_raw, 0x00)


def build_socks4_dns_request(cd, dst_port, domain):
    # 0.0.0.1 = invalid IP specifying a dns lookup
    dst_ip, = struct.unpack('>L', b'\x00\x00\x00\x01')

    request = struct.pack('>BBHLB', 4, cd, dst_port, dst_ip, 0x00)
    request += domain + b'\x00'

    return request


def parse_socks4_reply(data):
    '''
    Returns a tuple containing (vn, cd, dst_port, dst_ip) given socks response
    data.
    '''
    vn, cd, dst_port, dst_ip = struct.unpack('>BBHL', data)

    dst_ip = ipaddress.IPv4Address(dst_ip).exploded

    return (vn, cd, dst_port, dst_ip)


class SocksProxyTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start a SOCKS proxy for testing
        proxy = socksnake.SocksProxy(const.PORT, const.BUFSIZE, const.BACKLOG)

        proxy_server_thread = threading.Thread(target=proxy.start)
        proxy_server_thread.daemon = True
        proxy_server_thread.start()

        # Ensure that the socks proxy is up before returning by trying to
        # connect to it repeatedly until we succeed or hit a 5 second timeout
        start_time = time.time()
        connect_test_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connected = False

        while not connected or (time.time() - start_time) > 5:
            try:
                connect_test_s.connect(('0.0.0.0', const.PORT))
                connect_test_s.close()
                connected = True
            except ConnectionRefusedError:
                pass

    def test_socks_connect(self):
        # Mock HTTP response
        http_response = b'HTTP/1.1 302 Found'

        # Create a mock webserver on port 8080
        web_server = threading.Thread(
            target=start_mock_server, args=(8080, http_response))
        web_server.daemon = True
        web_server.start()

        # Set up a socket and connect to the SOCKS server
        request_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request_s.connect(('0.0.0.0', const.PORT))

        # Attempt to send a SOCKS CONNECT request to the server
        socks_request = build_socks4_ip_request(
            const.REQUEST_CD_CONNECT, 8080, '0.0.0.0')
        request_s.send(socks_request)

        # Get and verify the SOCKS reply
        socks_reply = request_s.recv(const.BUFSIZE)
        vn, cd, _, _ = parse_socks4_reply(socks_reply)
        self.assertEqual(cd, const.RESPONSE_CD_REQUEST_GRANTED)
        self.assertEqual(vn, const.SERVER_VN)

        # Send an HTTP GET request to the mock server via the SOCKS proxy
        request_s.send(b'GET / HTTP/1.1')
        http_data = request_s.recv(const.BUFSIZE)
        self.assertEqual(http_response, http_data)

        request_s.close()

    def test_socks_bind(self):
        # Set up a socket and connect to the SOCKS server
        client_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_s.connect(('0.0.0.0', const.PORT))

        # Attempt to send a SOCKS BIND request to the server for a primary
        # connection to 0.0.0.0:8080
        socks_request = build_socks4_ip_request(
            const.REQUEST_CD_BIND, 8080, '0.0.0.0')
        client_s.send(socks_request)

        # Get and verify the SOCKS reply
        socks_reply = client_s.recv(const.BUFSIZE)
        vn, cd, dst_port, dst_ip = parse_socks4_reply(socks_reply)
        self.assertEqual(cd, const.RESPONSE_CD_REQUEST_GRANTED)
        self.assertEqual(vn, const.SERVER_VN)
        self.assertIn(dst_port, range(1, 2**16))
        self.assertEqual(dst_ip, '0.0.0.0')

        # Mock an appliction server and connect it to the SOCKS server
        app_server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        app_server_s.connect((dst_ip, dst_port))

        # Verify that a second SOCKS response was received by the client
        socks_reply = client_s.recv(const.BUFSIZE)
        vn, cd, _, _ = parse_socks4_reply(socks_reply)
        self.assertEqual(cd, const.RESPONSE_CD_REQUEST_GRANTED)
        self.assertEqual(vn, const.SERVER_VN)

        # Send some data from the application server to the client and verify
        # that it was received
        test_data = b'Some data being sent from server to client'
        app_server_s.send(test_data)
        data = client_s.recv(const.BUFSIZE)
        self.assertEqual(data, test_data)

        # Send some data from the client to the application server and verify
        # that it was received
        test_data = b'Some data being sent from client to server'
        client_s.send(test_data)
        data = app_server_s.recv(const.BUFSIZE)
        self.assertEqual(data, test_data)

        # Close the application server and client connections
        app_server_s.close()
        client_s.close()

    def test_socks_resolve_dns(self):
        # Set up a socket and connect to the SOCKS server
        request_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request_s.connect(('0.0.0.0', const.PORT))

        # Attempt to send a SOCKS CONNECT request to the server
        # for google.com:443
        # I'm working under the assumption here that google.com is always
        # going to resolve
        socks_request = build_socks4_dns_request(
            const.REQUEST_CD_CONNECT, 443, b'google.com')
        request_s.send(socks_request)

        # Get and verify the SOCKS reply
        socks_reply = request_s.recv(const.BUFSIZE)
        vn, cd, _, _ = parse_socks4_reply(socks_reply)
        self.assertEqual(cd, const.RESPONSE_CD_REQUEST_GRANTED)
        self.assertEqual(vn, const.SERVER_VN)

        request_s.close()


if __name__ == '__main__':
    unittest.main()
