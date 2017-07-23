#!/usr/bin/env python3
import socket
import threading
import select
import sys
import struct
import ipaddress
import argparse

import const


def build_socks_reply(cd, dst_port=0x0000, dst_ip='0.0.0.0'):
    '''
    Build a SOCKS4 reply with the specified reply code, destination port and
    destination ip.
    '''
    dst_ip_bytes = ipaddress.IPv4Address(dst_ip).packed
    dst_ip_raw, = struct.unpack('>L', dst_ip_bytes)

    return struct.pack('>BBHL', const.SERVER_VN, cd, dst_port, dst_ip_raw)


class ClientRequest:
    '''Represents a client SOCKS4 request'''

    def __init__(self, data):
        '''Construct a new ClientRequeset from the given raw SOCKS request'''
        self.invalid = False

        # Client requests must be at least 9 bytes to hold all necessary data
        if len(data) < 9:
            self.invalid = True
            return

        # Version number (VN)
        self.parse_vn(data)

        # SOCKS command code (CD)
        self.parse_cd(data)

        # Destination port
        self.parse_dst_port(data)

        # Destination IP / Domain name (if specified)
        self.parse_ip(data)

        # Userid
        self.parse_userid(data)

    @classmethod
    def parse_fixed(cls, data):
        '''Parse and return the fixed-length part of a SOCKS request

        Returns a tuple containing (vn, cd, dst_port, dst_ip) given the raw
        socks request
        '''
        return struct.unpack('>BBHL', data[:8])

    def parse_vn(self, data):
        '''Parse and store the version number given the raw SOCKS request'''
        vn, _, _, _ = ClientRequest.parse_fixed(data)
        if (vn != const.CLIENT_VN):
            self.invalid = True

    def parse_dst_port(self, data):
        '''Parse and store the destination port given the raw SOCKS request'''
        _, _, dst_port, _ = ClientRequest.parse_fixed(data)
        self.dst_port = dst_port

    def parse_cd(self, data):
        '''Parse and store the request code given the raw SOCKS request'''
        _, cd, _, _ = ClientRequest.parse_fixed(data)
        if (cd == const.REQUEST_CD_CONNECT or cd == const.REQUEST_CD_BIND):
            self.cd = cd
        else:
            self.invalid = True

    def parse_ip(self, data):
        '''Parse and store the destination ip given the raw SOCKS request

        If the IP is of the form 0.0.0.(1-255), attempt to resolve the domain
        name specified, then store the resolved ip as the destination ip.
        '''
        _, _, _, dst_ip = ClientRequest.parse_fixed(data)

        ip = ipaddress.IPv4Address(dst_ip)
        o1, o2, o3, o4 = ip.packed

        # Invalid ip address specifying that we must resolve the domain
        # specified in data (As specified in SOCKS4a)
        if (o1, o2, o3) == (0, 0, 0) and o4 != 0:
            try:
                # Variable length part of the request containing the userid
                # and domain (8th byte onwards)
                userid_and_domain = data[8:]

                # Extract the domain to resolve
                _, domain, _ = userid_and_domain.split(b'\x00')

            except ValueError:
                # Error parsing request
                self.invalid = True
                return

            try:
                resolved_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                # Domain name not found
                self.invalid = True
                return

            self.dst_ip = resolved_ip

        else:
            self.dst_ip = ip.exploded

    def parse_userid(self, data):
        '''Parse and store the userid given the raw SOCKS request'''
        try:
            index = data.index(b'\x00')
            self.userid = data[8:index]
        except ValueError:
            self.invalid = True
        except IndexError:
            self.invalid = True

    def isInvalid(self):
        '''Returns true if this request is invalid, false otherwise'''
        return self.invalid


class RelayThread(threading.Thread):
    '''Thread object that relays traffic between two hosts'''

    def __init__(self, s1, s2):
        '''Construct a new RelayThread to relay traffic between the 2 sockets
        specified'''
        self._s1 = s1
        self._s2 = s2
        threading.Thread.__init__(self)

    def _close_sockets(self):
        '''Close both sockets in this Relay Thread'''
        self._s1.close()
        self._s2.close()

    def run(self):
        '''Start relaying traffic between the two sockets specified

        Traffic is relayed until one socket is closed or encounters an error,
        at which point both sockets will be closed and the thread will
        terminate.
        '''
        while True:
            ready, _, err = select.select(
                [self._s1, self._s2], [], [self._s1, self._s2])

            # Handle socket errors
            if err:
                self._close_sockets()
                return

            for s in ready:
                try:
                    data = s.recv(const.BUFSIZE)
                except ConnectionResetError:
                    # Connection reset by either s1 or s2, close sockets and
                    # return
                    self._close_sockets()
                    return

                if not data:
                    # Connection gracefully closed, close sockets and return
                    self._close_sockets()
                    return

                if s is self._s1:
                    self._s2.sendall(data)
                else:
                    self._s1.sendall(data)


class BindThread(threading.Thread):
    '''Thread object that sets up a SOCKS BIND request'''

    def __init__(self, client_request, client_conn):
        '''Create a new BIND thread for the given ClientRequest and connection
        to the client'''
        self._client_request = client_request
        self._client_conn = client_conn
        threading.Thread.__init__(self)

    def run(self):
        '''Attempt a SOCKS bind operation and relay traffic if successful'''
        try:
            # Open a listening socket on an open port
            server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_s.bind(('0.0.0.0', 0))
            server_s.settimeout(const.SOCKS_TIMEOUT)
            ip, port = server_s.getsockname()
            server_s.listen(1)

            # Inform client of open socket
            self._client_conn.sendall(build_socks_reply(
                const.RESPONSE_CD_REQUEST_GRANTED, port, ip))

            # Wait for the application server to accept the connection
            server_conn, addr = server_s.accept()
        except:
            # Something went wrong, inform the client and return
            self._client_conn.sendall(
                build_socks_reply(
                    const.RESPONSE_CD_REQUEST_REJECTED))
            self._client_conn.close()
            return

        # Application server connected, inform client
        self._client_conn.sendall(
            build_socks_reply(
                const.RESPONSE_CD_REQUEST_GRANTED))

        # Relay traffic between client_conn and server_conn
        relay_thread = RelayThread(self._client_conn, server_conn)
        relay_thread.daemon = True
        relay_thread.start()


class SocksProxy:
    '''A SOCKS4a Proxy'''

    def __init__(self, port):
        '''Create a new SOCKS4 proxy on the specified port'''
        self._host = '0.0.0.0'
        self._port = port
        self._bufsize = const.BUFSIZE
        self._backlog = const.BACKLOG

    def start(self):
        '''Start listening for SOCKS connections, blocking'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self._host, self._port))
        s.listen(self._backlog)

        while True:
            try:
                conn, addr = s.accept()
                data = conn.recv(self._bufsize)

                # Got a connection, handle it with process_request()
                self._process_request(data, conn)
            except KeyboardInterrupt as ki:
                s.close()
                print('Caught KeyboardInterrupt, exiting')
                sys.exit(0)

    def _process_connect_request(self, client_request, client_conn):
        '''Process a SOCKS CONNECT request'''
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_conn.settimeout(const.SOCKS_TIMEOUT)

        try:
            server_conn.connect(
                (client_request.dst_ip, client_request.dst_port))
        except socket.timeout:
            # Connection to specified host timed out, reject the SOCKS request
            server_conn.close()
            client_conn.send(
                build_socks_reply(
                    const.RESPONSE_CD_REQUEST_REJECTED))
            client_conn.close()

        client_conn.send(build_socks_reply(const.RESPONSE_CD_REQUEST_GRANTED))

        relay_thread = RelayThread(client_conn, server_conn)
        relay_thread.daemon = True
        relay_thread.start()

    def _process_bind_request(self, client_request, client_conn):
        '''Process a SOCKS BIND request'''
        bind_thread = BindThread(client_request, client_conn)
        bind_thread.daemon = True
        bind_thread.start()

    def _process_request(self, data, client_conn):
        '''Process a general SOCKS request'''
        client_request = ClientRequest(data)

        # Handle invalid requests
        if client_request.isInvalid():
            client_conn.send(
                build_socks_reply(
                    const.RESPONSE_CD_REQUEST_REJECTED))
            client_conn.close()
            return

        if client_request.cd == const.REQUEST_CD_CONNECT:
            self._process_connect_request(client_request, client_conn)
        else:
            self._process_bind_request(client_request, client_conn)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='SOCKS4a Proxy Implementation',
        epilog='Homepage: https://github.com/GunshipPenguin/sock-snake',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        '--port',
        type=int,
        help='port to listen for incoming SOCKS requests on',
        action='store',
        default=const.PORT)

    args = parser.parse_args()

    print('Listening on port', str(args.port))

    proxy = SocksProxy(args.port)
    proxy.start()
