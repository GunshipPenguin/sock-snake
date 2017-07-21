import socket
import threading
import select
import sys
import struct
import ipaddress
import const

def build_socks_reply(cd, dst_port=0x0000, dst_ip='0.0.0.0'):
    dst_ip_bytes = ipaddress.IPv4Address(dst_ip).packed
    return struct.pack('>BBHL', const.SERVER_VN, cd, dst_port, struct.unpack('>L', dst_ip_bytes)[0])

class ClientRequest:
    def __init__(self, data):
        '''Construct a new client request from the given binary data'''
        self.invalid = False

        # Client requests must be at least 9 bytes to hold all necessary data
        if len(data) < 9:
            self.invalid = True
            return

        # Extract everything minus the userid from data
        vn, cd, dst_port, dst_ip = struct.unpack('>BBHL', data[:8])

        # Version number
        if (vn != const.CLIENT_VN):
            self.invalid = True

        # SOCKS command code (CD)
        self.cd = cd
        if (self.cd != const.REQUEST_CD_CONNECT and self.cd != const.REQUEST_CD_BIND):
            self.invalid = True

        # Destination port
        self.dst_port = dst_port

        # Destination IP (Parse as a dotted quad string)
        self.dst_ip = ipaddress.IPv4Address(dst_ip).exploded

        # UserId
        self.userid = data[8:-1] # Strip the null byte at the end

    def isInvalid(self):
        return self.invalid

class RelayThread(threading.Thread):
    def __init__(self, s1, s2):
        self.s1 = s1
        self.s2 = s2
        threading.Thread.__init__(self)

    def _close_sockets(self):
        self.s1.close()
        self.s2.close()

    def run(self):
        while True:
            ready, _, err = select.select([self.s1, self.s2], [], [self.s1, self.s2])

            # Handle socket errors
            if err:
                self._close_sockets()
                return

            for s in ready:
                try:
                    data = s.recv(const.BUFSIZE)
                except ConnectionResetError:
                    # Connection reset by either s1 or s2, close sockets and return
                    self._close_sockets()
                    return

                if not data:
                    # Connection gracefully closed, close sockets and return
                    self._close_sockets()
                    return

                if s is self.s1:
                    self.s2.sendall(data)
                else:
                    self.s1.sendall(data)

class BindThread(threading.Thread):
    def __init__(self, clientRequest, client_conn):
        self.clientRequest = clientRequest
        self.client_conn = client_conn
        threading.Thread.__init__(self)

    def run(self):
        try:
            # Open a listening socket on the specified port
            server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_s.bind(('0.0.0.0', 0))
            server_s.settimeout(SOCKS_TIMEOUT)
            ip, port = server_s.getsockname()
            server_s.listen(1)

            # Inform client of open socket
            self.client_conn.sendall(build_socks_reply(const.RESPONSE_CD_REQUEST_GRANTED, port, ip))

            # Wait for the application server to accept the connection
            server_conn, addr = server_s.accept()
        except:
            # Something went wrong, inform the client and return
            self.client_conn.sendall(build_socks_reply(const.RESPONSE_CD_REQUEST_REJECTED))
            self.client_conn.close()
            return

        # Application server connected, inform client
        self.client_conn.sendall(build_socks_reply(const.RESPONSE_CD_REQUEST_GRANTED))

        # Relay traffic between client_conn and server_conn
        relayThread = RelayThread(self.client_conn, server_conn)
        relayThread.daemon = True
        relayThread.start()

class SocksProxy:
    def __init__(self, port, bufsize, backlog):
        self._host = '0.0.0.0'
        self._port = port
        self._bufsize = bufsize
        self._backlog = backlog

    def start(self):
        print ('Listening on ' + self._host + ':' + str(self._port))

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
            except Exception as e:
                print(e)
                s.close()
                sys.exit(1)

    def _process_connect_request(self, clientRequest, clientConn):
        serverConn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverConn.settimeout(const.SOCKS_TIMEOUT)

        try:
            serverConn.connect((clientRequest.dst_ip, clientRequest.dst_port))
        except socket.timeout:
            # Connection to specified host timed out, reject the SOCKS request
            serverConn.close()
            clientConn.send(build_socks_reply(const.RESPONSE_CD_REQUEST_REJECTED))
            clientConn.close()

        clientConn.send(build_socks_reply(const.RESPONSE_CD_REQUEST_GRANTED))

        relayThread = RelayThread(clientConn, serverConn)
        relayThread.daemon = True
        relayThread.start()

    def _process_bind_request(self, clientRequest, clientConn):
        bindThread = BindThread(clientRequest, clientConn)
        bindThread.daemon = True
        bindThread.start()

    def _process_request(self, data, clientConn):
        clientRequest = ClientRequest(data)

        # Handle invalid requests
        if clientRequest.isInvalid():
            clientConn.send(build_socks_reply(const.RESPONSE_CD_REQUEST_REJECTED))
            clientConn.close()
            return

        if clientRequest.cd == const.REQUEST_CD_CONNECT:
            self._process_connect_request(clientRequest, clientConn)
        else:
            self._process_bind_request(clientRequest, clientConn)

if __name__ == '__main__':
    proxy = SocksProxy(const.PORT, const.BUFSIZE, const.BACKLOG)
    proxy.start()
