# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 443
# Parameter to bind a socket to a device, using SO_BINDTODEVICE
# Only root can set this option
# If the name is an empty string or None, the interface is chosen when
# a routing decision is made
# OUTGOING_INTERFACE = "eth0"
OUTGOING_INTERFACE = ""

#
# Whitelist Domain
# Hanya domain yang terdaftar di bawah yang boleh diakses.
# Subdomain otomatis diizinkan (e.g. mail.google.com -> google.com).
#
WHITELISTED_DOMAINS = {
    'google.com',
    'youtube.com',
    'youtube-nocookie.com',
    'googleapis.com',
    'gstatic.com',
    'ggpht.com',
    'live.com',
    'msftauth.net',
    'microsoftonline.com',
    'hsprotect.net',
    'crcldu.com',
    'microsoft.com',
    'perimeterx.net',
    'goorm.io',
    'channel.io',
    'px-cloud.net',
    'name-fake.com',
    'office.net',
    'sentry.io',

    # GitHub / GitLab
    'github.com',
    'githubusercontent.com',
    'githubassets.com',
    'gitlab.com',

    # AWS / Cloud
    'amazonaws.com',
    'aws.dev',
    'amazon.com',
    'cloudfront.net',
    'execute-api.us-east-1.amazonaws.com',
    'execute-api.us-east-2.amazonaws.com',
    'sagemaker.aws',
    'studiolab.sagemaker.aws',

    # Nopecha / Captcha Services
    'nopecha.com',
    'awswaf.com',
    'captcha.awswaf.com',

    # IP Check
    'whoer.net',
    'ifconfig.me',
    'cloudflare.com',
    'shields.io',
    'jsdelivr.net',
    'ipinfo.io',

    # Local / Custom
    'polresacehbarat.com',
    'cloudsigma.com',
    'cloudadore.com',
    'generator.email',
    'emailfake.com',
    'arkain.io',
    '2fa.live',
}

#
# Blocked Ports
# Koneksi ke port berikut akan langsung ditolak.
#
BLOCKED_PORTS = {21, 22, 23, 25, 43, 110, 143, 465, 587, 993, 995, 3389, 5900}

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'


def is_domain_allowed(host):
    """
    Periksa apakah host diizinkan berdasarkan whitelist domain.
    - Jika host berupa IP address, langsung izinkan.
    - Jika host berupa domain, cocokkan dengan whitelist (termasuk subdomain).
    """
    if isinstance(host, bytes):
        host = host.decode('utf-8', errors='ignore')
    host = host.strip().lower()
    # Cek apakah IP address (IPv4)
    try:
        socket.inet_aton(host)
        return True  # IP address diizinkan
    except socket.error:
        pass
    # Cocokkan domain dengan whitelist
    for allowed in WHITELISTED_DOMAINS:
        allowed = allowed.lower()
        if host == allowed or host.endswith('.' + allowed):
            return True
    return False


def is_port_blocked(port):
    """
    Periksa apakah port termasuk dalam daftar block.
    """
    return port in BLOCKED_PORTS


class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def proxy_loop(socket_src, socket_dst):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def request_client(wrapper):
    """ Client request details """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else:
        return False
    print("[REQ] {}:{}".format(dst_addr if isinstance(dst_addr, str) else dst_addr.decode('utf-8', errors='ignore'), dst_port))
    return (dst_addr, dst_port)


def request(wrapper):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = request_client(wrapper)
    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'

    if dst:
        dst_addr, dst_port = dst
        host_str = dst_addr if isinstance(dst_addr, str) else dst_addr.decode('utf-8', errors='ignore')

        # === CEK BLOCKED PORT ===
        if is_port_blocked(dst_port):
            print("[BLOCKED PORT] {}:{}".format(host_str, dst_port))
            rep = b'\x02'  # Connection not allowed by ruleset
            reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
            try:
                wrapper.sendall(reply)
            except socket.error:
                pass
            if wrapper != 0:
                wrapper.close()
            return

        # === CEK WHITELIST DOMAIN ===
        if not is_domain_allowed(dst_addr):
            print("[BLOCKED DOMAIN] {}:{}".format(host_str, dst_port))
            rep = b'\x02'  # Connection not allowed by ruleset
            reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
            try:
                wrapper.sendall(reply)
            except socket.error:
                pass
            if wrapper != 0:
                wrapper.close()
            return

        socket_dst = connect_to_dst(dst_addr, dst_port)
        if socket_dst == 0:
            rep = b'\x01'
        else:
            rep = b'\x00'
            bnd = socket.inet_aton(socket_dst.getsockname()[0])
            bnd += pack(">H", socket_dst.getsockname()[1])
    else:
        socket_dst = 0
        rep = b'\x01'

    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':
        proxy_loop(wrapper, socket_dst)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    return True


def connection(wrapper):
    """ Function run by a thread """
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock


def bind_port(sock):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


def main():
    """ Main function """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    print("[*] SOCKS5 Proxy (No-Auth) running on {}:{}".format(LOCAL_ADDR, LOCAL_PORT))
    print("[*] Whitelist: {} domains | Blocked ports: {}".format(
        len(WHITELISTED_DOMAINS), sorted(BLOCKED_PORTS)))
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
