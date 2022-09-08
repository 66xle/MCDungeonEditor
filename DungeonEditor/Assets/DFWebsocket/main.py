#!/usr/bin/python
import json

import threading
import socket
import errno
import selectors
from threading import Lock
import array
import os
import struct
import sys

__version__ = "1.2.1"

def sendItem():

    with open('D:/robbo/Unity Projects/DungeonEditor/Assets/DFWebsocket/nbt.txt') as f:
        text = f.read()


    data = {}
    data['type'] = 'nbt'
    data['data'] = text
    # data['data'] = json_template
    data['source'] = 'websocket test'
    json_data = json.dumps(data)


    ws = create_connection("ws://localhost:31371")
    print("Sending 'Hello, World'...")

    ws.send(json_data)
    print("Sent")
    print("Receiving...")
    result =  ws.recv()
    print("Received '%s'" % result)
    ws.close()

try:
    # If wsaccel is available, use compiled routines to mask data.
    # wsaccel only provides around a 10% speed boost compared
    # to the websocket-client _mask() implementation.
    # Note that wsaccel is unmaintained.
    from wsaccel.xormask import XorMaskerSimple

    def _mask(_m, _d):
        return XorMaskerSimple(_m).process(_d)

except ImportError:
    # wsaccel is not available, use websocket-client _mask()
    native_byteorder = sys.byteorder

    def _mask(mask_value, data_value):
        datalen = len(data_value)
        data_value = int.from_bytes(data_value, native_byteorder)
        mask_value = int.from_bytes(mask_value * (datalen // 4) + mask_value[: datalen % 4], native_byteorder)
        return (data_value ^ mask_value).to_bytes(datalen, native_byteorder)

__all__ = [
    'ABNF', 'continuous_frame', 'frame_buffer',
    'STATUS_NORMAL',
    'STATUS_GOING_AWAY',
    'STATUS_PROTOCOL_ERROR',
    'STATUS_UNSUPPORTED_DATA_TYPE',
    'STATUS_STATUS_NOT_AVAILABLE',
    'STATUS_ABNORMAL_CLOSED',
    'STATUS_INVALID_PAYLOAD',
    'STATUS_POLICY_VIOLATION',
    'STATUS_MESSAGE_TOO_BIG',
    'STATUS_INVALID_EXTENSION',
    'STATUS_UNEXPECTED_CONDITION',
    'STATUS_BAD_GATEWAY',
    'STATUS_TLS_HANDSHAKE_ERROR',
]

# closing frame status codes.
STATUS_NORMAL = 1000
STATUS_GOING_AWAY = 1001
STATUS_PROTOCOL_ERROR = 1002
STATUS_UNSUPPORTED_DATA_TYPE = 1003
STATUS_STATUS_NOT_AVAILABLE = 1005
STATUS_ABNORMAL_CLOSED = 1006
STATUS_INVALID_PAYLOAD = 1007
STATUS_POLICY_VIOLATION = 1008
STATUS_MESSAGE_TOO_BIG = 1009
STATUS_INVALID_EXTENSION = 1010
STATUS_UNEXPECTED_CONDITION = 1011
STATUS_BAD_GATEWAY = 1014
STATUS_TLS_HANDSHAKE_ERROR = 1015

VALID_CLOSE_STATUS = (
    STATUS_NORMAL,
    STATUS_GOING_AWAY,
    STATUS_PROTOCOL_ERROR,
    STATUS_UNSUPPORTED_DATA_TYPE,
    STATUS_INVALID_PAYLOAD,
    STATUS_POLICY_VIOLATION,
    STATUS_MESSAGE_TOO_BIG,
    STATUS_INVALID_EXTENSION,
    STATUS_UNEXPECTED_CONDITION,
    STATUS_BAD_GATEWAY,
)
class ABNF(object):
    """
    ABNF frame class.
    See http://tools.ietf.org/html/rfc5234
    and http://tools.ietf.org/html/rfc6455#section-5.2
    """

    # operation code values.
    OPCODE_CONT = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xa

    # available operation code value tuple
    OPCODES = (OPCODE_CONT, OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE,
               OPCODE_PING, OPCODE_PONG)

    # opcode human readable string
    OPCODE_MAP = {
        OPCODE_CONT: "cont",
        OPCODE_TEXT: "text",
        OPCODE_BINARY: "binary",
        OPCODE_CLOSE: "close",
        OPCODE_PING: "ping",
        OPCODE_PONG: "pong"
    }

    # data length threshold.
    LENGTH_7 = 0x7e
    LENGTH_16 = 1 << 16
    LENGTH_63 = 1 << 63

    def __init__(self, fin=0, rsv1=0, rsv2=0, rsv3=0,
                 opcode=OPCODE_TEXT, mask=1, data=""):
        """
        Constructor for ABNF. Please check RFC for arguments.
        """
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self.opcode = opcode
        self.mask = mask
        if data is None:
            data = ""
        self.data = data
        self.get_mask_key = os.urandom

    def validate(self, skip_utf8_validation=False):
        """
        Validate the ABNF frame.

        Parameters
        ----------
        skip_utf8_validation: skip utf8 validation.
        """
        if self.rsv1 or self.rsv2 or self.rsv3:
            raise WebSocketProtocolException("rsv is not implemented, yet")

        if self.opcode not in ABNF.OPCODES:
            raise WebSocketProtocolException("Invalid opcode %r", self.opcode)

        if self.opcode == ABNF.OPCODE_PING and not self.fin:
            raise WebSocketProtocolException("Invalid ping frame.")

        if self.opcode == ABNF.OPCODE_CLOSE:
            l = len(self.data)
            if not l:
                return
            if l == 1 or l >= 126:
                raise WebSocketProtocolException("Invalid close frame.")
            if l > 2 and not skip_utf8_validation and not validate_utf8(self.data[2:]):
                raise WebSocketProtocolException("Invalid close frame.")

            code = 256 * self.data[0] + self.data[1]
            if not self._is_valid_close_status(code):
                raise WebSocketProtocolException("Invalid close opcode.")

    @staticmethod
    def _is_valid_close_status(code):
        return code in VALID_CLOSE_STATUS or (3000 <= code < 5000)

    def __str__(self):
        return "fin=" + str(self.fin) \
            + " opcode=" + str(self.opcode) \
            + " data=" + str(self.data)

    @staticmethod
    def create_frame(data, opcode, fin=1):
        """
        Create frame to send text, binary and other data.

        Parameters
        ----------
        data: <type>
            data to send. This is string value(byte array).
            If opcode is OPCODE_TEXT and this value is unicode,
            data value is converted into unicode string, automatically.
        opcode: <type>
            operation code. please see OPCODE_XXX.
        fin: <type>
            fin flag. if set to 0, create continue fragmentation.
        """
        if opcode == ABNF.OPCODE_TEXT and isinstance(data, str):
            data = data.encode("utf-8")
        # mask must be set if send data from client
        return ABNF(fin, 0, 0, 0, opcode, 1, data)

    def format(self):
        """
        Format this object to string(byte array) to send data to server.
        """
        if any(x not in (0, 1) for x in [self.fin, self.rsv1, self.rsv2, self.rsv3]):
            raise ValueError("not 0 or 1")
        if self.opcode not in ABNF.OPCODES:
            raise ValueError("Invalid OPCODE")
        length = len(self.data)
        if length >= ABNF.LENGTH_63:
            raise ValueError("data is too long")

        frame_header = chr(self.fin << 7 |
                           self.rsv1 << 6 | self.rsv2 << 5 | self.rsv3 << 4 |
                           self.opcode).encode('latin-1')
        if length < ABNF.LENGTH_7:
            frame_header += chr(self.mask << 7 | length).encode('latin-1')
        elif length < ABNF.LENGTH_16:
            frame_header += chr(self.mask << 7 | 0x7e).encode('latin-1')
            frame_header += struct.pack("!H", length)
        else:
            frame_header += chr(self.mask << 7 | 0x7f).encode('latin-1')
            frame_header += struct.pack("!Q", length)

        if not self.mask:
            return frame_header + self.data
        else:
            mask_key = self.get_mask_key(4)
            return frame_header + self._get_masked(mask_key)

    def _get_masked(self, mask_key):
        s = ABNF.mask(mask_key, self.data)

        if isinstance(mask_key, str):
            mask_key = mask_key.encode('utf-8')

        return mask_key + s

    @staticmethod
    def mask(mask_key, data):
        """
        Mask or unmask data. Just do xor for each byte

        Parameters
        ----------
        mask_key: <type>
            4 byte string.
        data: <type>
            data to mask/unmask.
        """
        if data is None:
            data = ""

        if isinstance(mask_key, str):
            mask_key = mask_key.encode('latin-1')

        if isinstance(data, str):
            data = data.encode('latin-1')

        return _mask(array.array("B", mask_key), array.array("B", data))
class frame_buffer(object):
    _HEADER_MASK_INDEX = 5
    _HEADER_LENGTH_INDEX = 6

    def __init__(self, recv_fn, skip_utf8_validation):
        self.recv = recv_fn
        self.skip_utf8_validation = skip_utf8_validation
        # Buffers over the packets from the layer beneath until desired amount
        # bytes of bytes are received.
        self.recv_buffer = []
        self.clear()
        self.lock = Lock()

    def clear(self):
        self.header = None
        self.length = None
        self.mask = None

    def has_received_header(self):
        return self.header is None

    def recv_header(self):
        header = self.recv_strict(2)
        b1 = header[0]
        fin = b1 >> 7 & 1
        rsv1 = b1 >> 6 & 1
        rsv2 = b1 >> 5 & 1
        rsv3 = b1 >> 4 & 1
        opcode = b1 & 0xf
        b2 = header[1]
        has_mask = b2 >> 7 & 1
        length_bits = b2 & 0x7f

        self.header = (fin, rsv1, rsv2, rsv3, opcode, has_mask, length_bits)

    def has_mask(self):
        if not self.header:
            return False
        return self.header[frame_buffer._HEADER_MASK_INDEX]

    def has_received_length(self):
        return self.length is None

    def recv_length(self):
        bits = self.header[frame_buffer._HEADER_LENGTH_INDEX]
        length_bits = bits & 0x7f
        if length_bits == 0x7e:
            v = self.recv_strict(2)
            self.length = struct.unpack("!H", v)[0]
        elif length_bits == 0x7f:
            v = self.recv_strict(8)
            self.length = struct.unpack("!Q", v)[0]
        else:
            self.length = length_bits

    def has_received_mask(self):
        return self.mask is None

    def recv_mask(self):
        self.mask = self.recv_strict(4) if self.has_mask() else ""

    def recv_frame(self):

        with self.lock:
            # Header
            if self.has_received_header():
                self.recv_header()
            (fin, rsv1, rsv2, rsv3, opcode, has_mask, _) = self.header

            # Frame length
            if self.has_received_length():
                self.recv_length()
            length = self.length

            # Mask
            if self.has_received_mask():
                self.recv_mask()
            mask = self.mask

            # Payload
            payload = self.recv_strict(length)
            if has_mask:
                payload = ABNF.mask(mask, payload)

            # Reset for next frame
            self.clear()

            frame = ABNF(fin, rsv1, rsv2, rsv3, opcode, has_mask, payload)
            frame.validate(self.skip_utf8_validation)

        return frame

    def recv_strict(self, bufsize):
        shortage = bufsize - sum(map(len, self.recv_buffer))
        while shortage > 0:
            # Limit buffer size that we pass to socket.recv() to avoid
            # fragmenting the heap -- the number of bytes recv() actually
            # reads is limited by socket buffer and is relatively small,
            # yet passing large numbers repeatedly causes lots of large
            # buffers allocated and then shrunk, which results in
            # fragmentation.
            bytes_ = self.recv(min(16384, shortage))
            self.recv_buffer.append(bytes_)
            shortage -= len(bytes_)

        unified = bytes("", 'utf-8').join(self.recv_buffer)

        if shortage == 0:
            self.recv_buffer = []
            return unified
        else:
            self.recv_buffer = [unified[bufsize:]]
            return unified[:bufsize]
class continuous_frame(object):

    def __init__(self, fire_cont_frame, skip_utf8_validation):
        self.fire_cont_frame = fire_cont_frame
        self.skip_utf8_validation = skip_utf8_validation
        self.cont_data = None
        self.recving_frames = None

    def validate(self, frame):
        if not self.recving_frames and frame.opcode == ABNF.OPCODE_CONT:
            raise WebSocketProtocolException("Illegal frame")
        if self.recving_frames and \
                frame.opcode in (ABNF.OPCODE_TEXT, ABNF.OPCODE_BINARY):
            raise WebSocketProtocolException("Illegal frame")

    def add(self, frame):
        if self.cont_data:
            self.cont_data[1] += frame.data
        else:
            if frame.opcode in (ABNF.OPCODE_TEXT, ABNF.OPCODE_BINARY):
                self.recving_frames = frame.opcode
            self.cont_data = [frame.opcode, frame.data]

        if frame.fin:
            self.recving_frames = None

    def is_fire(self, frame):
        return frame.fin or self.fire_cont_frame

    def extract(self, frame):
        data = self.cont_data
        self.cont_data = None
        frame.data = data[1]
        if not self.fire_cont_frame and data[0] == ABNF.OPCODE_TEXT and not self.skip_utf8_validation and not validate_utf8(frame.data):
            raise WebSocketPayloadException(
                "cannot decode: " + repr(frame.data))

        return [data[0], frame]

import selectors
import sys
import threading
import time
import traceback

__all__ = ["WebSocketApp"]

class Dispatcher:
    """
    Dispatcher
    """
    def __init__(self, app, ping_timeout):
        self.app = app
        self.ping_timeout = ping_timeout

    def read(self, sock, read_callback, check_callback):
        while self.app.keep_running:
            sel = selectors.DefaultSelector()
            sel.register(self.app.sock.sock, selectors.EVENT_READ)

            r = sel.select(self.ping_timeout)
            if r:
                if not read_callback():
                    break
            check_callback()
            sel.close()

class SSLDispatcher:
    """
    SSLDispatcher
    """
    def __init__(self, app, ping_timeout):
        self.app = app
        self.ping_timeout = ping_timeout

    def read(self, sock, read_callback, check_callback):
        while self.app.keep_running:
            r = self.select()
            if r:
                if not read_callback():
                    break
            check_callback()

    def select(self):
        sock = self.app.sock.sock
        if sock.pending():
            return [sock,]

        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_READ)

        r = sel.select(self.ping_timeout)
        sel.close()

        if len(r) > 0:
            return r[0][0]

class WebSocketApp(object):
    """
    Higher level of APIs are provided. The interface is like JavaScript WebSocket object.
    """

    def __init__(self, url, header=None,
                 on_open=None, on_message=None, on_error=None,
                 on_close=None, on_ping=None, on_pong=None,
                 on_cont_message=None,
                 keep_running=True, get_mask_key=None, cookie=None,
                 subprotocols=None,
                 on_data=None):
        """
        WebSocketApp initialization

        Parameters
        ----------
        url: str
            Websocket url.
        header: list or dict
            Custom header for websocket handshake.
        on_open: function
            Callback object which is called at opening websocket.
            on_open has one argument.
            The 1st argument is this class object.
        on_message: function
            Callback object which is called when received data.
            on_message has 2 arguments.
            The 1st argument is this class object.
            The 2nd argument is utf-8 data received from the server.
        on_error: function
            Callback object which is called when we get error.
            on_error has 2 arguments.
            The 1st argument is this class object.
            The 2nd argument is exception object.
        on_close: function
            Callback object which is called when connection is closed.
            on_close has 3 arguments.
            The 1st argument is this class object.
            The 2nd argument is close_status_code.
            The 3rd argument is close_msg.
        on_cont_message: function
            Callback object which is called when a continuation
            frame is received.
            on_cont_message has 3 arguments.
            The 1st argument is this class object.
            The 2nd argument is utf-8 string which we get from the server.
            The 3rd argument is continue flag. if 0, the data continue
            to next frame data
        on_data: function
            Callback object which is called when a message received.
            This is called before on_message or on_cont_message,
            and then on_message or on_cont_message is called.
            on_data has 4 argument.
            The 1st argument is this class object.
            The 2nd argument is utf-8 string which we get from the server.
            The 3rd argument is data type. ABNF.OPCODE_TEXT or ABNF.OPCODE_BINARY will be came.
            The 4th argument is continue flag. If 0, the data continue
        keep_running: bool
            This parameter is obsolete and ignored.
        get_mask_key: function
            A callable function to get new mask keys, see the
            WebSocket.set_mask_key's docstring for more information.
        cookie: str
            Cookie value.
        subprotocols: list
            List of available sub protocols. Default is None.
        """
        self.url = url
        self.header = header if header is not None else []
        self.cookie = cookie

        self.on_open = on_open
        self.on_message = on_message
        self.on_data = on_data
        self.on_error = on_error
        self.on_close = on_close
        self.on_ping = on_ping
        self.on_pong = on_pong
        self.on_cont_message = on_cont_message
        self.keep_running = False
        self.get_mask_key = get_mask_key
        self.sock = None
        self.last_ping_tm = 0
        self.last_pong_tm = 0
        self.subprotocols = subprotocols

    def send(self, data, opcode=ABNF.OPCODE_TEXT):
        """
        send message

        Parameters
        ----------
        data: str
            Message to send. If you set opcode to OPCODE_TEXT,
            data must be utf-8 string or unicode.
        opcode: int
            Operation code of data. Default is OPCODE_TEXT.
        """

        if not self.sock or self.sock.send(data, opcode) == 0:
            raise WebSocketConnectionClosedException(
                "Connection is already closed.")

    def close(self, **kwargs):
        """
        Close websocket connection.
        """
        self.keep_running = False
        if self.sock:
            self.sock.close(**kwargs)
            self.sock = None

    def _send_ping(self, interval, event, payload):
        while not event.wait(interval):
            self.last_ping_tm = time.time()
            if self.sock:
                try:
                    self.sock.ping(payload)
                except Exception as ex:
                    _logging.warning("send_ping routine terminated: {}".format(ex))
                    break

    def run_forever(self, sockopt=None, sslopt=None,
                    ping_interval=0, ping_timeout=None,
                    ping_payload="",
                    http_proxy_host=None, http_proxy_port=None,
                    http_no_proxy=None, http_proxy_auth=None,
                    skip_utf8_validation=False,
                    host=None, origin=None, dispatcher=None,
                    suppress_origin=False, proxy_type=None):
        """
        Run event loop for WebSocket framework.

        This loop is an infinite loop and is alive while websocket is available.

        Parameters
        ----------
        sockopt: tuple
            Values for socket.setsockopt.
            sockopt must be tuple
            and each element is argument of sock.setsockopt.
        sslopt: dict
            Optional dict object for ssl socket option.
        ping_interval: int or float
            Automatically send "ping" command
            every specified period (in seconds).
            If set to 0, no ping is sent periodically.
        ping_timeout: int or float
            Timeout (in seconds) if the pong message is not received.
        ping_payload: str
            Payload message to send with each ping.
        http_proxy_host: str
            HTTP proxy host name.
        http_proxy_port: int or str
            HTTP proxy port. If not set, set to 80.
        http_no_proxy: list
            Whitelisted host names that don't use the proxy.
        skip_utf8_validation: bool
            skip utf8 validation.
        host: str
            update host header.
        origin: str
            update origin header.
        dispatcher: Dispatcher object
            customize reading data from socket.
        suppress_origin: bool
            suppress outputting origin header.

        Returns
        -------
        teardown: bool
            False if caught KeyboardInterrupt, True if other exception was raised during a loop
        """

        if ping_timeout is not None and ping_timeout <= 0:
            raise WebSocketException("Ensure ping_timeout > 0")
        if ping_interval is not None and ping_interval < 0:
            raise WebSocketException("Ensure ping_interval >= 0")
        if ping_timeout and ping_interval and ping_interval <= ping_timeout:
            raise WebSocketException("Ensure ping_interval > ping_timeout")
        if not sockopt:
            sockopt = []
        if not sslopt:
            sslopt = {}
        if self.sock:
            raise WebSocketException("socket is already opened")
        thread = None
        self.keep_running = True
        self.last_ping_tm = 0
        self.last_pong_tm = 0

        def teardown(close_frame=None):
            """
            Tears down the connection.

            Parameters
            ----------
            close_frame: ABNF frame
                If close_frame is set, the on_close handler is invoked
                with the statusCode and reason from the provided frame.
            """

            if thread and thread.is_alive():
                event.set()
                thread.join()
            self.keep_running = False
            if self.sock:
                self.sock.close()
            close_status_code, close_reason = self._get_close_args(
                close_frame if close_frame else None)
            self.sock = None

            # Finally call the callback AFTER all teardown is complete
            self._callback(self.on_close, close_status_code, close_reason)

        try:
            self.sock = WebSocket(
                self.get_mask_key, sockopt=sockopt, sslopt=sslopt,
                fire_cont_frame=self.on_cont_message is not None,
                skip_utf8_validation=skip_utf8_validation,
                enable_multithread=True)
            self.sock.settimeout(getdefaulttimeout())
            self.sock.connect(
                self.url, header=self.header, cookie=self.cookie,
                http_proxy_host=http_proxy_host,
                http_proxy_port=http_proxy_port, http_no_proxy=http_no_proxy,
                http_proxy_auth=http_proxy_auth, subprotocols=self.subprotocols,
                host=host, origin=origin, suppress_origin=suppress_origin,
                proxy_type=proxy_type)
            if not dispatcher:
                dispatcher = self.create_dispatcher(ping_timeout)

            self._callback(self.on_open)

            if ping_interval:
                event = threading.Event()
                thread = threading.Thread(
                    target=self._send_ping, args=(ping_interval, event, ping_payload))
                thread.daemon = True
                thread.start()

            def read():
                if not self.keep_running:
                    return teardown()

                op_code, frame = self.sock.recv_data_frame(True)
                if op_code == ABNF.OPCODE_CLOSE:
                    return teardown(frame)
                elif op_code == ABNF.OPCODE_PING:
                    self._callback(self.on_ping, frame.data)
                elif op_code == ABNF.OPCODE_PONG:
                    self.last_pong_tm = time.time()
                    self._callback(self.on_pong, frame.data)
                elif op_code == ABNF.OPCODE_CONT and self.on_cont_message:
                    self._callback(self.on_data, frame.data,
                                   frame.opcode, frame.fin)
                    self._callback(self.on_cont_message,
                                   frame.data, frame.fin)
                else:
                    data = frame.data
                    if op_code == ABNF.OPCODE_TEXT:
                        data = data.decode("utf-8")
                    self._callback(self.on_data, data, frame.opcode, True)
                    self._callback(self.on_message, data)

                return True

            def check():
                if (ping_timeout):
                    has_timeout_expired = time.time() - self.last_ping_tm > ping_timeout
                    has_pong_not_arrived_after_last_ping = self.last_pong_tm - self.last_ping_tm < 0
                    has_pong_arrived_too_late = self.last_pong_tm - self.last_ping_tm > ping_timeout

                    if (self.last_ping_tm and
                            has_timeout_expired and
                            (has_pong_not_arrived_after_last_ping or has_pong_arrived_too_late)):
                        raise WebSocketTimeoutException("ping/pong timed out")
                return True

            dispatcher.read(self.sock.sock, read, check)
        except (Exception, KeyboardInterrupt, SystemExit) as e:
            self._callback(self.on_error, e)
            if isinstance(e, SystemExit):
                # propagate SystemExit further
                raise
            teardown()
            return not isinstance(e, KeyboardInterrupt)

    def create_dispatcher(self, ping_timeout):
        timeout = ping_timeout or 10
        if self.sock.is_ssl():
            return SSLDispatcher(self, timeout)

        return Dispatcher(self, timeout)

    def _get_close_args(self, close_frame):
        """
        _get_close_args extracts the close code and reason from the close body
        if it exists (RFC6455 says WebSocket Connection Close Code is optional)
        """
        # Need to catch the case where close_frame is None
        # Otherwise the following if statement causes an error
        if not self.on_close or not close_frame:
            return [None, None]

        # Extract close frame status code
        if close_frame.data and len(close_frame.data) >= 2:
            close_status_code = 256 * close_frame.data[0] + close_frame.data[1]
            reason = close_frame.data[2:].decode('utf-8')
            return [close_status_code, reason]
        else:
            # Most likely reached this because len(close_frame_data.data) < 2
            return [None, None]

    def _callback(self, callback, *args):
        if callback:
            try:
                callback(self, *args)

            except Exception as e:
                _logging.error("error from callback {}: {}".format(callback, e))
                if self.on_error:
                    self.on_error(self, e)

import http.cookies

class SimpleCookieJar(object):
    def __init__(self):
        self.jar = dict()

    def add(self, set_cookie):
        if set_cookie:
            simpleCookie = http.cookies.SimpleCookie(set_cookie)

            for k, v in simpleCookie.items():
                domain = v.get("domain")
                if domain:
                    if not domain.startswith("."):
                        domain = "." + domain
                    cookie = self.jar.get(domain) if self.jar.get(domain) else http.cookies.SimpleCookie()
                    cookie.update(simpleCookie)
                    self.jar[domain.lower()] = cookie

    def set(self, set_cookie):
        if set_cookie:
            simpleCookie = http.cookies.SimpleCookie(set_cookie)

            for k, v in simpleCookie.items():
                domain = v.get("domain")
                if domain:
                    if not domain.startswith("."):
                        domain = "." + domain
                    self.jar[domain.lower()] = simpleCookie

    def get(self, host):
        if not host:
            return ""

        cookies = []
        for domain, simpleCookie in self.jar.items():
            host = host.lower()
            if host.endswith(domain) or host == domain[1:]:
                cookies.append(self.jar.get(domain))

        return "; ".join(filter(
            None, sorted(
                ["%s=%s" % (k, v.value) for cookie in filter(None, cookies) for k, v in cookie.items()]
            )))

"""
_core.py
====================================
WebSocket Python client
"""

"""
_core.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import socket
import struct
import threading
import time

__all__ = ['WebSocket', 'create_connection']


class WebSocket(object):
    """
    Low level WebSocket interface.

    This class is based on the WebSocket protocol `draft-hixie-thewebsocketprotocol-76 <http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76>`_

    We can connect to the websocket server and send/receive data.
    The following example is an echo client.

    >>> import websocket
    >>> ws = websocket.WebSocket()
    >>> ws.connect("ws://echo.websocket.org")
    >>> ws.send("Hello, Server")
    >>> ws.recv()
    'Hello, Server'
    >>> ws.close()

    Parameters
    ----------
    get_mask_key: func
        A callable function to get new mask keys, see the
        WebSocket.set_mask_key's docstring for more information.
    sockopt: tuple
        Values for socket.setsockopt.
        sockopt must be tuple and each element is argument of sock.setsockopt.
    sslopt: dict
        Optional dict object for ssl socket options.
    fire_cont_frame: bool
        Fire recv event for each cont frame. Default is False.
    enable_multithread: bool
        If set to True, lock send method.
    skip_utf8_validation: bool
        Skip utf8 validation.
    """

    def __init__(self, get_mask_key=None, sockopt=None, sslopt=None,
                 fire_cont_frame=False, enable_multithread=True,
                 skip_utf8_validation=False, **_):
        """
        Initialize WebSocket object.

        Parameters
        ----------
        sslopt: dict
            Optional dict object for ssl socket options.
        """
        self.sock_opt = sock_opt(sockopt, sslopt)
        self.handshake_response = None
        self.sock = None

        self.connected = False
        self.get_mask_key = get_mask_key
        # These buffer over the build-up of a single frame.
        self.frame_buffer = frame_buffer(self._recv, skip_utf8_validation)
        self.cont_frame = continuous_frame(
            fire_cont_frame, skip_utf8_validation)

        if enable_multithread:
            self.lock = threading.Lock()
            self.readlock = threading.Lock()
        else:
            self.lock = NoLock()
            self.readlock = NoLock()

    def __iter__(self):
        """
        Allow iteration over websocket, implying sequential `recv` executions.
        """
        while True:
            yield self.recv()

    def __next__(self):
        return self.recv()

    def next(self):
        return self.__next__()

    def fileno(self):
        return self.sock.fileno()

    def set_mask_key(self, func):
        """
        Set function to create mask key. You can customize mask key generator.
        Mainly, this is for testing purpose.

        Parameters
        ----------
        func: func
            callable object. the func takes 1 argument as integer.
            The argument means length of mask key.
            This func must return string(byte array),
            which length is argument specified.
        """
        self.get_mask_key = func

    def gettimeout(self):
        """
        Get the websocket timeout (in seconds) as an int or float

        Returns
        ----------
        timeout: int or float
             returns timeout value (in seconds). This value could be either float/integer.
        """
        return self.sock_opt.timeout

    def settimeout(self, timeout):
        """
        Set the timeout to the websocket.

        Parameters
        ----------
        timeout: int or float
            timeout time (in seconds). This value could be either float/integer.
        """
        self.sock_opt.timeout = timeout
        if self.sock:
            self.sock.settimeout(timeout)

    timeout = property(gettimeout, settimeout)

    def getsubprotocol(self):
        """
        Get subprotocol
        """
        if self.handshake_response:
            return self.handshake_response.subprotocol
        else:
            return None

    subprotocol = property(getsubprotocol)

    def getstatus(self):
        """
        Get handshake status
        """
        if self.handshake_response:
            return self.handshake_response.status
        else:
            return None

    status = property(getstatus)

    def getheaders(self):
        """
        Get handshake response header
        """
        if self.handshake_response:
            return self.handshake_response.headers
        else:
            return None

    def is_ssl(self):
        try:
            return isinstance(self.sock, ssl.SSLSocket)
        except:
            return False

    headers = property(getheaders)

    def connect(self, url, **options):
        """
        Connect to url. url is websocket url scheme.
        ie. ws://host:port/resource
        You can customize using 'options'.
        If you set "header" list object, you can set your own custom header.

        >>> ws = WebSocket()
        >>> ws.connect("ws://echo.websocket.org/",
                ...     header=["User-Agent: MyProgram",
                ...             "x-custom: header"])

        Parameters
        ----------
        header: list or dict
            Custom http header list or dict.
        cookie: str
            Cookie value.
        origin: str
            Custom origin url.
        connection: str
            Custom connection header value.
            Default value "Upgrade" set in _handshake.py
        suppress_origin: bool
            Suppress outputting origin header.
        host: str
            Custom host header string.
        timeout: int or float
            Socket timeout time. This value is an integer or float.
            If you set None for this value, it means "use default_timeout value"
        http_proxy_host: str
            HTTP proxy host name.
        http_proxy_port: str or int
            HTTP proxy port. Default is 80.
        http_no_proxy: list
            Whitelisted host names that don't use the proxy.
        http_proxy_auth: tuple
            HTTP proxy auth information. Tuple of username and password. Default is None.
        redirect_limit: int
            Number of redirects to follow.
        subprotocols: list
            List of available subprotocols. Default is None.
        socket: socket
            Pre-initialized stream socket.
        """
        self.sock_opt.timeout = options.get('timeout', self.sock_opt.timeout)
        self.sock, addrs = connect(url, self.sock_opt, proxy_info(**options),
                                   options.pop('socket', None))

        try:
            self.handshake_response = handshake(self.sock, *addrs, **options)
            for attempt in range(options.pop('redirect_limit', 3)):
                if self.handshake_response.status in SUPPORTED_REDIRECT_STATUSES:
                    url = self.handshake_response.headers['location']
                    self.sock.close()
                    self.sock, addrs = connect(url, self.sock_opt, proxy_info(**options),
                                               options.pop('socket', None))
                    self.handshake_response = handshake(self.sock, *addrs, **options)
            self.connected = True
        except:
            if self.sock:
                self.sock.close()
                self.sock = None
            raise

    def send(self, payload, opcode=ABNF.OPCODE_TEXT):
        """
        Send the data as string.

        Parameters
        ----------
        payload: str
            Payload must be utf-8 string or unicode,
            If the opcode is OPCODE_TEXT.
            Otherwise, it must be string(byte array).
        opcode: int
            Operation code (opcode) to send.
        """

        frame = ABNF.create_frame(payload, opcode)
        return self.send_frame(frame)

    def send_frame(self, frame):
        """
        Send the data frame.

        >>> ws = create_connection("ws://echo.websocket.org/")
        >>> frame = ABNF.create_frame("Hello", ABNF.OPCODE_TEXT)
        >>> ws.send_frame(frame)
        >>> cont_frame = ABNF.create_frame("My name is ", ABNF.OPCODE_CONT, 0)
        >>> ws.send_frame(frame)
        >>> cont_frame = ABNF.create_frame("Foo Bar", ABNF.OPCODE_CONT, 1)
        >>> ws.send_frame(frame)

        Parameters
        ----------
        frame: ABNF frame
            frame data created by ABNF.create_frame
        """
        if self.get_mask_key:
            frame.get_mask_key = self.get_mask_key
        data = frame.format()
        length = len(data)
        if (isEnabledForTrace()):
            trace("++Sent raw: " + repr(data))
            trace("++Sent decoded: " + frame.__str__())
        with self.lock:
            while data:
                l = self._send(data)
                data = data[l:]

        return length

    def send_binary(self, payload):
        return self.send(payload, ABNF.OPCODE_BINARY)

    def ping(self, payload=""):
        """
        Send ping data.

        Parameters
        ----------
        payload: str
            data payload to send server.
        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send(payload, ABNF.OPCODE_PING)

    def pong(self, payload=""):
        """
        Send pong data.

        Parameters
        ----------
        payload: str
            data payload to send server.
        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send(payload, ABNF.OPCODE_PONG)

    def recv(self):
        """
        Receive string data(byte array) from the server.

        Returns
        ----------
        data: string (byte array) value.
        """
        with self.readlock:
            opcode, data = self.recv_data()
        if opcode == ABNF.OPCODE_TEXT:
            return data.decode("utf-8")
        elif opcode == ABNF.OPCODE_TEXT or opcode == ABNF.OPCODE_BINARY:
            return data
        else:
            return ''

    def recv_data(self, control_frame=False):
        """
        Receive data with operation code.

        Parameters
        ----------
        control_frame: bool
            a boolean flag indicating whether to return control frame
            data, defaults to False

        Returns
        -------
        opcode, frame.data: tuple
            tuple of operation code and string(byte array) value.
        """
        opcode, frame = self.recv_data_frame(control_frame)
        return opcode, frame.data

    def recv_data_frame(self, control_frame=False):
        """
        Receive data with operation code.

        Parameters
        ----------
        control_frame: bool
            a boolean flag indicating whether to return control frame
            data, defaults to False

        Returns
        -------
        frame.opcode, frame: tuple
            tuple of operation code and string(byte array) value.
        """
        while True:
            frame = self.recv_frame()
            if (isEnabledForTrace()):
                trace("++Rcv raw: " + repr(frame.format()))
                trace("++Rcv decoded: " + frame.__str__())
            if not frame:
                # handle error:
                # 'NoneType' object has no attribute 'opcode'
                raise WebSocketProtocolException(
                    "Not a valid frame %s" % frame)
            elif frame.opcode in (ABNF.OPCODE_TEXT, ABNF.OPCODE_BINARY, ABNF.OPCODE_CONT):
                self.cont_frame.validate(frame)
                self.cont_frame.add(frame)

                if self.cont_frame.is_fire(frame):
                    return self.cont_frame.extract(frame)

            elif frame.opcode == ABNF.OPCODE_CLOSE:
                self.send_close()
                return frame.opcode, frame
            elif frame.opcode == ABNF.OPCODE_PING:
                if len(frame.data) < 126:
                    self.pong(frame.data)
                else:
                    raise WebSocketProtocolException(
                        "Ping message is too long")
                if control_frame:
                    return frame.opcode, frame
            elif frame.opcode == ABNF.OPCODE_PONG:
                if control_frame:
                    return frame.opcode, frame

    def recv_frame(self):
        """
        Receive data as frame from server.

        Returns
        -------
        self.frame_buffer.recv_frame(): ABNF frame object
        """
        return self.frame_buffer.recv_frame()

    def send_close(self, status=STATUS_NORMAL, reason=bytes('', encoding='utf-8')):
        """
        Send close data to the server.

        Parameters
        ----------
        status: int
            Status code to send. See STATUS_XXX.
        reason: str or bytes
            The reason to close. This must be string or bytes.
        """
        if status < 0 or status >= ABNF.LENGTH_16:
            raise ValueError("code is invalid range")
        self.connected = False
        self.send(struct.pack('!H', status) + reason, ABNF.OPCODE_CLOSE)

    def close(self, status=STATUS_NORMAL, reason=bytes('', encoding='utf-8'), timeout=3):
        """
        Close Websocket object

        Parameters
        ----------
        status: int
            Status code to send. See STATUS_XXX.
        reason: bytes
            The reason to close.
        timeout: int or float
            Timeout until receive a close frame.
            If None, it will wait forever until receive a close frame.
        """
        if self.connected:
            if status < 0 or status >= ABNF.LENGTH_16:
                raise ValueError("code is invalid range")

            try:
                self.connected = False
                self.send(struct.pack('!H', status) + reason, ABNF.OPCODE_CLOSE)
                sock_timeout = self.sock.gettimeout()
                self.sock.settimeout(timeout)
                start_time = time.time()
                while timeout is None or time.time() - start_time < timeout:
                    try:
                        frame = self.recv_frame()
                        if frame.opcode != ABNF.OPCODE_CLOSE:
                            continue
                        if isEnabledForError():
                            recv_status = struct.unpack("!H", frame.data[0:2])[0]
                            if recv_status >= 3000 and recv_status <= 4999:
                                debug("close status: " + repr(recv_status))
                            elif recv_status != STATUS_NORMAL:
                                error("close status: " + repr(recv_status))
                        break
                    except:
                        break
                self.sock.settimeout(sock_timeout)
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass

            self.shutdown()

    def abort(self):
        """
        Low-level asynchronous abort, wakes up other threads that are waiting in recv_*
        """
        if self.connected:
            self.sock.shutdown(socket.SHUT_RDWR)

    def shutdown(self):
        """
        close socket, immediately.
        """
        if self.sock:
            self.sock.close()
            self.sock = None
            self.connected = False

    def _send(self, data):
        return send(self.sock, data)

    def _recv(self, bufsize):
        try:
            return recv(self.sock, bufsize)
        except WebSocketConnectionClosedException:
            if self.sock:
                self.sock.close()
            self.sock = None
            self.connected = False
            raise


def create_connection(url, timeout=None, class_=WebSocket, **options):
    """
    Connect to url and return websocket object.

    Connect to url and return the WebSocket object.
    Passing optional timeout parameter will set the timeout on the socket.
    If no timeout is supplied,
    the global default timeout setting returned by getdefaulttimeout() is used.
    You can customize using 'options'.
    If you set "header" list object, you can set your own custom header.

    >>> conn = create_connection("ws://echo.websocket.org/",
         ...     header=["User-Agent: MyProgram",
         ...             "x-custom: header"])

    Parameters
    ----------
    class_: class
        class to instantiate when creating the connection. It has to implement
        settimeout and connect. It's __init__ should be compatible with
        WebSocket.__init__, i.e. accept all of it's kwargs.
    header: list or dict
        custom http header list or dict.
    cookie: str
        Cookie value.
    origin: str
        custom origin url.
    suppress_origin: bool
        suppress outputting origin header.
    host: str
        custom host header string.
    timeout: int or float
        socket timeout time. This value could be either float/integer.
        If set to None, it uses the default_timeout value.
    http_proxy_host: str
        HTTP proxy host name.
    http_proxy_port: str or int
        HTTP proxy port. If not set, set to 80.
    http_no_proxy: list
        Whitelisted host names that don't use the proxy.
    http_proxy_auth: tuple
        HTTP proxy auth information. tuple of username and password. Default is None.
    enable_multithread: bool
        Enable lock for multithread.
    redirect_limit: int
        Number of redirects to follow.
    sockopt: tuple
        Values for socket.setsockopt.
        sockopt must be a tuple and each element is an argument of sock.setsockopt.
    sslopt: dict
        Optional dict object for ssl socket options.
    subprotocols: list
        List of available subprotocols. Default is None.
    skip_utf8_validation: bool
        Skip utf8 validation.
    socket: socket
        Pre-initialized stream socket.
    """
    sockopt = options.pop("sockopt", [])
    sslopt = options.pop("sslopt", {})
    fire_cont_frame = options.pop("fire_cont_frame", False)
    enable_multithread = options.pop("enable_multithread", True)
    skip_utf8_validation = options.pop("skip_utf8_validation", False)
    websock = class_(sockopt=sockopt, sslopt=sslopt,
                     fire_cont_frame=fire_cont_frame,
                     enable_multithread=enable_multithread,
                     skip_utf8_validation=skip_utf8_validation, **options)
    websock.settimeout(timeout if timeout is not None else getdefaulttimeout())
    websock.connect(url, **options)
    return websock


class WebSocketException(Exception):
    """
    WebSocket exception class.
    """
    pass


class WebSocketProtocolException(WebSocketException):
    """
    If the WebSocket protocol is invalid, this exception will be raised.
    """
    pass


class WebSocketPayloadException(WebSocketException):
    """
    If the WebSocket payload is invalid, this exception will be raised.
    """
    pass


class WebSocketConnectionClosedException(WebSocketException):
    """
    If remote host closed the connection or some network error happened,
    this exception will be raised.
    """
    pass


class WebSocketTimeoutException(WebSocketException):
    """
    WebSocketTimeoutException will be raised at socket timeout during read/write data.
    """
    pass


class WebSocketProxyException(WebSocketException):
    """
    WebSocketProxyException will be raised when proxy error occurred.
    """
    pass


class WebSocketBadStatusException(WebSocketException):
    """
    WebSocketBadStatusException will be raised when we get bad handshake status code.
    """

    def __init__(self, message, status_code, status_message=None, resp_headers=None):
        msg = message % (status_code, status_message)
        super(WebSocketBadStatusException, self).__init__(msg)
        self.status_code = status_code
        self.resp_headers = resp_headers


class WebSocketAddressException(WebSocketException):
    """
    If the websocket address info cannot be found, this exception will be raised.
    """
    pass

"""
_handshake.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import hashlib
import hmac
import os
from base64 import encodebytes as base64encode
from http import client as HTTPStatus

__all__ = ["handshake_response", "handshake", "SUPPORTED_REDIRECT_STATUSES"]

# websocket supported version.
VERSION = 13

SUPPORTED_REDIRECT_STATUSES = (HTTPStatus.MOVED_PERMANENTLY, HTTPStatus.FOUND, HTTPStatus.SEE_OTHER,)
SUCCESS_STATUSES = SUPPORTED_REDIRECT_STATUSES + (HTTPStatus.SWITCHING_PROTOCOLS,)

CookieJar = SimpleCookieJar()

class handshake_response(object):

    def __init__(self, status, headers, subprotocol):
        self.status = status
        self.headers = headers
        self.subprotocol = subprotocol
        CookieJar.add(headers.get("set-cookie"))


def handshake(sock, hostname, port, resource, **options):
    headers, key = _get_handshake_headers(resource, hostname, port, options)

    header_str = "\r\n".join(headers)
    send(sock, header_str)
    dump("request header", header_str)

    status, resp = _get_resp_headers(sock)
    if status in SUPPORTED_REDIRECT_STATUSES:
        return handshake_response(status, resp, None)
    success, subproto = _validate(resp, key, options.get("subprotocols"))
    if not success:
        raise WebSocketException("Invalid WebSocket Header")

    return handshake_response(status, resp, subproto)


def _pack_hostname(hostname):
    # IPv6 address
    if ':' in hostname:
        return '[' + hostname + ']'

    return hostname


def _get_handshake_headers(resource, host, port, options):
    headers = [
        "GET %s HTTP/1.1" % resource,
        "Upgrade: websocket"
    ]
    if port == 80 or port == 443:
        hostport = _pack_hostname(host)
    else:
        hostport = "%s:%d" % (_pack_hostname(host), port)
    if "host" in options and options["host"] is not None:
        headers.append("Host: %s" % options["host"])
    else:
        headers.append("Host: %s" % hostport)

    if "suppress_origin" not in options or not options["suppress_origin"]:
        if "origin" in options and options["origin"] is not None:
            headers.append("Origin: %s" % options["origin"])
        else:
            headers.append("Origin: http://%s" % hostport)

    key = _create_sec_websocket_key()

    # Append Sec-WebSocket-Key & Sec-WebSocket-Version if not manually specified
    if 'header' not in options or 'Sec-WebSocket-Key' not in options['header']:
        key = _create_sec_websocket_key()
        headers.append("Sec-WebSocket-Key: %s" % key)
    else:
        key = options['header']['Sec-WebSocket-Key']

    if 'header' not in options or 'Sec-WebSocket-Version' not in options['header']:
        headers.append("Sec-WebSocket-Version: %s" % VERSION)

    if 'connection' not in options or options['connection'] is None:
        headers.append('Connection: Upgrade')
    else:
        headers.append(options['connection'])

    subprotocols = options.get("subprotocols")
    if subprotocols:
        headers.append("Sec-WebSocket-Protocol: %s" % ",".join(subprotocols))

    if "header" in options:
        header = options["header"]
        if isinstance(header, dict):
            header = [
                ": ".join([k, v])
                for k, v in header.items()
                if v is not None
            ]
        headers.extend(header)

    server_cookie = CookieJar.get(host)
    client_cookie = options.get("cookie", None)

    cookie = "; ".join(filter(None, [server_cookie, client_cookie]))

    if cookie:
        headers.append("Cookie: %s" % cookie)

    headers.append("")
    headers.append("")

    return headers, key


def _get_resp_headers(sock, success_statuses=SUCCESS_STATUSES):
    status, resp_headers, status_message = read_headers(sock)
    if status not in success_statuses:
        raise WebSocketBadStatusException("Handshake status %d %s", status, status_message, resp_headers)
    return status, resp_headers


_HEADERS_TO_CHECK = {
    "upgrade": "websocket",
    "connection": "upgrade",
}


def _validate(headers, key, subprotocols):
    subproto = None
    for k, v in _HEADERS_TO_CHECK.items():
        r = headers.get(k, None)
        if not r:
            return False, None
        r = [x.strip().lower() for x in r.split(',')]
        if v not in r:
            return False, None

    if subprotocols:
        subproto = headers.get("sec-websocket-protocol", None)
        if not subproto or subproto.lower() not in [s.lower() for s in subprotocols]:
            error("Invalid subprotocol: " + str(subprotocols))
            return False, None
        subproto = subproto.lower()

    result = headers.get("sec-websocket-accept", None)
    if not result:
        return False, None
    result = result.lower()

    if isinstance(result, str):
        result = result.encode('utf-8')

    value = (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode('utf-8')
    hashed = base64encode(hashlib.sha1(value).digest()).strip().lower()
    success = hmac.compare_digest(hashed, result)

    if success:
        return True, subproto
    else:
        return False, None


def _create_sec_websocket_key():
    randomness = os.urandom(16)
    return base64encode(randomness).decode('utf-8').strip()

"""
_http.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import errno
import os
import socket
import sys

from base64 import encodebytes as base64encode

__all__ = ["proxy_info", "connect", "read_headers"]

try:
    from python_socks.sync import Proxy
    from python_socks._errors import *
    from python_socks._types import ProxyType
    HAVE_PYTHON_SOCKS = True
except:
    HAVE_PYTHON_SOCKS = False

    class ProxyError(Exception):
        pass

    class ProxyTimeoutError(Exception):
        pass

    class ProxyConnectionError(Exception):
        pass


class proxy_info(object):

    def __init__(self, **options):
        self.proxy_host = options.get("http_proxy_host", None)
        if self.proxy_host:
            self.proxy_port = options.get("http_proxy_port", 0)
            self.auth = options.get("http_proxy_auth", None)
            self.no_proxy = options.get("http_no_proxy", None)
            self.proxy_protocol = options.get("proxy_type", "http")
            # Note: If timeout not specified, default python-socks timeout is 60 seconds
            self.proxy_timeout = options.get("timeout", None)
            if self.proxy_protocol not in ['http', 'socks4', 'socks4a', 'socks5', 'socks5h']:
                raise ProxyError("Only http, socks4, socks5 proxy protocols are supported")
        else:
            self.proxy_port = 0
            self.auth = None
            self.no_proxy = None
            self.proxy_protocol = "http"


def _start_proxied_socket(url, options, proxy):
    if not HAVE_PYTHON_SOCKS:
        raise WebSocketException("Python Socks is needed for SOCKS proxying but is not available")

    hostname, port, resource, is_secure = parse_url(url)

    if proxy.proxy_protocol == "socks5":
        rdns = False
        proxy_type = ProxyType.SOCKS5
    if proxy.proxy_protocol == "socks4":
        rdns = False
        proxy_type = ProxyType.SOCKS4
    # socks5h and socks4a send DNS through proxy
    if proxy.proxy_protocol == "socks5h":
        rdns = True
        proxy_type = ProxyType.SOCKS5
    if proxy.proxy_protocol == "socks4a":
        rdns = True
        proxy_type = ProxyType.SOCKS4

    ws_proxy = Proxy.create(
        proxy_type=proxy_type,
        host=proxy.proxy_host,
        port=int(proxy.proxy_port),
        username=proxy.auth[0] if proxy.auth else None,
        password=proxy.auth[1] if proxy.auth else None,
        rdns=rdns)

    sock = ws_proxy.connect(hostname, port, timeout=proxy.proxy_timeout)

    if is_secure and HAVE_SSL:
        sock = _ssl_socket(sock, options.sslopt, hostname)
    elif is_secure:
        raise WebSocketException("SSL not available.")

    return sock, (hostname, port, resource)


def connect(url, options, proxy, socket):
    # Use _start_proxied_socket() only for socks4 or socks5 proxy
    # Use _tunnel() for http proxy
    # TODO: Use python-socks for http protocol also, to standardize flow
    if proxy.proxy_host and not socket and not (proxy.proxy_protocol == "http"):
        return _start_proxied_socket(url, options, proxy)

    hostname, port, resource, is_secure = parse_url(url)

    if socket:
        return socket, (hostname, port, resource)

    addrinfo_list, need_tunnel, auth = _get_addrinfo_list(
        hostname, port, is_secure, proxy)
    if not addrinfo_list:
        raise WebSocketException(
            "Host not found.: " + hostname + ":" + str(port))

    sock = None
    try:
        sock = _open_socket(addrinfo_list, options.sockopt, options.timeout)
        if need_tunnel:
            sock = _tunnel(sock, hostname, port, auth)

        if is_secure:
            if HAVE_SSL:
                sock = _ssl_socket(sock, options.sslopt, hostname)
            else:
                raise WebSocketException("SSL not available.")

        return sock, (hostname, port, resource)
    except:
        if sock:
            sock.close()
        raise


def _get_addrinfo_list(hostname, port, is_secure, proxy):
    phost, pport, pauth = get_proxy_info(
        hostname, is_secure, proxy.proxy_host, proxy.proxy_port, proxy.auth, proxy.no_proxy)
    try:
        # when running on windows 10, getaddrinfo without socktype returns a socktype 0.
        # This generates an error exception: `_on_error: exception Socket type must be stream or datagram, not 0`
        # or `OSError: [Errno 22] Invalid argument` when creating socket. Force the socket type to SOCK_STREAM.
        if not phost:
            addrinfo_list = socket.getaddrinfo(
                hostname, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
            return addrinfo_list, False, None
        else:
            pport = pport and pport or 80
            # when running on windows 10, the getaddrinfo used above
            # returns a socktype 0. This generates an error exception:
            # _on_error: exception Socket type must be stream or datagram, not 0
            # Force the socket type to SOCK_STREAM
            addrinfo_list = socket.getaddrinfo(phost, pport, 0, socket.SOCK_STREAM, socket.SOL_TCP)
            return addrinfo_list, True, pauth
    except socket.gaierror as e:
        raise WebSocketAddressException(e)


def _open_socket(addrinfo_list, sockopt, timeout):
    err = None
    for addrinfo in addrinfo_list:
        family, socktype, proto = addrinfo[:3]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        for opts in DEFAULT_SOCKET_OPTION:
            sock.setsockopt(*opts)
        for opts in sockopt:
            sock.setsockopt(*opts)

        address = addrinfo[4]
        err = None
        while not err:
            try:
                sock.connect(address)
            except socket.error as error:
                error.remote_ip = str(address[0])
                try:
                    eConnRefused = (errno.ECONNREFUSED, errno.WSAECONNREFUSED)
                except:
                    eConnRefused = (errno.ECONNREFUSED, )
                if error.errno == errno.EINTR:
                    continue
                elif error.errno in eConnRefused:
                    err = error
                    continue
                else:
                    if sock:
                        sock.close()
                    raise error
            else:
                break
        else:
            continue
        break
    else:
        if err:
            raise err

    return sock


def _wrap_sni_socket(sock, sslopt, hostname, check_hostname):
    context = ssl.SSLContext(sslopt.get('ssl_version', ssl.PROTOCOL_TLS))

    if sslopt.get('cert_reqs', ssl.CERT_NONE) != ssl.CERT_NONE:
        cafile = sslopt.get('ca_certs', None)
        capath = sslopt.get('ca_cert_path', None)
        if cafile or capath:
            context.load_verify_locations(cafile=cafile, capath=capath)
        elif hasattr(context, 'load_default_certs'):
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if sslopt.get('certfile', None):
        context.load_cert_chain(
            sslopt['certfile'],
            sslopt.get('keyfile', None),
            sslopt.get('password', None),
        )
    # see
    # https://github.com/liris/websocket-client/commit/b96a2e8fa765753e82eea531adb19716b52ca3ca#commitcomment-10803153
    context.verify_mode = sslopt['cert_reqs']
    if HAVE_CONTEXT_CHECK_HOSTNAME:
        context.check_hostname = check_hostname
    if 'ciphers' in sslopt:
        context.set_ciphers(sslopt['ciphers'])
    if 'cert_chain' in sslopt:
        certfile, keyfile, password = sslopt['cert_chain']
        context.load_cert_chain(certfile, keyfile, password)
    if 'ecdh_curve' in sslopt:
        context.set_ecdh_curve(sslopt['ecdh_curve'])

    return context.wrap_socket(
        sock,
        do_handshake_on_connect=sslopt.get('do_handshake_on_connect', True),
        suppress_ragged_eofs=sslopt.get('suppress_ragged_eofs', True),
        server_hostname=hostname,
    )


def _ssl_socket(sock, user_sslopt, hostname):
    sslopt = dict(cert_reqs=ssl.CERT_REQUIRED)
    sslopt.update(user_sslopt)

    certPath = os.environ.get('WEBSOCKET_CLIENT_CA_BUNDLE')
    if certPath and os.path.isfile(certPath) \
            and user_sslopt.get('ca_certs', None) is None:
        sslopt['ca_certs'] = certPath
    elif certPath and os.path.isdir(certPath) \
            and user_sslopt.get('ca_cert_path', None) is None:
        sslopt['ca_cert_path'] = certPath

    if sslopt.get('server_hostname', None):
        hostname = sslopt['server_hostname']

    check_hostname = sslopt["cert_reqs"] != ssl.CERT_NONE and sslopt.pop(
        'check_hostname', True)
    sock = _wrap_sni_socket(sock, sslopt, hostname, check_hostname)

    if not HAVE_CONTEXT_CHECK_HOSTNAME and check_hostname:
        match_hostname(sock.getpeercert(), hostname)

    return sock


def _tunnel(sock, host, port, auth):
    debug("Connecting proxy...")
    connect_header = "CONNECT %s:%d HTTP/1.1\r\n" % (host, port)
    connect_header += "Host: %s:%d\r\n" % (host, port)

    # TODO: support digest auth.
    if auth and auth[0]:
        auth_str = auth[0]
        if auth[1]:
            auth_str += ":" + auth[1]
        encoded_str = base64encode(auth_str.encode()).strip().decode().replace('\n', '')
        connect_header += "Proxy-Authorization: Basic %s\r\n" % encoded_str
    connect_header += "\r\n"
    dump("request header", connect_header)

    send(sock, connect_header)

    try:
        status, resp_headers, status_message = read_headers(sock)
    except Exception as e:
        raise WebSocketProxyException(str(e))

    if status != 200:
        raise WebSocketProxyException(
            "failed CONNECT via proxy status: %r" % status)

    return sock


def read_headers(sock):
    status = None
    status_message = None
    headers = {}
    trace("--- response header ---")

    while True:
        line = recv_line(sock)
        line = line.decode('utf-8').strip()
        if not line:
            break
        trace(line)
        if not status:

            status_info = line.split(" ", 2)
            status = int(status_info[1])
            if len(status_info) > 2:
                status_message = status_info[2]
        else:
            kv = line.split(":", 1)
            if len(kv) == 2:
                key, value = kv
                if key.lower() == "set-cookie" and headers.get("set-cookie"):
                    headers["set-cookie"] = headers.get("set-cookie") + "; " + value.strip()
                else:
                    headers[key.lower()] = value.strip()
            else:
                raise WebSocketException("Invalid header")

    trace("-----------------------")

    return status, headers, status_message

"""

"""

"""
_logging.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging

_logger = logging.getLogger('websocket')
try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

_logger.addHandler(NullHandler())

_traceEnabled = False

__all__ = ["enableTrace", "dump", "error", "warning", "debug", "trace",
           "isEnabledForError", "isEnabledForDebug", "isEnabledForTrace"]


def enableTrace(traceable, handler=logging.StreamHandler()):
    """
    Turn on/off the traceability.

    Parameters
    ----------
    traceable: bool
        If set to True, traceability is enabled.
    """
    global _traceEnabled
    _traceEnabled = traceable
    if traceable:
        _logger.addHandler(handler)
        _logger.setLevel(logging.DEBUG)


def dump(title, message):
    if _traceEnabled:
        _logger.debug("--- " + title + " ---")
        _logger.debug(message)
        _logger.debug("-----------------------")


def error(msg):
    _logger.error(msg)


def warning(msg):
    _logger.warning(msg)


def debug(msg):
    _logger.debug(msg)


def trace(msg):
    if _traceEnabled:
        _logger.debug(msg)


def isEnabledForError():
    return _logger.isEnabledFor(logging.ERROR)


def isEnabledForDebug():
    return _logger.isEnabledFor(logging.DEBUG)


def isEnabledForTrace():
    return _traceEnabled

"""

"""

"""
_socket.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import errno
import selectors
import socket

DEFAULT_SOCKET_OPTION = [(socket.SOL_TCP, socket.TCP_NODELAY, 1)]
if hasattr(socket, "SO_KEEPALIVE"):
    DEFAULT_SOCKET_OPTION.append((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))
if hasattr(socket, "TCP_KEEPIDLE"):
    DEFAULT_SOCKET_OPTION.append((socket.SOL_TCP, socket.TCP_KEEPIDLE, 30))
if hasattr(socket, "TCP_KEEPINTVL"):
    DEFAULT_SOCKET_OPTION.append((socket.SOL_TCP, socket.TCP_KEEPINTVL, 10))
if hasattr(socket, "TCP_KEEPCNT"):
    DEFAULT_SOCKET_OPTION.append((socket.SOL_TCP, socket.TCP_KEEPCNT, 3))

_default_timeout = None

__all__ = ["DEFAULT_SOCKET_OPTION", "sock_opt", "setdefaulttimeout", "getdefaulttimeout",
           "recv", "recv_line", "send"]


class sock_opt(object):

    def __init__(self, sockopt, sslopt):
        if sockopt is None:
            sockopt = []
        if sslopt is None:
            sslopt = {}
        self.sockopt = sockopt
        self.sslopt = sslopt
        self.timeout = None


def setdefaulttimeout(timeout):
    """
    Set the global timeout setting to connect.

    Parameters
    ----------
    timeout: int or float
        default socket timeout time (in seconds)
    """
    global _default_timeout
    _default_timeout = timeout


def getdefaulttimeout():
    """
    Get default timeout

    Returns
    ----------
    _default_timeout: int or float
        Return the global timeout setting (in seconds) to connect.
    """
    return _default_timeout


def recv(sock, bufsize):
    if not sock:
        raise WebSocketConnectionClosedException("socket is already closed.")

    def _recv():
        try:
            return sock.recv(bufsize)
        except SSLWantReadError:
            pass
        except socket.error as exc:
            error_code = extract_error_code(exc)
            if error_code is None:
                raise
            if error_code != errno.EAGAIN or error_code != errno.EWOULDBLOCK:
                raise

        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_READ)

        r = sel.select(sock.gettimeout())
        sel.close()

        if r:
            return sock.recv(bufsize)

    try:
        if sock.gettimeout() == 0:
            bytes_ = sock.recv(bufsize)
        else:
            bytes_ = _recv()
    except socket.timeout as e:
        message = extract_err_message(e)
        raise WebSocketTimeoutException(message)
    except SSLError as e:
        message = extract_err_message(e)
        if isinstance(message, str) and 'timed out' in message:
            raise WebSocketTimeoutException(message)
        else:
            raise

    if not bytes_:
        raise WebSocketConnectionClosedException(
            "Connection to remote host was lost.")

    return bytes_


def recv_line(sock):
    line = []
    while True:
        c = recv(sock, 1)
        line.append(c)
        if c == b'\n':
            break
    return b''.join(line)


def send(sock, data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    if not sock:
        raise WebSocketConnectionClosedException("socket is already closed.")

    def _send():
        try:
            return sock.send(data)
        except SSLWantWriteError:
            pass
        except socket.error as exc:
            error_code = extract_error_code(exc)
            if error_code is None:
                raise
            if error_code != errno.EAGAIN or error_code != errno.EWOULDBLOCK:
                raise

        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_WRITE)

        w = sel.select(sock.gettimeout())
        sel.close()

        if w:
            return sock.send(data)

    try:
        if sock.gettimeout() == 0:
            return sock.send(data)
        else:
            return _send()
    except socket.timeout as e:
        message = extract_err_message(e)
        raise WebSocketTimeoutException(message)
    except Exception as e:
        message = extract_err_message(e)
        if isinstance(message, str) and "timed out" in message:
            raise WebSocketTimeoutException(message)
        else:
            raise

"""
_ssl_compat.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__all__ = ["HAVE_SSL", "ssl", "SSLError", "SSLWantReadError", "SSLWantWriteError"]

try:
    import ssl
    from ssl import SSLError
    from ssl import SSLWantReadError
    from ssl import SSLWantWriteError
    HAVE_CONTEXT_CHECK_HOSTNAME = False
    if hasattr(ssl, 'SSLContext') and hasattr(ssl.SSLContext, 'check_hostname'):
        HAVE_CONTEXT_CHECK_HOSTNAME = True

    __all__.append("HAVE_CONTEXT_CHECK_HOSTNAME")
    HAVE_SSL = True
except ImportError:
    # dummy class of SSLError for environment without ssl support
    class SSLError(Exception):
        pass

    class SSLWantReadError(Exception):
        pass

    class SSLWantWriteError(Exception):
        pass

    ssl = None
    HAVE_SSL = False

"""

"""
"""
_url.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import socket
import struct

from urllib.parse import unquote, urlparse


__all__ = ["parse_url", "get_proxy_info"]


def parse_url(url):
    """
    parse url and the result is tuple of
    (hostname, port, resource path and the flag of secure mode)

    Parameters
    ----------
    url: str
        url string.
    """
    if ":" not in url:
        raise ValueError("url is invalid")

    scheme, url = url.split(":", 1)

    parsed = urlparse(url, scheme="http")
    if parsed.hostname:
        hostname = parsed.hostname
    else:
        raise ValueError("hostname is invalid")
    port = 0
    if parsed.port:
        port = parsed.port

    is_secure = False
    if scheme == "ws":
        if not port:
            port = 80
    elif scheme == "wss":
        is_secure = True
        if not port:
            port = 443
    else:
        raise ValueError("scheme %s is invalid" % scheme)

    if parsed.path:
        resource = parsed.path
    else:
        resource = "/"

    if parsed.query:
        resource += "?" + parsed.query

    return hostname, port, resource, is_secure


DEFAULT_NO_PROXY_HOST = ["localhost", "127.0.0.1"]


def _is_ip_address(addr):
    try:
        socket.inet_aton(addr)
    except socket.error:
        return False
    else:
        return True


def _is_subnet_address(hostname):
    try:
        addr, netmask = hostname.split("/")
        return _is_ip_address(addr) and 0 <= int(netmask) < 32
    except ValueError:
        return False


def _is_address_in_network(ip, net):
    ipaddr = struct.unpack('!I', socket.inet_aton(ip))[0]
    netaddr, netmask = net.split('/')
    netaddr = struct.unpack('!I', socket.inet_aton(netaddr))[0]

    netmask = (0xFFFFFFFF << (32 - int(netmask))) & 0xFFFFFFFF
    return ipaddr & netmask == netaddr


def _is_no_proxy_host(hostname, no_proxy):
    if not no_proxy:
        v = os.environ.get("no_proxy", os.environ.get("NO_PROXY", "")).replace(" ", "")
        if v:
            no_proxy = v.split(",")
    if not no_proxy:
        no_proxy = DEFAULT_NO_PROXY_HOST

    if '*' in no_proxy:
        return True
    if hostname in no_proxy:
        return True
    if _is_ip_address(hostname):
        return any([_is_address_in_network(hostname, subnet) for subnet in no_proxy if _is_subnet_address(subnet)])
    for domain in [domain for domain in no_proxy if domain.startswith('.')]:
        if hostname.endswith(domain):
            return True
    return False


def get_proxy_info(
        hostname, is_secure, proxy_host=None, proxy_port=0, proxy_auth=None,
        no_proxy=None, proxy_type='http'):
    """
    Try to retrieve proxy host and port from environment
    if not provided in options.
    Result is (proxy_host, proxy_port, proxy_auth).
    proxy_auth is tuple of username and password
    of proxy authentication information.

    Parameters
    ----------
    hostname: str
        Websocket server name.
    is_secure: bool
        Is the connection secure? (wss) looks for "https_proxy" in env
        before falling back to "http_proxy"
    proxy_host: str
        http proxy host name.
    http_proxy_port: str or int
        http proxy port.
    http_no_proxy: list
        Whitelisted host names that don't use the proxy.
    http_proxy_auth: tuple
        HTTP proxy auth information. Tuple of username and password. Default is None.
    proxy_type: str
        Specify the proxy protocol (http, socks4, socks4a, socks5, socks5h). Default is "http".
        Use socks4a or socks5h if you want to send DNS requests through the proxy.
    """
    if _is_no_proxy_host(hostname, no_proxy):
        return None, 0, None

    if proxy_host:
        port = proxy_port
        auth = proxy_auth
        return proxy_host, port, auth

    env_keys = ["http_proxy"]
    if is_secure:
        env_keys.insert(0, "https_proxy")

    for key in env_keys:
        value = os.environ.get(key, os.environ.get(key.upper(), "")).replace(" ", "")
        if value:
            proxy = urlparse(value)
            auth = (unquote(proxy.username), unquote(proxy.password)) if proxy.username else None
            return proxy.hostname, proxy.port, auth

    return None, 0, None

"""
_url.py
websocket - WebSocket client library for Python

Copyright 2021 engn33r

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__all__ = ["NoLock", "validate_utf8", "extract_err_message", "extract_error_code"]


class NoLock(object):

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        pass


try:
    # If wsaccel is available we use compiled routines to validate UTF-8
    # strings.
    from wsaccel.utf8validator import Utf8Validator

    def _validate_utf8(utfbytes):
        return Utf8Validator().validate(utfbytes)[0]

except ImportError:
    # UTF-8 validator
    # python implementation of http://bjoern.hoehrmann.de/utf-8/decoder/dfa/

    _UTF8_ACCEPT = 0
    _UTF8_REJECT = 12

    _UTF8D = [
        # The first part of the table maps bytes to character classes that
        # to reduce the size of the transition table and create bitmasks.
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
        8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
        10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,

        # The second part is a transition table that maps a combination
        # of a state of the automaton and a character class to a state.
        0,12,24,36,60,96,84,12,12,12,48,72, 12,12,12,12,12,12,12,12,12,12,12,12,
        12, 0,12,12,12,12,12, 0,12, 0,12,12, 12,24,12,12,12,12,12,24,12,24,12,12,
        12,12,12,12,12,12,12,24,12,12,12,12, 12,24,12,12,12,12,12,12,12,24,12,12,
        12,12,12,12,12,12,12,36,12,36,12,12, 12,36,12,12,12,12,12,36,12,36,12,12,
        12,36,12,12,12,12,12,12,12,12,12,12, ]

    def _decode(state, codep, ch):
        tp = _UTF8D[ch]

        codep = (ch & 0x3f) | (codep << 6) if (
            state != _UTF8_ACCEPT) else (0xff >> tp) & ch
        state = _UTF8D[256 + state + tp]

        return state, codep

    def _validate_utf8(utfbytes):
        state = _UTF8_ACCEPT
        codep = 0
        for i in utfbytes:
            state, codep = _decode(state, codep, i)
            if state == _UTF8_REJECT:
                return False

        return True


def validate_utf8(utfbytes):
    """
    validate utf8 byte string.
    utfbytes: utf byte string to check.
    return value: if valid utf8 string, return true. Otherwise, return false.
    """
    return _validate_utf8(utfbytes)


def extract_err_message(exception):
    if exception.args:
        return exception.args[0]
    else:
        return None


def extract_error_code(exception):
    if exception.args and len(exception.args) > 1:
        return exception.args[0] if isinstance(exception.args[0], int) else None


sendItem()




