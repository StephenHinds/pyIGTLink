# -*- coding: utf-8 -*-
"""
Created on Tue Nov  3 19:17:05 2015

@author: Daniel Hoyer Iversen
"""

from __future__ import print_function
import crcmod
import numpy as np
import signal
import collections
import socket
import sys
import struct
import threading
import time
import select


if sys.version_info >= (3, 0):
    import socketserver as SocketServer
else:
    import SocketServer

IGTL_HEADER_VERSION = 1
IGTL_HEADER_VERSION_2 = 2
IGTL_IMAGE_HEADER_VERSION = 1
IGTL_HEADER_SIZE = 58

# 0   2                       14                                      34             42               50              58
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | V |          TYPE         |              DEVICE_NAME              |   TIME_STAMP  |   BODY_SIZE   |     CRC64     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# 0          58            72
# +----------+-------------+-------------------+-----------+
# | HEADER   | EXT_HEADER  | CONTENT           | META_DATA |
# +----------+-------------+-------------------+-----------+
#            | < -----------------Body-------------------> |
#
#  CONTENT =  BODY_SIZE - (EXT_HEADER_SIZE + METADATA_SIZE)


class PyIGTLink(SocketServer.TCPServer):
    """ For streaming data over TCP with IGTLink"""
    def __init__(self, port=18944, localServer=False, iface='eth0'):
        """
        port - port number
        """
        buffer_size = 100
        if localServer:
            host = "127.0.0.1"
        else:
            if sys.platform.startswith('win32'):
                host = socket.gethostbyname(socket.gethostname())
            elif sys.platform.startswith('linux'):
                import fcntl
                soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    ifname = iface
                    host = socket.inet_ntoa(fcntl.ioctl(soc.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
                    # http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
                except: # noqa
                    ifname = 'lo'
                    host = socket.inet_ntoa(fcntl.ioctl(soc.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
            else:
                # the iface can be also an ip address in systems where the previous code won't work
                host = iface

        SocketServer.TCPServer.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, (host, port), TCPRequestHandler)

        self.message_queue = collections.deque(maxlen=buffer_size)
        self.message_in_queue = collections.deque(maxlen=buffer_size)

        self.lock_server_thread = threading.Lock()

        self._connected = False
        self.shuttingdown = False

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        server_thread = threading.Thread(target=self.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        thread = threading.Thread(target=self._print_ip_adress_and_port_no)
        thread.daemon = True
        thread.start()

    def get_ip_adress(self):
        return self.server_address[0]

    def get_port_no(self):
        return self.server_address[1]

    def add_message_to_send_queue(self, message, wait=False):
        """
            Returns True if sucessfull
        """
        if not isinstance(message, MessageBase) or not message.is_valid():
            _print("Warning: Only accepts valid messages of class message")
            return False

        if self._connected:
            with self.lock_server_thread:
                self.message_queue.append(message)  # copy.deepcopy(message))
            while wait and len(self.message_queue) > 0:
                time.sleep(0.001)
        else:
            if len(self.message_queue) > 0:
                with self.lock_server_thread:
                    self.message_queue.clear()
        return True

    def _signal_handler(self, signum, stackframe):
        if signum == signal.SIGTERM or signum == signal.SIGINT:
            self.close_server()
            _print('YOU KILLED ME, BUT I CLOSED THE SERVER BEFORE I DIED')
            sys.exit(signum)

    def is_connected(self):
        return self._connected

    def update_connected_status(self, val):
        self._connected = val

    def close_server(self):
        """Will close connection and shutdown server"""
        self._connected = False
        with self.lock_server_thread:
            self.shuttingdown = True
        self.shutdown()
        self.server_close()
        _print("\nServer closed\n")

    def _print_ip_adress_and_port_no(self):
        while True:
            while not self._connected:
                with self.lock_server_thread:
                    if self.shuttingdown:
                        _print("No connections\nIp adress: " + str(self.get_ip_adress()) + "\nPort number: " + str(self.get_port_no()))
                        break
                time.sleep(5)
            time.sleep(10)
            with self.lock_server_thread:
                if self.shuttingdown:
                    break


class TCPRequestHandler(SocketServer.BaseRequestHandler):
    """
    Help class for PyIGTLink
    """
    def handle(self):
        self.server.update_connected_status(True)
        CONNECTION_LIST = []
        CONNECTION_LIST.append(self.request)

        while True:
            read_sockets, write_sockets, error_sockets = select.select(CONNECTION_LIST, [], [],0)
            if len(self.server.message_queue) > 0:
                with self.server.lock_server_thread:
                    message = self.server.message_queue.popleft()
                    response_data = message.get_binary_message()
                    # print "Send: " + str(message._timestamp)
                    try:
                        self.request.sendall(response_data)
                    except Exception as exp:
                        self.server.update_connected_status(False)
                        _print('ERROR, FAILED TO SEND DATA. \n'+str(exp))
                        return
            else:
                time.sleep(1/1000.0)
                with self.server.lock_server_thread:
                    if self.server.shuttingdown:
                        _print('shutting down')
                        break
            for sock in read_sockets:
                if sock == self.request:
                    try:
                        _print("incoming data")

                        reply = []
                        len_count = 0

                        while len_count < IGTL_HEADER_SIZE:
                            reply.append(self.request.recv(IGTL_HEADER_SIZE - len_count))
                            len_count += len(reply[-1])
                        reply = b''.join(reply)

                        base_message = MessageBase()
                        package = base_message.unpack(reply)
                        data = None

                        reply = []
                        len_count = 0
                        while len_count < package['data_len']:
                            reply.append(self.request.recv(package['data_len'] - len_count))
                            len_count += len(reply[-1])
                        reply = b''.join(reply)

                        if 'STRING' in package['type']:
                            str_message = StringMessage(package)
                            data, valid = str_message.unpack_body(reply)
                            data['timestamp'] = package['timestamp']
                            if not valid:
                                data = None
                            else:
                                print(data['data'])

                        if 'STATUS' in package['type']:
                            status_message = StatusMessage()
                            data, valid = status_message.unpack_body(reply)
                            data['timestamp'] = package['timestamp']
                            if not valid:
                                data = None
                            else:
                                print(data['subcode'], data['code'], data['error_name'],data['message'])

                        if 'TRANSFORM' in package['type']:
                            tform_message = TransformMessage(np.eye(4))
                            data, valid = tform_message.unpack_body(reply)
                            data['timestamp'] = package['timestamp']
                            if not valid:
                                data = None
                            else:
                                print(data['data'])

                        if 'IMAGE' in package['type']:
                            image_message = ImageMessage(np.zeros((2, 2), dtype=np.uint8))
                            data, valid = image_message.unpack_body(reply)
                            data['timestamp'] = package['timestamp']
                            if not valid:
                                data = None
                            else:
                                print(data['data'])

                        self.server.message_in_queue.append(data)
                    except Exception as e:
                        _print(str(e))
                else:
                    _print("new connection?")
                    try:
                        break
                    except:
                        _print("broken connection")
                        break


# Help functions and help classes:
def _print(text):
    print("**********PyIGTLink*********\n" + text + "\n****************************")


# http://openigtlink.org/protocols/v2_header.html
class MessageBase(object):
    """message"""
    def __init__(self):
        self._valid_message = False
        # Version number The version number field specifies the header format version. Currently the version number is 1.
        # Please note that this is different from the protocol version.
        self._version = IGTL_HEADER_VERSION
        # The type name field is an ASCII character string specifying the type of the data contained in
        # the message body e.g. TRANSFORM. The length of the type name must be within 12 characters.
        self._name = ""
        # The device name field contains an ASCII character string specifying the name of the the message.
        self._device_name = ""
        # The timestamp field contains a 64-bit timestamp indicating when the data is generated.
        # Please refer http://openigtlink.org/protocols/v2_timestamp.html for the format of the 64-bit timestamp.
        self._timestamp = time.time() * 1000

        self._endian = ">"  # big-endian

        self._binary_body = None
        self._binary_head = None
        self._body_pack_size = 0

        if self._version == 2:
            self._binary_extended_header = None
            self._extended_header = None
            # extended_header_size, meta_data_header_size, meta_data_size, message_id
            self._metadata = None
            self._metadata_header = None
            self._metadata_header_size = 0
            self._extended_header_size = 0
            self._metadata_size = 0
            self._metadata_message_id = 0
            self._message_id = None
            self._reserved = 0
            # self._metadata_map = None
            self._content = None
            self._index_count = 0

            # temporary
            self._key_size = 0
            self._value_encoding = 0
            self._value_size = 0
            self._key = ""
            self._value = "="
            self._metadata_map = []

    def pack_extended_header(self):
        binary_message = struct.pack(self._endian+"H", self._extended_header_size)
        binary_message += binary_message + struct.pack(self._endian+"H", self._metadata_size)
        binary_message += binary_message + struct.pack(self._endian + "I", self._message_id)
        binary_message += binary_message + struct.pack(self._endian + "I", self._reserved)

        self._binary_extended_header = binary_message

    def unpack_extended_header(self, message):
        (self._extended_header_size, self._metadata_size, self._message_id, self._reserved) \
        = struct.unpack(">HII", message)

    def pack_metadata(self):
        '''
        # Metadata header:
        # pack index count
        # for each index: pack the lengths: key size, value encoding
        binary_message = struct.pack(self._endian+"H", self._index_count)

        for
        binary_message += binary_message + struct.pack(self._endian+"H", self._metadata_size)


        # Metadata body:
        # pack the key and pack the value
        binary_message = struct.pack(self._endian+"H", self._extended_header_size)
        binary_message = struct.pack()
        '''

    def unpack_metadata(self, message):
        self._index_count = struct.unpack(">H", message)

    def pack(self):
        binary_body = self.get_binary_body()
        body_size = self.get_body_pack_size()
        crc = CRC64(binary_body)
        _timestamp1 = int(self._timestamp / 1000)
        _timestamp2 = _igtl_nanosec_to_frac(int((self._timestamp / 1000.0 - _timestamp1)*10**9))
        binary_message = struct.pack(self._endian+"H", self._version)
        binary_message = binary_message + struct.pack(self._endian+"12s", self._name.encode('utf-8'))
        binary_message = binary_message + struct.pack(self._endian+"20s", self._device_name.encode('utf-8'))
        binary_message = binary_message + struct.pack(self._endian+"II", _timestamp1, _timestamp2)
        binary_message = binary_message + struct.pack(self._endian+"Q", body_size)
        binary_message = binary_message + struct.pack(self._endian+"Q", crc)

        self._binary_head = binary_message

    def unpack(self, message):
        s = struct.Struct('> H 12s 20s II Q Q')  # big-endian
        values = s.unpack(message)
        self._version = values[0]
        self._name = str(values[1], 'utf-8').rstrip('\0')
        self._device_name = str(values[2], 'utf-8').rstrip('\0')

        seconds = float(values[3])
        frac_of_second = values[4]
        nanoseconds = float(_igtl_frac_to_nanosec(frac_of_second))

        timestamp = seconds + (nanoseconds * 1e-9)

        self._body_size = values[5]

        valid = False

        return {'type': self._name,
                'device_name': self._device_name,
                'timestamp': self._timestamp,
                'valid': valid,
                'data_len': self._body_size}

    def get_binary_message(self):
        if not self._binary_head:
            self.pack()
        return self._binary_head + self.get_binary_body()

    def get_binary_body(self):
        if not self._binary_body:
            self.pack_body()
        return self._binary_body

    def pack_body(self):
        self._binary_body = b""

    def is_valid(self):
        return self._valid_message

    def get_body_pack_size(self):
        return self._body_pack_size


class CommandMessage(MessageBase):
    def __init__(self, command, command_id, command_name, encoding, timestamp=None, device_name='', ):
        MessageBase.__init__(self)
        self._valid_message = True
        self._name = "STATUS"
        self._device_name = device_name
        if timestamp:
            self._timestamp = timestamp
        self._command_id = command_id
        self._command_name = command_name
        self._encoding = encoding
        self.command = command


    def pack_body(self):
        # COMMAND_ID as uint32 (The unique ID of this command)
        binary_message = struct.pack(self._endian + "I", self._command_id)

        # COMMAND_NAME as uint8[IGT_COMMAND_SIZE] (The name of the command)
        binary_message += struct.pack(self._endian + "B", self._command_name)

        # ENCODING as uint16 (Character encoding type as MIBenum)
        binary_message += struct.pack(self._endian + "H", self._encoding)

        self._body_pack_size = len(binary_message)

        self._binary_body = binary_message

    def unpack_body(self, message):
        (self._command_id, self._command_name, self._encoding, self._message) \
            = struct.unpack(">Hq20s%ds" % (len(message) - 30), message)
        self._error_name = str(self._error_name, 'ascii')
        self._message = str(self._message, 'ascii')
        valid = True
        return {'type': 'String',
                'code': self._code,
                'subcode': self._sub_code,
                'error_name': self._error_name,
                'message': self._message}, True


class StatusMessage(MessageBase):
    __maxCharLength_ERROR_NAME = 20
    __length_STATUS_MESSAGE = None

    _messageCode = (['Invalid packet - 0 is not used', \
                     'OK (Default status)', \
                     'Unknown error', \
                     'Panic mode (emergency)', \
                     'Not found (file, configuration, device etc)', \
                     'Access denied', \
                     'Busy', \
                     'Time out - Connection lost', \
                     'Overflow - Can\'t be reached', \
                     'Checksum error', \
                     'Configuration error', \
                     'Not enough resource (memory, storage etc)', \
                     'Illegal/Unknown instruction (or feature not implemented / Unknown command received)', \
                     'Device not ready (starting up)', \
                     'Manual mode (device does not accept commands)', \
                     'Device disabled', \
                     'Device not present', \
                     'Device version not known', \
                     'Hardware failure', \
                     'Exiting / shut down in progress'])

    def __init__(self, code = 1, sub_code = 0, error_name ='OK', message = '', timestamp=None, device_name = '', ):
        MessageBase.__init__(self)
        self._valid_message = True
        self._name = "STATUS"
        self._device_name = device_name
        if timestamp:
            self._timestamp = timestamp
        self._code = code
        self._sub_code = sub_code
        self._error_name = error_name
        self._message = message

    def pack_body(self):
        # CODE as uint16 (Status code groups: 1-Ok, 2-Generic Error, ... (see below))
        binary_message = struct.pack(self._endian + "H", self._code)

        # SUB_CODE as int64 (Sub-code for the error (ex. 0x200 - file not found))
        binary_message += struct.pack(self._endian + "Q", self._sub_code)

        # ERROR_NAME as char[20] ("Error", "OK", "Warning" - can be anything, don't relay on this)
        self._error_name = bytes(self._error_name, 'ascii')
        binary_message += struct.pack(self._endian + "20s", self._error_name)

        # MESSAGE as char[BODY_SIZE-30] (Optional (English) description (ex. "File C:\test.ini not found"))
        self._message = bytes(self._message, 'ascii')
        binary_message += struct.pack(self._endian + "%ds" % len(self._message), self._message)

        self._body_pack_size = len(binary_message)

        self._binary_body = binary_message

    def unpack_body(self, message):
        (self._code, self._sub_code, self._error_name, self._message) \
            = struct.unpack(">Hq20s%ds" % (len(message) - 30), message)
        self._error_name = str(self._error_name, 'ascii')
        self._message = str(self._message, 'ascii')
        valid = True
        return {'type': 'String',
                'code': self._code,
                'subcode': self._sub_code,
                'error_name': self._error_name,
                'message': self._message}, True


class StringMessage(MessageBase):
    def __init__(self, message='', timestamp=None, device_name=''):
        MessageBase.__init__(self)
        self._valid_message = True
        self._name = "STRING"
        self._device_name = device_name
        if timestamp:
            self._timestamp = timestamp

        self._encoding = 3  # ASCII
        self._length = len(message)
        self._string = message

    def pack_body(self):
        # ENCODING as uint16 (Character encoding type as MIBenum value. Default=3)
        binary_message = struct.pack(self._endian+"H", self._encoding)

        # LENGTH as uint16 (Length of string (bytes))
        binary_message += struct.pack(self._endian + "H", self._length)

        # STRING as uint8 (Byte array of the string)
        self._string= bytes(self._string, 'ascii')  # Or other appropriate encoding
        binary_message += struct.pack(self._endian + "%ds" % len(self._string), self._string)

        self._body_pack_size = len(binary_message)

        self._binary_body = binary_message

    def unpack_body(self, message):
        (self._encoding, self._length, self._string) = struct.unpack(">HH%ds" % (len(message) - 4), message)
        self._string = str(self._string, 'ascii')
        print(self._string)
        valid = True
        return {'type': 'String',
                'data': self._string}, True


# http://openigtlink.org/protocols/v2_image.html
class ImageMessage(MessageBase):
    def __init__(self, image, spacing=[1, 1, 1], timestamp=None, device_name=''):
        """
        Image package
        image - image data
        spacing - spacing in mm
        timestamp - milliseconds since 1970
        """

        MessageBase.__init__(self)
        self._valid_message = True
        self._name = "IMAGE"
        self._device_name = device_name
        if timestamp:
            self._timestamp = timestamp

        try:
            self._data = np.asarray(image)
        except Exception as exp:
            _print('ERROR, INVALID IMAGE. \n' + str(exp))
            self._valid_message = False
            return

        if len(self._data.shape) < 2:
            self._valid_message = False
            _print('ERROR, INVALID IMAGE SIZE. \n')
            return


# Only int8 is suppoerted now
#        if self._data.dtype == np.int8:
#            self._datatype_s = 2
#            self._format_data = "b"
#        elif self._data.dtype == np.uint8:
#            self._datatype_s = 3
#            self._format_data = "B"
#        elif self._data.dtype == np.int16:
#            self._datatype_s = 4
#            self._format_data = "h"
#        elif self._data.dtype == np.uint16:
#            self._datatype_s = 5
#            self._format_data = "H"
#        elif self._data.dtype == np.int32:
#            self._datatype_s = 6
#            self._format_data = "i"
#        elif self._data.dtype == np.uint32:
#            self._datatype_s = 7
#            self._format_data = "I"
#        elif self._data.dtype == np.float32:
#            self._datatype_s = 10
#            self._format_data = "f"
#        elif self._data.dtype == np.float64:
#            self._datatype_s = 11
#            self._format_data = "f"
#        else:
#            pass
        self._data = np.array(self._data, dtype=np.uint8)
        self._datatype_s = 3
        self._format_data = "B"

        self._spacing = spacing
        self._matrix = np.identity(4)  # A matrix representing the origin and the orientation of the image.

    def pack_body(self):
        binary_message = struct.pack(self._endian+"H", IGTL_IMAGE_HEADER_VERSION)
        # Number of Image Components (1:Scalar, >1:Vector). (NOTE: Vector data is stored fully interleaved.)
        binary_message += struct.pack(self._endian+"B", len(self._data.shape) - 1)
        binary_message += struct.pack(self._endian+"B", self._datatype_s)

        if self._data.dtype.byteorder == "<":
            byteorder = "F"
            binary_message += struct.pack(self._endian+"B", 2)  # Endian for image data (1:BIG 2:LITTLE)
            # (NOTE: values in image header is fixed to BIG endian)
        else:
            self._data.dtype.byteorder == ">"
            byteorder = "C"
            binary_message += struct.pack(self._endian+"B", 1)  # Endian for image data (1:BIG 2:LITTLE)
            # (NOTE: values in image header is fixed to BIG endian)

        binary_message += struct.pack(self._endian+"B", 1)  # image coordinate (1:RAS 2:LPS)

        binary_message += struct.pack(self._endian+"H", self._data.shape[1])
        binary_message += struct.pack(self._endian+"H", self._data.shape[0])
        if len(self._data.shape) > 2:
            binary_message += struct.pack(self._endian+"H", self._data.shape[2])
        else:
            binary_message += struct.pack(self._endian+"H", 1)

        origin = np.zeros(3)
        norm_i = np.zeros(3)
        norm_j = np.zeros(3)
        norm_k = np.zeros(3)
        for i in range(3):
            norm_i[i] = self._matrix[i][0]
            norm_j[i] = self._matrix[i][1]
            norm_k[i] = self._matrix[i][2]
            origin[i] = self._matrix[i][3]

        binary_message += struct.pack(self._endian+"f", norm_i[0] * self._spacing[0])
        binary_message += struct.pack(self._endian+"f", norm_i[1] * self._spacing[0])
        binary_message += struct.pack(self._endian+"f", norm_i[2] * self._spacing[0])
        binary_message += struct.pack(self._endian+"f", norm_j[0] * self._spacing[1])
        binary_message += struct.pack(self._endian+"f", norm_j[1] * self._spacing[1])
        binary_message += struct.pack(self._endian+"f", norm_j[2] * self._spacing[1])
        binary_message += struct.pack(self._endian+"f", norm_k[0] * self._spacing[2])
        binary_message += struct.pack(self._endian+"f", norm_k[1] * self._spacing[2])
        binary_message += struct.pack(self._endian+"f", norm_k[2] * self._spacing[2])
        binary_message += struct.pack(self._endian+"f", origin[0])
        binary_message += struct.pack(self._endian+"f", origin[1])
        binary_message += struct.pack(self._endian+"f", origin[2])

        binary_message += struct.pack(self._endian+"H", 0)      # Starting index of subvolume
        binary_message += struct.pack(self._endian+"H", 0)      # Starting index of subvolume
        binary_message += struct.pack(self._endian+"H", 0)      # Starting index of subvolume

        binary_message += struct.pack(self._endian+"H", self._data.shape[0])  # number of pixels of subvolume
        binary_message += struct.pack(self._endian+"H", self._data.shape[1])
        if len(self._data.shape) > 2:
            binary_message += struct.pack(self._endian+"H", self._data.shape[2])
        else:
            binary_message += struct.pack(self._endian+"H", 1)

        binary_message += self._data.tostring(byteorder)  # struct.pack(fmt,*data)
        self._body_pack_size = len(binary_message)

        self._binary_body = binary_message

    def unpack_body(self, message):
        header_portion_len = 12 + (12 * 4) + 12

        s_head = \
            struct.Struct('> H B B B B H H H f f f f f f f f f f f f H H H H H H')
        values_header = s_head.unpack(message[:header_portion_len])

        endian = values_header[3]
        size_x = values_header[23]
        size_y = values_header[24]
        size_z = values_header[25]
        if endian == 2:
            endian = '<'
        else:
            endian = '>'

        values_img = message[header_portion_len:]

        dt = np.dtype(np.uint8)
        dt = dt.newbyteorder(endian)
        data = np.frombuffer(values_img, dtype=dt)

        data = np.squeeze(np.reshape(data, [size_y, size_x, size_z]))

        return {'type': 'IMAGE',
                'data': data}, True


class TransformMessage(MessageBase):
    def __init__(self, tform, timestamp=None, device_name=''):
        """
        Image package
        image - image data
        spacing - spacing in mm
        timestamp - milliseconds since 1970
        """

        MessageBase.__init__(self)
        self._valid_message = True
        self._name = "TRANSFORM"
        self._device_name = device_name
        if timestamp:
            self._timestamp = timestamp

        try:
            self._data = np.asarray(tform, dtype=np.float32)
        except Exception as exp:
            _print('ERROR, INVALID TRANSFORM. \n' + str(exp))
            self._valid_message = False
            return

        if len(self._data.shape) != 2:
            self._valid_message = False
            _print('ERROR, INVALID TRANSFORM SIZE. \n')
            return


# transforms are floats
#        if self._data.dtype == np.int8:
#            self._datatype_s = 2
#            self._format_data = "b"
#        elif self._data.dtype == np.uint8:
#            self._datatype_s = 3
#            self._format_data = "B"
#        elif self._data.dtype == np.int16:
#            self._datatype_s = 4
#            self._format_data = "h"
#        elif self._data.dtype == np.uint16:
#            self._datatype_s = 5
#            self._format_data = "H"
#        elif self._data.dtype == np.int32:
#            self._datatype_s = 6
#            self._format_data = "i"
#        elif self._data.dtype == np.uint32:
#            self._datatype_s = 7
#            self._format_data = "I"
#        elif self._data.dtype == np.float32:
#            self._datatype_s = 10
#            self._format_data = "f"
#        elif self._data.dtype == np.float64:
#            self._datatype_s = 11
#            self._format_data = "f"
#        else:
#            pass
        self._data = np.array(self._data, dtype=np.float32)
        self._datatype_s = 10
        self._format_data = "f"

        self._matrix = self._data  # A matrix representing the origin pose.

    def pack_body(self):
        # binary_message = struct.pack(self._endian+"H", IGTL_TRANSFORM_HEADER_VERSION)
        # transform data, following protocol specification
        binary_message = struct.pack(self._endian + "f", self._matrix[0, 0])  # R11
        binary_message += struct.pack(self._endian + "f", self._matrix[1, 0])  # R21
        binary_message += struct.pack(self._endian + "f", self._matrix[2, 0])  # R31

        binary_message += struct.pack(self._endian + "f", self._matrix[0, 1])  # R12
        binary_message += struct.pack(self._endian + "f", self._matrix[1, 1])  # R22
        binary_message += struct.pack(self._endian + "f", self._matrix[2, 1])  # R32

        binary_message += struct.pack(self._endian + "f", self._matrix[0, 2])  # R13
        binary_message += struct.pack(self._endian + "f", self._matrix[1, 2])  # R23
        binary_message += struct.pack(self._endian + "f", self._matrix[2, 2])  # R33

        binary_message += struct.pack(self._endian + "f", self._matrix[0, 3])  # TX
        binary_message += struct.pack(self._endian + "f", self._matrix[1, 3])  # TY
        binary_message += struct.pack(self._endian + "f", self._matrix[2, 3])  # TZ

        self._body_pack_size = len(binary_message)

        self._binary_body = binary_message

    def unpack_body(self, message):
        s = struct.Struct('> f f f f f f f f f f f f')
        values = s.unpack(message)
        self._matrix = np.asarray([[values[0], values[3], values[6], values[9]],
                                   [values[1], values[4], values[7], values[10]],
                                   [values[2], values[5], values[8], values[11]],
                                   [0, 0, 0, 1]])

        valid = True

        return {'type': 'TRANSFORM',
                'data': self._matrix}, valid


class ImageMessageMatlab(ImageMessage):
    def __init__(self, image, dim, spacing=[1, 1, 1], timestamp=None):
        """
        Image package from Matlab
        image - image data as vector  reshape(data,1,dim(1)*dim(2))
        dim - image dimension  [dim(1), dim(2)]
        spacing - spacing in mm
        timestamp - milliseconds since 1970
        """
        try:
            data = np.asarray(image)
        except Exception as e:
            _print('ERROR, INVALID IMAGE. \n' + str(e))
            self._valid_message = False
            return
        data = data.reshape(dim)
        ImageMessage.__init__(self, data, spacing, timestamp)


# http://slicer-devel.65872.n3.nabble.com/OpenIGTLinkIF-and-CRC-td4031360.html
CRC64 = crcmod.mkCrcFun(0x142F0E1EBA9EA3693, rev=False, initCrc=0x0000000000000000, xorOut=0x0000000000000000)


# https://github.com/openigtlink/OpenIGTLink/blob/cf9619e2fece63be0d30d039f57b1eb4d43b1a75/Source/igtlutil/igtl_util.c#L168
def _igtl_nanosec_to_frac(nanosec):
    base = 1000000000  # 10^9
    mask = 0x80000000
    r = 0x00000000
    while mask:
        base += 1
        base >>= 1
        if (nanosec >= base):
            r |= mask
            nanosec = nanosec - base
        mask >>= 1
    return r

# https://github.com/openigtlink/OpenIGTLink/blob/cf9619e2fece63be0d30d039f57b1eb4d43b1a75/Source/igtlutil/igtl_util.c#L193
def _igtl_frac_to_nanosec(frac):
    base = 1000000000 # 10^9
    mask = 0x80000000
    r = 0x00000000
    while mask:
        base += 1
        base >>= 1
        r += base if (frac & mask) else 0
        mask >>= 1
    return r



if __name__ == "__main__":
    """
    Usage:
    pyIGTLink.py
    Run as local server sending random tissue data

    """
    if len(sys.argv) == 1:
        print("\n\n   Run as server, sending random data\n\n  ")
        server = PyIGTLink(localServer=True)

        samples = 500
        beams = 100
        k = 0

        while True:
            if server.is_connected():
                k = k+1
                print(k)
                _data = np.random.randn(samples, beams)*50+100
                # data[:, :, 1] = data[:, :, 1] + 90
                image_message = ImageMessage(_data)
                transform_message = TransformMessage(np.eye(4).astype(dtype=np.float32))
                server.add_message_to_send_queue(image_message)
                server.add_message_to_send_queue(transform_message)
                string_message = StringMessage("hello")
                server.add_message_to_send_queue(string_message)
            time.sleep(0.1)
            print(server.is_connected())

    elif len(sys.argv) == 2:
        print("\n\n   Run as server, sending moving circle \n\n  ")
        server = PyIGTLink(localServer=True)

        n = 500
        r = 90

        k = 0
        while True:
            if server.is_connected():
                k = k+1
                print(k)
                a = np.mod(10*k, n)
                b = np.mod((400*k)/n+30, n)
                y, x = np.ogrid[-a:n-a, -b:n-b]
                mask = x*x + y*y <= r*r

                _data = np.ones((n, n))
                _data[mask] = 255

                print(_data.shape)

                image_message = ImageMessage(_data)
                server.add_message_to_send_queue(image_message)
            time.sleep(0.1)
