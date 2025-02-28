from abc import ABC, abstractmethod
import socket
import struct
import zlib
import json
import pickle
import random
from typing import Union, Tuple, Dict, Any
from datetime import datetime

from utils.cryptography import xor_encrypt_decrypt
from utils.logging import log_layer

class OSILayer(ABC):
    def _log_operation(self, operation: str, message: str, indent_level: int = 0, **extra):
        details = []
        for key, value in extra.items():
            if isinstance(value, bytes):
                value = value.hex()
            elif isinstance(value, dict):
                value = json.dumps(value, indent=2)
            details.append(f"{key}: {value}")
        
        full_message = f"{message}"
        if details:
            full_message += f" | {', '.join(details)}"
        
        log_layer(self.layer_name, operation, full_message, indent_level)

    @abstractmethod
    def send(self, data: bytes) -> bytes:
        """Process and send data to the next lower layer."""
        pass

    @abstractmethod
    def receive(self, data: bytes) -> bytes:
        """Process and receive data from the lower layer."""
        pass

class PhysicalLayer(OSILayer):
    def __init__(self, error_rate: float = 0.01):
        self.layer_name = "Physical"
        self.error_rate = error_rate

    def _simulate_noise(self, data: bytes) -> bytes:
        # Simulate signal interference
        if random.random() < self.error_rate:
            pos = random.randint(0, len(data) - 1)
            noise_byte = random.randint(0, 255)
            corrupted = data[:pos] + bytes([noise_byte]) + data[pos + 1:]
            self._log_operation("NOISE", "Signal corruption", 2,
                              position=pos,
                              original_byte=data[pos],
                              noise_byte=noise_byte)
            return corrupted
        return data

    def send(self, data: bytes) -> bytes:
        # Convert to Manchester encoding (simulated)
        self._log_operation("SEND", "Raw data", 0, input_bytes=data)
        encoded = b''.join(bytes([b, ~b & 0xFF]) for b in data)
        self._log_operation("SEND", "Manchester encoded", 1, encoded_bytes=encoded)
        
        result = self._simulate_noise(encoded)
        if result != encoded:
            self._log_operation("SEND", "Noise applied", 1, corrupted_bytes=result)
        return result

    def receive(self, data: bytes) -> bytes:
        # Decode Manchester encoding (simulated)
        self._log_operation("RECEIVE", "Raw signal", 0, signal=data)
        decoded = bytes(data[i] for i in range(0, len(data), 2))
        self._log_operation("RECEIVE", "Manchester decoded", 1, decoded_bytes=decoded)
        return decoded

class DataLinkLayer(OSILayer):
    def __init__(self, physical_layer: PhysicalLayer, mac_address: str):
        self.physical_layer = physical_layer
        self.mac_address = mac_address.replace(':', '')
        self.layer_name = "DataLink"

    def _calculate_crc(self, data: bytes) -> int:
        return zlib.crc32(data) & 0xFFFFFFFF

    def send(self, data: bytes) -> bytes:
        # Create Ethernet II frame structure
        self._log_operation("SEND", "Creating Ethernet frame", 0, payload_size=len(data))
        
        dest_mac = b'\xFF' * 6  # Broadcast
        source_mac = bytes.fromhex(self.mac_address)
        length = len(data)
        ethertype = struct.pack('!H', 0x0800)  # IPv4
        crc = struct.pack('!L', self._calculate_crc(data))
        
        self._log_operation("SEND", "Frame details", 1,
                          dest_mac=dest_mac.hex(),
                          source_mac=source_mac.hex(),
                          ethertype=ethertype.hex(),
                          crc=crc.hex())
        
        frame = dest_mac + source_mac + ethertype + data + crc
        return self.physical_layer.send(frame)

    def receive(self, data: bytes) -> Union[bytes, None]:
        raw_frame = self.physical_layer.receive(data)
        self._log_operation("RECEIVE", "Processing frame", 0, frame_size=len(raw_frame))
        
        if len(raw_frame) < 14:  # Minimum Ethernet frame size
            self._log_operation("RECEIVE", "Invalid frame size", 1, size=len(raw_frame))
            return None

        dest_mac = raw_frame[:6]
        source_mac = raw_frame[6:12]
        ethertype = raw_frame[12:14]
        payload = raw_frame[14:-4]
        received_crc = raw_frame[-4:]

        self._log_operation("RECEIVE", "Frame parsed", 1,
                          dest_mac=dest_mac.hex(),
                          source_mac=source_mac.hex(),
                          ethertype=ethertype.hex(),
                          crc=received_crc.hex())

        calculated_crc = self._calculate_crc(payload)
        if calculated_crc != struct.unpack('!L', received_crc)[0]:
            self._log_operation("RECEIVE", "CRC check failed", 1,
                              expected=calculated_crc,
                              received=struct.unpack('!L', received_crc)[0])
            return None
            
        self._log_operation("RECEIVE", "Frame validated", 1)
        return payload

class NetworkLayer(OSILayer):
    def __init__(self, data_link_layer: DataLinkLayer, source_ip: str, destination_ip: str):
        self.data_link_layer = data_link_layer
        self.source_ip = socket.inet_aton(source_ip)
        self.destination_ip = socket.inet_aton(destination_ip)
        self.layer_name = "Network"
        self.packet_id = 0

    def send(self, data: bytes) -> bytes:
        # Create IPv4 header
        self._log_operation("SEND", "Creating IP packet", 0)
        
        version_ihl = bytes([0x45])  # IPv4, IHL=5 words
        tos = bytes([0x00])
        total_length = struct.pack('!H', 20 + len(data))
        identification = struct.pack('!H', self.packet_id)
        self.packet_id += 1
        flags_fragment = bytes([0x40, 0x00])  # Don't Fragment
        ttl = bytes([64])
        protocol = bytes([6])  # TCP
        checksum = bytes([0x00, 0x00])  # Simplified
        
        self._log_operation("SEND", "IP header details", 1,
                          version="IPv4",
                          total_length=len(data) + 20,
                          packet_id=self.packet_id,
                          ttl=64,
                          protocol="TCP",
                          source_ip=socket.inet_ntoa(self.source_ip),
                          dest_ip=socket.inet_ntoa(self.destination_ip))
        
        header = (version_ihl + tos + total_length + identification +
                 flags_fragment + ttl + protocol + checksum +
                 self.source_ip + self.destination_ip)
        
        return self.data_link_layer.send(header + data)

    def receive(self, data: bytes) -> Union[bytes, None]:
        packet = self.data_link_layer.receive(data)
        self._log_operation("RECEIVE", "Processing IP packet", 0)
        
        if packet is None or len(packet) < 20:
            self._log_operation("RECEIVE", "Invalid packet size", 1)
            return None

        header = packet[:20]
        payload = packet[20:]
        
        # Basic header validation
        version_ihl = header[0]
        if version_ihl >> 4 != 4:  # Check IPv4
            self._log_operation("RECEIVE", "Invalid IP version", 1, version=version_ihl >> 4)
            return None
            
        self._log_operation("RECEIVE", "Packet validated", 1,
                          version="IPv4",
                          total_length=len(packet),
                          ttl=header[8])
        return payload

class TransportLayer(OSILayer):
    def __init__(self, network_layer: NetworkLayer):
        self.network_layer = network_layer
        self.layer_name = "Transport"
        self.sequence_number = 0
        self.ack_number = 0
        self.window_size = 65535
        self.mss = 1460  # Maximum Segment Size

    def _create_tcp_header(self, data: bytes, flags: int) -> bytes:
        source_port = struct.pack('!H', 12345)
        dest_port = struct.pack('!H', 80)
        seq_num = struct.pack('!L', self.sequence_number)
        ack_num = struct.pack('!L', self.ack_number)
        offset_reserved_flags = struct.pack('!H', (5 << 12) | flags)  # 5 words, flags
        window = struct.pack('!H', self.window_size)
        checksum = struct.pack('!H', 0)  # Simplified
        urgent_ptr = struct.pack('!H', 0)

        return (source_port + dest_port + seq_num + ack_num +
                offset_reserved_flags + window + checksum + urgent_ptr)

    def send(self, data: bytes) -> bytes:
        # Split data into MSS-sized segments if needed
        segments = [data[i:i + self.mss] for i in range(0, len(data), self.mss)]
        
        # For simulation, we'll just send the first segment
        flags = 0x018  # PSH + ACK
        header = self._create_tcp_header(segments[0], flags)
        self.sequence_number += len(segments[0])
        
        self._log_operation("SEND", "TCP segment details", 1,
                          sequence_number=self.sequence_number,
                          ack_number=self.ack_number,
                          flags="PSH+ACK",
                          window_size=self.window_size,
                          segment_size=len(segments[0]))
        
        return self.network_layer.send(header + segments[0])

    def receive(self, data: bytes) -> Union[bytes, None]:
        segment = self.network_layer.receive(data)
        self._log_operation("RECEIVE", "Processing TCP segment", 0)
        
        if segment is None or len(segment) < 20:  # Minimum TCP header size
            self._log_operation("RECEIVE", "Invalid segment size", 1)
            return None

        header = segment[:20]
        payload = segment[20:]
        
        # Update acknowledgment number
        received_seq = struct.unpack('!L', header[4:8])[0]
        self.ack_number = received_seq + len(payload)
        
        self._log_operation("RECEIVE", "Segment processed", 1,
                          received_seq=received_seq,
                          ack_number=self.ack_number,
                          payload_size=len(payload))
        return payload

class SessionLayer(OSILayer):
    def __init__(self, transport_layer: TransportLayer, session_id: str):
        self.transport_layer = transport_layer
        self.session_id = session_id
        self.layer_name = "Session"
        self.sequence = 0
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def _create_session_header(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'sequence': self.sequence,
            'timestamp': datetime.now().isoformat(),
            'type': 'DATA'
        }

    def send(self, data: bytes) -> bytes:
        self._log_operation("SEND", "Creating session data", 0,
                          session_id=self.session_id,
                          sequence=self.sequence)
        
        header = self._create_session_header()
        self.sequence += 1
        
        # Store session state
        self.sessions[self.session_id] = {
            'last_sequence': self.sequence,
            'last_activity': header['timestamp']
        }
        
        self._log_operation("SEND", "Session state updated", 1,
                          session_state=self.sessions[self.session_id])
        
        session_data = {
            'header': header,
            'payload': data.hex()  # Convert bytes to hex for JSON serialization
        }
        
        return self.transport_layer.send(json.dumps(session_data).encode())

    def receive(self, data: bytes) -> Union[bytes, None]:
        raw_data = self.transport_layer.receive(data)
        self._log_operation("RECEIVE", "Processing session data", 0)
        
        if raw_data is None:
            self._log_operation("RECEIVE", "No data received", 1)
            return None

        try:
            session_data = json.loads(raw_data.decode())
            header = session_data['header']
            
            # Validate session
            self._log_operation("RECEIVE", "Session validation", 1,
                              received_session=header['session_id'],
                              received_sequence=header['sequence'])
            
            if (header['session_id'] != self.session_id or
                header['sequence'] <= self.sessions.get(self.session_id, {}).get('last_sequence', -1)):
                self._log_operation("RECEIVE", "Session validation failed", 2)
                return None
            
            # Update session state
            self.sessions[header['session_id']] = {
                'last_sequence': header['sequence'],
                'last_activity': header['timestamp']
            }
            
            self._log_operation("RECEIVE", "Session state updated", 1,
                              session_state=self.sessions[header['session_id']])
            
            return bytes.fromhex(session_data['payload'])
        except (json.JSONDecodeError, KeyError) as e:
            self._log_operation("RECEIVE", "Session data parsing error", 1,
                              error=str(e))
            return None

class PresentationLayer(OSILayer):
    def __init__(self, session_layer: SessionLayer, encryption_key: int):
        self.session_layer = session_layer
        self.encryption_key = encryption_key
        self.layer_name = "Presentation"
        self.supported_formats = {
            'json': {'content_type': 'application/json', 'encoding': 'utf-8'},
            'pickle': {'content_type': 'application/python-pickle', 'encoding': 'binary'},
            'plain': {'content_type': 'text/plain', 'encoding': 'utf-8'}
        }

    def _encode_data(self, data: Any, format: str = 'json') -> Tuple[bytes, str]:
        if format == 'json':
            return json.dumps(data).encode(), 'json'
        elif format == 'pickle':
            return pickle.dumps(data), 'pickle'
        else:  # plain
            return str(data).encode(), 'plain'

    def _decode_data(self, data: bytes, format: str) -> Any:
        if format == 'json':
            return json.loads(data.decode())
        elif format == 'pickle':
            return pickle.loads(data)
        else:  # plain
            return data.decode()

    def send(self, data: Any, format: str = 'json') -> bytes:
        self._log_operation("SEND", "Processing data", 0,
                          format=format,
                          content_type=self.supported_formats[format]['content_type'])
        
        encoded_data, format_type = self._encode_data(data, format)
        self._log_operation("SEND", "Data encoded", 1,
                          format=format_type,
                          size=len(encoded_data))
        
        # Compress
        compressed = zlib.compress(encoded_data)
        self._log_operation("SEND", "Data compressed", 1,
                          original_size=len(encoded_data),
                          compressed_size=len(compressed))
        
        # Encrypt (simplified)
        encrypted = bytes([b ^ self.encryption_key for b in compressed])
        self._log_operation("SEND", "Data encrypted", 1,
                          encrypted_size=len(encrypted))
        
        # Create metadata
        metadata = {
            'format': format_type,
            'compressed': True,
            'encrypted': True,
            'content_type': self.supported_formats[format_type]['content_type']
        }
        
        # Combine metadata and payload
        package = {
            'metadata': metadata,
            'payload': encrypted.hex()
        }
        
        return self.session_layer.send(json.dumps(package).encode())

    def receive(self, data: bytes) -> Union[Any, None]:
        raw_data = self.session_layer.receive(data)
        self._log_operation("RECEIVE", "Processing data", 0)
        
        if raw_data is None:
            self._log_operation("RECEIVE", "No data received", 1)
            return None

        try:
            package = json.loads(raw_data.decode())
            metadata = package['metadata']
            payload = bytes.fromhex(package['payload'])
            
            self._log_operation("RECEIVE", "Data metadata", 1,
                              metadata=metadata)
            
            # Decrypt
            decrypted = bytes([b ^ self.encryption_key for b in payload])
            self._log_operation("RECEIVE", "Data decrypted", 1,
                              decrypted_size=len(decrypted))
            
            # Decompress
            decompressed = zlib.decompress(decrypted)
            self._log_operation("RECEIVE", "Data decompressed", 1,
                              original_size=len(payload),
                              decompressed_size=len(decompressed))
            
            # Decode according to format
            result = self._decode_data(decompressed, metadata['format'])
            self._log_operation("RECEIVE", "Data decoded", 1,
                              format=metadata['format'])
            
            return result
        except Exception as e:
            self._log_operation("RECEIVE", "Data processing error", 1,
                              error=str(e))
            return None

class ApplicationLayer(OSILayer):
    def __init__(self, presentation_layer: PresentationLayer):
        self.presentation_layer = presentation_layer
        self.layer_name = "Application"
        self.supported_protocols = {'HTTP', 'FTP', 'SMTP'}

    def _create_http_request(self, method: str, path: str, headers: Dict[str, str], body: Any) -> Dict[str, Any]:
        return {
            'protocol': 'HTTP/1.1',
            'method': method,
            'path': path,
            'headers': headers,
            'body': body
        }

    def _create_http_response(self, status_code: int, body: Any) -> Dict[str, Any]:
        return {
            'protocol': 'HTTP/1.1',
            'status_code': status_code,
            'status_text': 'OK' if status_code == 200 else 'Error',
            'headers': {
                'Content-Type': 'application/json',
                'Date': datetime.now().isoformat()
            },
            'body': body
        }

    def send(self, data: Any, protocol: str = 'HTTP') -> bytes:
        self._log_operation("SEND", "Creating request", 0,
                          protocol=protocol)
        
        if protocol not in self.supported_protocols:
            self._log_operation("SEND", "Protocol not supported", 1,
                              protocol=protocol)
            raise ValueError(f"Unsupported protocol: {protocol}")

        if protocol == 'HTTP':
            request = self._create_http_request(
                method='POST',
                path='/',
                headers={
                    'Host': 'example.com',
                    'Content-Type': 'application/json',
                    'Date': datetime.now().isoformat()
                },
                body=data
            )
            self._log_operation("SEND", "HTTP request created", 1,
                              method='POST',
                              path='/',
                              headers=request['headers'])
            return self.presentation_layer.send(request, format='json')
        
        # Add other protocols as needed
        return self.presentation_layer.send(data)

    def receive(self, data: bytes) -> Union[Any, None]:
        received_data = self.presentation_layer.receive(data)
        self._log_operation("RECEIVE", "Processing response", 0)
        
        if received_data is None:
            self._log_operation("RECEIVE", "No data received", 1)
            return None

        if isinstance(received_data, dict) and received_data.get('protocol') == 'HTTP/1.1':
            # Process HTTP response
            self._log_operation("RECEIVE", "HTTP response", 1,
                              status_code=received_data.get('status_code'),
                              headers=received_data.get('headers'))
            return received_data.get('body')
        
        self._log_operation("RECEIVE", "Raw data response", 1)
        return received_data
