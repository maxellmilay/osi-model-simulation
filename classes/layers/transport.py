from classes.layers.base import OSILayer
from classes.layers.network import NetworkLayer

import struct
from typing import Union

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
