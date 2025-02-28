from classes.layers.base import OSILayer
from classes.layers.datalink import DataLinkLayer

import socket
import struct
from typing import Union

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
