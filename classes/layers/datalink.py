from classes.layers.base import OSILayer
from classes.layers.physical import PhysicalLayer

import struct
import zlib
from typing import Union

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
