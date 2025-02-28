from classes.layers.base import OSILayer
from classes.layers.session import SessionLayer

import json
import pickle
import zlib
from typing import Union, Tuple, Any

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
