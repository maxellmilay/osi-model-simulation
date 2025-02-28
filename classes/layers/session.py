from classes.layers.base import OSILayer
from classes.layers.transport import TransportLayer

from typing import Union, Dict, Any
from datetime import datetime
import json

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
