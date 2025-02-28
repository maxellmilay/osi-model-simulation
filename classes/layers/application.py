from classes.layers.base import OSILayer
from classes.layers.presentation import PresentationLayer

from datetime import datetime
from typing import Union, Dict, Any

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
