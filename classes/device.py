from classes.layers.physical import PhysicalLayer
from classes.layers.datalink import DataLinkLayer
from classes.layers.network import NetworkLayer
from classes.layers.transport import TransportLayer
from classes.layers.session import SessionLayer
from classes.layers.presentation import PresentationLayer
from classes.layers.application import ApplicationLayer

class Device:
    def __init__(self, name, config):
        self.name = name
        
        # Initialize layers with configuration
        self.physical_layer = PhysicalLayer()
        self.data_link_layer = DataLinkLayer(
            self.physical_layer,
            mac_address=config['mac_address']
        )
        self.network_layer = NetworkLayer(
            self.data_link_layer,
            source_ip=config['source_ip'],
            destination_ip=config['destination_ip']
        )
        self.transport_layer = TransportLayer(self.network_layer)
        self.session_layer = SessionLayer(
            self.transport_layer,
            session_id=config['session_id']
        )
        self.presentation_layer = PresentationLayer(
            self.session_layer,
            encryption_key=config['encryption_key']
        )
        self.application_layer = ApplicationLayer(self.presentation_layer)

        # Register MAC-IP pair in ARP table
        DataLinkLayer.register_mac_ip_pair(
            config['mac_address'],
            config['source_ip']
        )

    def send_message(self, message):
        print(f"\n[{self.name}] Initiating message transmission")
        return self.application_layer.send(message)

    def receive_message(self, data):
        print(f"\n[{self.name}] Processing received message")
        return self.application_layer.receive(data)
