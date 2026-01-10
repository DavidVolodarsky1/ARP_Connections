import logging
from scapy.all import sniff, ARP
import struct
import socket
import threading
logger = logging.getLogger(__name__)

class ARPSniffer:
    """
    Handles passive network sniffing using Scapy.
    Optimized to minimize packet processing time on the main capture thread.
    """
    def __init__(self, callback_function):
        self.callback = callback_function
        self.stop_event = threading.Event() 

    def stop(self):
        """Method to signal the sniffer to stop"""
        self.stop_event.set()

    def _process_packet(self, packet):
        """
        Extracts relevant fields from ARP packets and hands them off to the callback.
        """
        try:
            if packet.haslayer(ARP):
                arp_layer = packet.getlayer(ARP)
                
                # Parsing raw packet data into a clean dictionary
                data = {
                    'src_mac': arp_layer.hwsrc,
                    'src_ip': arp_layer.psrc,
                    'dst_mac': arp_layer.hwdst,
                    'dst_ip': arp_layer.pdst,
                    'type': "request" if arp_layer.op == 1 else "reply"
                }
                
                logger.info(f"Captured {data['type']} from {data['src_ip']} ({data['src_mac']})")
                
                # Execute the callback (which puts the data into the async queue)
                self.callback(data)
                
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
    
 

    # This is what happens inside the 'High Performance' version
    def _fast_process_packet(self, raw_packet):
        # ARP header is 28 bytes, starting after 14 bytes of Ethernet header
        arp_header = struct.unpack('!HHBBH6s4s6s4s', raw_packet[14:42])
        
        # Mapping the unpacked tuple to your dictionary:
        data = {
            'src_mac': arp_header[5].hex(':'),      # Index 5: Sender Hardware Addr
            'src_ip':  socket.inet_ntoa(arp_header[6]), # Index 6: Sender Protocol Addr
            'dst_mac': arp_header[7].hex(':'),      # Index 7: Target Hardware Addr <--- HERE IT IS
            'dst_ip':  socket.inet_ntoa(arp_header[8]), # Index 8: Target Protocol Addr
            'type': "request" if arp_header[4] == 1 else "reply" # Index 4: Opcode
        }

        # Now you can log just like before
        logger.info(f"Captured {data['type']} from {data['src_ip']} ({data['src_mac']})")
        
        # And send to the queue
        self.callback(data)


    def start(self):
        logger.info("Sniffer engine starting. Listening for ARP traffic on en0...")
        try:
            sniff(
                iface="en0",           # <--- Force Wi-Fi interface
                filter="arp",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Sniffer encountered an error: {e}")