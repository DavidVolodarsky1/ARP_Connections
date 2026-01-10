import networkx as nx
import matplotlib.pyplot as plt
from models import NetworkNode, NetworkEdge # ודא שאתה מייבא את המודלים
import time # לוודא שזמן זמין
import matplotlib
matplotlib.use('Agg') # 'Agg' is for writing to file ONLY (no window needed)
import time
import os
import logging
import json
from networkx.readwrite import json_graph
from definitions import MAX_AGE_SECONDS

# Get the logger defined in main
logger = logging.getLogger(__name__)

class NetworkGraphManager:
    def __init__(self):
        self.graph = nx.DiGraph() 
        self.nodes_data = {} 
        # ניתן להוסיף כאן גם מילון ל-IP ל-MAC לצורך חיפוש מהיר
        self.ip_to_mac = {} 

    def update_graph(self, packet_data):
        src_mac = packet_data['src_mac']
        dst_mac = packet_data['dst_mac']
        src_ip = packet_data['src_ip']
        dst_ip = packet_data['dst_ip'] # Added for potential future use
        p_type = packet_data['type']

        # LOG THE PROCESSING START
        logger.info(f"Processing {p_type.upper()}: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")

        # Update IP-to-MAC mapping
        if src_ip and src_ip != "0.0.0.0":
            self.ip_to_mac[src_ip] = src_mac
        if dst_ip and dst_ip != "0.0.0.0" and dst_mac != "ff:ff:ff:ff:ff:ff":
            self.ip_to_mac[dst_ip] = dst_mac
            
        # 1. Handle Source Node
        if src_mac not in self.nodes_data:
            logger.info(f"New device discovered: {src_mac}")
            self.nodes_data[src_mac] = NetworkNode(mac=src_mac)
            self.graph.add_node(src_mac, obj=self.nodes_data[src_mac]) # Store node object
        
        self.nodes_data[src_mac].update_ip(src_ip)
        # Update node attributes in NetworkX if needed (e.g., for display)
        self.graph.nodes[src_mac]['label'] = f"{src_ip}\n({src_mac})" # For easier display
        
        # 2. Handle Destination Node (if not broadcast)
        if dst_mac != "ff:ff:ff:ff:ff:ff" and dst_mac != "00:00:00:00:00:00":
            if dst_mac not in self.nodes_data:
                self.nodes_data[dst_mac] = NetworkNode(mac=dst_mac)
                self.graph.add_node(dst_mac, obj=self.nodes_data[dst_mac])
            
            # 3. Create or Update Connection (Edge)
            if not self.graph.has_edge(src_mac, dst_mac):
                logger.info(f"New connection established: {src_mac} -> {dst_mac}")
                edge_data = NetworkEdge(source_mac=src_mac, target_mac=dst_mac)
                
                # ENRICHMENT: Confidence Score Logic
                # A 'reply' confirms a handshake (100%), a 'request' is an unverified attempt (50%)
                edge_data.confidence = 100 if p_type == "reply" else 50
                
                self.graph.add_edge(src_mac, dst_mac, data=edge_data)
            else:
                # If we previously saw a request but now see a reply, upgrade confidence
                if p_type == "reply":
                    self.graph[src_mac][dst_mac]['data'].confidence = 100
                    logger.debug(f"Confidence upgraded to 100% for connection {src_mac} -> {dst_mac}")
            
            self.graph[src_mac][dst_mac]['data'].increment(packet_data['type'])
            
            # For visualization later: make edge thickness reflect interaction count
            self.graph[src_mac][dst_mac]['weight'] = self.graph[src_mac][dst_mac]['data'].interaction_count

        # print(f"[Graph] Updated: {src_ip} ({src_mac}) -> {packet_data['dst_ip']} ({dst_mac})")


    def get_summary(self):
        return {
            "total_devices": self.graph.number_of_nodes(),
            "total_connections": self.graph.number_of_edges()
        }

    def visualize_graph(self):
        if not self.graph.nodes:
            print("[-] No nodes collected. Graph not saved.")
            return

        print("[*] Drawing and saving graph...")
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(self.graph, k=0.5)
        
        # Draw logic
        nx.draw(self.graph, pos, with_labels=True, 
                node_color='skyblue', node_size=2500, 
                arrowsize=20, font_size=8)
        
        filename = os.path.join(os.getcwd(), "network_report.png")
        plt.savefig(filename)
        plt.close()
        print(f"[+] SUCCESS: Graph saved to: {filename}")  

    def visualize_graph(self):
        if not self.graph.nodes:
            print("[-] No nodes collected. Graph not saved.")
            return

        # Ensure the directory exists
        output_dir = os.path.join(os.getcwd(), "outputs")
        os.makedirs(output_dir, exist_ok=True)

        print("[*] Drawing and saving graph...")
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(self.graph, k=0.5)
        
        nx.draw(self.graph, pos, with_labels=True, 
                node_color='skyblue', node_size=2500, 
                arrowsize=20, font_size=8)
        
        filename = os.path.join(output_dir, "network_report.png")
        plt.savefig(filename)
        plt.close()
        print(f"[+] SUCCESS: Graph saved to: {filename}")  

    def export_to_json(self, filename="network_topology.json"):
        """
        Serializes the graph into a JSON format inside the outputs folder.
        """
        # Ensure the directory exists
        output_dir = os.path.join(os.getcwd(), "outputs")
        os.makedirs(output_dir, exist_ok=True)
        
        full_path = os.path.join(output_dir, filename)

        formatted_data = {
            "summary": self.get_summary(),
            "nodes": [],
            "edges": []
        }

        for node_id, attrs in self.graph.nodes(data=True):
            node_obj = attrs.get('obj')
            formatted_data["nodes"].append({
                "mac": node_id,
                "ips": list(node_obj.ips) if node_obj else [],
                "label": attrs.get('label', "")
            })

        for u, v, attrs in self.graph.edges(data=True):
            edge_obj = attrs.get('data')
            formatted_data["edges"].append({
                "source": u,
                "target": v,
                "interaction_count": edge_obj.interaction_count if edge_obj else 0,
                "confidence_score": edge_obj.confidence if hasattr(edge_obj, 'confidence') else 0,
                "requests": edge_obj.requests if edge_obj else 0,
                "replies": edge_obj.replies if edge_obj else 0
            })

        with open(full_path, 'w') as f:
            json.dump(formatted_data, f, indent=4)
        print(f"[+] SUCCESS: JSON data exported to: {full_path}")      
    
        
    def print_insights(self):
        print("\n--- Network Insights ---")
        for mac, node in self.nodes_data.items():
            # Insight 1: Identify the Gateway (usually the most connected)
            connections = list(self.graph.neighbors(mac))
            if len(connections) > 3:
                logger.info(f"[Core Device] {node.ips} ({mac}) acts as a hub with {len(connections)} connections.")
            
            # Insight 2: Detect potential scanners (sending many requests with no replies)
            # This is where you show "Systems Thinking"
            if len(node.ips) > 1:
                 logger.info(f"[Alert] Device {mac} is seen with multiple IPs: {node.ips}")
    

    def prune_old_nodes(self, max_age_seconds=MAX_AGE_SECONDS):
        """
        Hook for Memory Management: Removes nodes that haven't been seen 
        within the TTL (Time-to-Live) period.
        """
        current_time = time.time()
        nodes_to_remove = [
            mac for mac, node in self.nodes_data.items() 
            if current_time - node.last_seen > max_age_seconds
        ]

        for mac in nodes_to_remove:
            logger.info(f"TTL Expired: Evicting inactive node {mac} from memory.")
            if self.graph.has_node(mac):
                self.graph.remove_node(mac)
            del self.nodes_data[mac]