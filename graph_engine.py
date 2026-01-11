import networkx as nx
import matplotlib.pyplot as plt
from models import NetworkNode, NetworkEdge 
import time 
import matplotlib
matplotlib.use('Agg') 
import time
import os
import logging
import json
from definitions import MAX_AGE_SECONDS

# Get the logger defined in main
logger = logging.getLogger(__name__)

class NetworkGraphManager:
    def __init__(self):
        self.graph = nx.DiGraph() 
        self.nodes_data = {} 
        self.ip_to_mac = {} 

    def update_graph(self, packet_data):
        """
        Main entry point for graph updates. Orchestrates node and edge management.
        """
        src_mac = packet_data['src_mac']
        dst_mac = packet_data['dst_mac']
        src_ip = packet_data['src_ip']
        dst_ip = packet_data['dst_ip'] 
        p_type = packet_data['type']

        logger.info(f"Processing {p_type.upper()}: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")

        # 1. Update/Create Source Node
        self._ensure_node_exists(src_mac, src_ip)

        # 2. Handle Destination and Edge Logic (skip broadcast)
        if dst_mac not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
            self._ensure_node_exists(dst_mac, dst_ip)
            self._update_edge(src_mac, dst_mac, p_type)

    def _ensure_node_exists(self, mac, ip):
        """
        Handles node discovery, IP-to-MAC mapping, and NetworkX node enrichment.
        """
        # Update mapping
        if ip and ip != "0.0.0.0":
            self.ip_to_mac[ip] = mac

        # Create if new
        if mac not in self.nodes_data:
            logger.info(f"New device discovered: {mac}")
            self.nodes_data[mac] = NetworkNode(mac=mac)
            self.graph.add_node(mac, obj=self.nodes_data[mac])
        
        # Update node data
        self.nodes_data[mac].update_ip(ip)
        self.graph.nodes[mac]['label'] = f"{ip}\n({mac})"

    def _update_edge(self, src_mac, dst_mac, p_type):
        """
        Handles the connection between nodes, including interaction counts and confidence.
        """
        if not self.graph.has_edge(src_mac, dst_mac):
            logger.info(f"New connection established: {src_mac} -> {dst_mac}")
            edge_data = NetworkEdge(source_mac=src_mac, target_mac=dst_mac)
            
            # Confidence logic: Reply is stronger evidence than a request
            edge_data.confidence = 100 if p_type == "reply" else 50
            self.graph.add_edge(src_mac, dst_mac, data=edge_data)
        else:
            # Upgrade existing edge if we now see a verified reply
            if p_type == "reply":
                self.graph[src_mac][dst_mac]['data'].confidence = 100
        
        # Increment counts and update visual weight
        edge = self.graph[src_mac][dst_mac]['data']
        edge.increment(p_type)
        self.graph[src_mac][dst_mac]['weight'] = edge.interaction_count


    def get_summary(self):
        return {
            "total_devices": self.graph.number_of_nodes(),
            "total_connections": self.graph.number_of_edges()
        }

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
        Orchestrates the export process: directory management and serialization.
        """
        # 1. Directory Setup
        output_dir = os.path.join(os.getcwd(), "outputs")
        os.makedirs(output_dir, exist_ok=True)
        full_path = os.path.join(output_dir, filename)

        # 2. Data Preparation
        export_payload = {
            "summary": self.get_summary(),
            "nodes": self._format_nodes_for_export(),
            "edges": self._format_edges_for_export()
        }

        # 3. File IO
        try:
            with open(full_path, 'w') as f:
                json.dump(export_payload, f, indent=4)
            logger.info(f"[+] SUCCESS: JSON data exported to: {full_path}")
        except Exception as e:
            logger.error(f"[-] Failed to export JSON: {e}")

    def _format_nodes_for_export(self):
        """Helper to map NetworkX nodes to JSON-friendly dictionaries."""
        nodes = []
        for node_id, attrs in self.graph.nodes(data=True):
            node_obj = attrs.get('obj')
            nodes.append({
                "mac": node_id,
                "ips": list(node_obj.ips) if node_obj else [],
                "label": attrs.get('label', "")
            })
        return nodes

    def _format_edges_for_export(self):
        """Helper to map NetworkX edges to JSON-friendly dictionaries."""
        edges = []
        for u, v, attrs in self.graph.edges(data=True):
            edge_obj = attrs.get('data')
            edges.append({
                "source": u,
                "target": v,
                "interaction_count": edge_obj.interaction_count if edge_obj else 0,
                "confidence_score": getattr(edge_obj, 'confidence', 0),
                "requests": getattr(edge_obj, 'requests', 0),
                "replies": getattr(edge_obj, 'replies', 0)
            })
        return edges
    
    def print_insights(self):
        logger.info("\n--- Network Insights ---")
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