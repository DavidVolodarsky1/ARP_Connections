import unittest
import time
from graph_engine import NetworkGraphManager
from models import NetworkNode

class TestNetworkSecurity(unittest.TestCase):
    def setUp(self):
        self.manager = NetworkGraphManager()

    def test_ip_spoofing_detection(self):
        """Verify that a single MAC claiming multiple IPs is tracked."""
        mac = "aa:bb:cc:dd:ee:ff"
        
        # Scenario: MAC starts with one IP
        self.manager.update_graph({'src_mac': mac, 'dst_mac': '00:11', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.5', 'type': 'request'})
        
        # Scenario: Same MAC suddenly claims a different IP (Potential Spoofing/MITM)
        self.manager.update_graph({'src_mac': mac, 'dst_mac': '00:11', 'src_ip': '10.0.0.99', 'dst_ip': '10.0.0.5', 'type': 'request'})
        
        node_obj = self.manager.nodes_data[mac]
        self.assertIn('10.0.0.1', node_obj.ips)
        self.assertIn('10.0.0.99', node_obj.ips)
        self.assertEqual(len(node_obj.ips), 2)

    def test_ttl_pruning(self):
        """Verify that old nodes are removed from the graph after aging out."""
        mac = "de:ad:be:ef:00:01"
        self.manager.update_graph({'src_mac': mac, 'dst_mac': '00:11', 'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'type': 'reply'})
        
        # Manually backdate the node's last seen time to 2 minutes ago
        self.manager.nodes_data[mac].last_seen = time.time() - 120
        
        # Run pruning with a 60-second limit
        self.manager.prune_old_nodes(max_age_seconds=60)
        
        self.assertNotIn(mac, self.manager.nodes_data)
        self.assertNotIn(mac, self.manager.graph.nodes)

    def test_interaction_weight_scaling(self):
        """Verify that multiple packets increase the 'weight' attribute for visualization."""
        src, dst = "aa:11", "bb:22"
        packet = {'src_mac': src, 'dst_mac': dst, 'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'type': 'request'}
        
        # Send 3 packets
        for _ in range(3):
            self.manager.update_graph(packet)
            
        weight = self.manager.graph[src][dst]['weight']
        self.assertEqual(weight, 3)

if __name__ == '__main__':
    unittest.main()