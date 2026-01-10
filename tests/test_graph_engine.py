import unittest
from graph_engine import NetworkGraphManager

class TestGraphEngine(unittest.TestCase):
    def setUp(self):
        """Initialize a fresh manager before each test."""
        self.manager = NetworkGraphManager()

    def test_node_creation(self):
        """Verify that a new MAC address creates a node."""
        packet = {
            'src_mac': 'aa:bb:cc:dd:ee:ff', 'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'type': 'request'
        }
        self.manager.update_graph(packet)
        self.assertIn('aa:bb:cc:dd:ee:ff', self.manager.nodes_data)
        self.assertEqual(len(self.manager.nodes_data), 1)

    def test_confidence_scoring(self):
        """Verify that a Request gives 50% confidence and a Reply gives 100%."""
        src, dst = 'aa:11', 'bb:22'
        
        # 1. Send Request
        req = {'src_mac': src, 'dst_mac': dst, 'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'type': 'request'}
        self.manager.update_graph(req)
        self.assertEqual(self.manager.graph[src][dst]['data'].confidence, 50)
        
        # 2. Send Reply
        res = {'src_mac': dst, 'dst_mac': src, 'src_ip': '2.2.2.2', 'dst_ip': '1.1.1.1', 'type': 'reply'}
        self.manager.update_graph(res)
        # Note: The edge is directed, so we check the edge created by the reply (dst -> src)
        self.assertEqual(self.manager.graph[dst][src]['data'].confidence, 100)

    def test_broadcast_filtering(self):
        """Ensure broadcast MACs do not create edges."""
        packet = {
            'src_mac': 'aa:11', 'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'type': 'request'
        }
        self.manager.update_graph(packet)
        self.assertEqual(self.manager.graph.number_of_edges(), 0)

if __name__ == '__main__':
    unittest.main()