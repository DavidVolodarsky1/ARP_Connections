from dataclasses import dataclass, field
from typing import Set, Dict
import time

@dataclass
class NetworkNode:
    mac: str
    ips: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    vendor: str = "Unknown"
    confidence_score: float = 0.0
    
    def update_ip(self, ip: str):
        if ip and ip != "0.0.0.0":
            self.ips.add(ip)
        self.last_seen = time.time()

@dataclass
class NetworkEdge:
    def __init__(self, source_mac, target_mac):
        self.source_mac = source_mac
        self.target_mac = target_mac
        self.interaction_count = 0
        self.requests = 0  # <--- New counter
        self.replies = 0   # <--- New counter
        self.confidence = 50 
        self.last_seen = None

    def increment(self, p_type):
        """Updates counters based on the packet type observed."""
        self.interaction_count += 1
        if p_type == "request":
            self.requests += 1
        elif p_type == "reply":
            self.replies += 1