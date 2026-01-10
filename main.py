import sys
import signal
import threading
import logging
from queue import Queue
from sniffer import ARPSniffer
from graph_engine import NetworkGraphManager
import time
from definitions import PRUNE_INTERVAL, MAX_AGE_SECONDS, MAX_QUEUE_SIZE

# --- Logging Configuration ---
# Configured to output to both a file and the console for real-time monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(threadName)s: %(message)s',
    handlers=[
        logging.FileHandler("network_analyzer.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def main():
    logger.info("System Startup: Initializing Async Network Analyzer")
    
    manager = NetworkGraphManager()
    packet_queue = Queue() # Thread-safe queue for Producer-Consumer pattern

    # --- Consumer Logic ---
    # This worker runs in a separate thread to process packets without blocking the sniffer
    def processing_worker():
        logger.info("Worker Thread started. Ready for processing.")
        
        # Track time for periodic maintenance tasks (TTL Pruning)
        last_prune_time = time.time()
        

        while True:
            packet_data = packet_queue.get()
            
            # Poison pill to gracefully shut down the worker
            if packet_data is None:
                logger.info("Worker Thread received shutdown signal. Running final insights...")
                manager.print_insights() # Print final security summary before thread dies
                packet_queue.task_done()
                break
            
            try:
                # 1. Update the topology with the new packet data
                manager.update_graph(packet_data)

                # 2. Periodic Maintenance Hook (Systems Thinking)
                # We don't prune on every packet (slow); we prune every PRUNE_INTERVAL
                current_time = time.time()
                if current_time - last_prune_time > PRUNE_INTERVAL:
                    manager.prune_old_nodes(MAX_AGE_SECONDS)
                    last_prune_time = current_time

            except Exception as e:
                logger.error(f"Failed to update graph with packet data: {e}")
            finally:
                packet_queue.task_done()

    # Start the background worker thread
    worker_thread = threading.Thread(target=processing_worker, name="GraphWorker", daemon=True)
    worker_thread.start()

    # --- Shutdown Handler ---
    def signal_handler(sig, frame):
            logger.warning("Shutdown triggered via SIGINT (Ctrl+C).")
            
            # 1. Signal the worker to stop after processing current queue
            packet_queue.put(None) 
            
            # 2. WAIT for the worker thread to finish processing everything in the queue
            # This ensures the graph is fully updated before we summarize or draw
            logger.info("Waiting for background worker to finish remaining tasks...")
            worker_thread.join(timeout=2.0) # Wait up to 2 seconds for the worker to exit
            
            # 3. Now get the summary - it will be 100% accurate
            summary = manager.get_summary()
            manager.print_insights() # This will print the gateway/scammer alerts to console
            logger.info(f"Final Session Summary: Found {summary['total_devices']} unique devices and {summary['total_connections']} connections.")
            
            try:
                logger.info("Generating final visual report...")
                manager.visualize_graph()
                logger.info("Report saved successfully as 'network_report.png'.")

                logger.info("Exporting graph data to JSON...")
                manager.export_to_json("network_topology.json")
                logger.info("Data exported successfully as 'network_topology.json'.")
            except Exception as e:
                logger.error(f"Visualization failed during shutdown: {e}")
                
            logger.info("Cleanup complete. Application exiting.")
            sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    # --- Producer Logic ---
    # The sniffer callback only places data in the queue - extremely low latency
    # --- Producer Logic ---
    def sniffer_callback(data):
        """
        Callback executed by the Sniffer thread.
        Implements Backpressure Handling to protect system stability.
        """
        # Threshold: If more than 1000 packets are waiting, we drop new ones.
        # This prevents the application from consuming infinite RAM if the 
        # CPU cannot keep up with the network traffic.
        current_queue_size = packet_queue.qsize()
        
        if current_queue_size > MAX_QUEUE_SIZE:
            # We use a warning level because data loss is occurring
            logger.warning(f"Backpressure Alert: Queue size at {current_queue_size}. Dropping incoming ARP packet to maintain stability.")
            return 
            
        packet_queue.put(data)

    sniffer = ARPSniffer(callback_function=sniffer_callback)
    
    logger.info("Sniffer engine starting. Listening for ARP traffic...")
    
    try:
        # This is a blocking call that keeps the main thread alive
        sniffer.start()
    except Exception as e:
        logger.critical(f"Critical error in Sniffer Engine: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()