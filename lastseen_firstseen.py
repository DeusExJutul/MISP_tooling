'''When deployed and executed on your MISP instance, this script will plow through all of your attributes and add first seen/last seen timestamps to them retroperspectively.'''


import os
import time
import logging
from logging.handlers import MemoryHandler
from pymisp import PyMISP
from datetime import datetime
from requests.exceptions import ConnectionError, HTTPError
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event, Lock
from requests.adapters import HTTPAdapter
from requests.sessions import Session
import random

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
misp_url = "https://your-misp-instance-url.com"  # Replace with your MISP instance URL
misp_key = "your-misp-api-key"  # Replace with your MISP API key
verify_cert = False
progress_file = "misp_attribute_progress.txt"
batch_size = 10000
log_batch_size = 10  # Number of logs before flushing
error_log_file = "error_log.txt"  # Log file for errors
pause_duration = 5  # Duration to pause threads in seconds

# Determine optimal max_workers for ThreadPoolExecutor
io_multiplier = 2  # Use 2x cores for I/O-bound tasks
cpu_count = os.cpu_count()
max_workers = min(100, io_multiplier * cpu_count)  # Cap max_workers at 100

# Increase the connection pool size
def create_custom_session(pool_connections=500, pool_maxsize=1000):
    """Create a custom session with an increased connection pool size."""
    session = Session()
    adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# Attribute types to process
attribute_types = [
    'md5', 'domain', 'hostname', 'url', 'ip-dst', 'ip-src',
    'ip-dst|port', 'ip-src|port', 'email', 'email-src', 'email-dst'
    # Add or remove attribute types as per your needs.
]

# Initialize MISP instance
misp = PyMISP(misp_url, misp_key, ssl=verify_cert)
misp.session = create_custom_session()

# Logging setup with memory buffering
log_handler = logging.StreamHandler()
buffer_handler = MemoryHandler(log_batch_size, flushLevel=logging.INFO, target=log_handler)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[buffer_handler])

logger = logging.getLogger(__name__)

# Error logger setup
error_logger = logging.getLogger("error_logger")
error_logger.setLevel(logging.ERROR)
error_file_handler = logging.FileHandler(error_log_file)
error_logger.addHandler(error_file_handler)

# Event to signal threads to pause/resume
pause_event = Event()
pause_event.set()  # Allow threads to proceed initially
pause_lock = Lock()

def load_progress():
    """Load the last processed attribute ID from the progress file."""
    if os.path.exists(progress_file):
        with open(progress_file, "r") as file:
            try:
                return int(file.read().strip())
            except ValueError:
                logger.error("Progress file is corrupted. Starting from the beginning.")
                return 0
    return 0

def save_progress(last_id):
    """Save the last processed attribute ID to the progress file."""
    try:
        with open(progress_file, "w") as file:
            file.write(str(last_id))
    except Exception as e:
        logger.error(f"Failed to save progress: {e}")

def get_earliest_and_latest(attribute):
    """Find earliest and latest timestamps for an attribute."""
    attribute_value = attribute['value']
    attribute_timestamp = int(attribute['timestamp'])

    try:
        search_result = misp.search(controller="attributes", value=attribute_value)['Attribute']
        timestamps = [int(attr['timestamp']) for attr in search_result]

        if timestamps:
            first_seen = datetime.utcfromtimestamp(min(timestamps)).isoformat() + "Z"
            last_seen_from_occurrences = datetime.utcfromtimestamp(max(timestamps)).isoformat() + "Z"
            last_seen = max(
                datetime.utcfromtimestamp(attribute_timestamp).isoformat() + "Z",
                last_seen_from_occurrences
            )
            return first_seen, last_seen
    except Exception as e:
        logger.error(f"Error fetching earliest/latest for value {attribute_value}: {e}")

    return None, None

def process_single_attribute(attribute):
    """Process a single attribute."""
    attribute_id = int(attribute['id'])
    try:
        while not pause_event.is_set():
            time.sleep(0.1)  # Wait until pause event is cleared

        first_seen, last_seen = get_earliest_and_latest(attribute)
        if not first_seen or not last_seen:
            logger.warning(f"No occurrence data for attribute ID {attribute_id}, skipping.")
            return attribute_id, False

        # Update the attribute
        misp.update_attribute({
            "id": attribute_id,
            "first_seen": first_seen,
            "last_seen": last_seen
        })
        logger.info(f"Updated attribute ID {attribute_id} with first_seen: {first_seen}, last_seen: {last_seen}")
        return attribute_id, True
    except Exception as e:
        if "Connection pool full" in str(e):
            with pause_lock:
                if random.random() < 0.5:  # Randomly pause ~50% of threads
                    pause_event.clear()
                    logger.warning("Pausing some threads due to connection pool full...")
                    time.sleep(pause_duration)
                    pause_event.set()
        error_logger.error(f"Attribute ID {attribute_id}, Error: {e}, Attribute: {attribute}")
        logger.error(f"Error processing attribute ID {attribute_id}: {e}")
        return attribute_id, False

def process_batch_concurrently(attributes):
    """Process a batch of attributes concurrently."""
    results = []
    failed_attributes = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_attribute = {executor.submit(process_single_attribute, attr): attr for attr in attributes}

        for future in as_completed(future_to_attribute):
            attribute_id, success = future.result()
            if success:
                results.append(attribute_id)
            else:
                failed_attributes.append(attribute_id)

    return results, failed_attributes

def process_attributes():
    """Process all attributes in MISP, starting from the last processed ID."""
    last_processed_id = load_progress()
    processed_count = 0

    while True:
        try:
            attributes = misp.search(
                controller='attributes',
                limit=batch_size,
                offset=processed_count,
                sort="timestamp DESC",
                type_attribute=attribute_types,
                id=f">{last_processed_id}"  # Fetch only unprocessed attributes
            )['Attribute']

            if not attributes:
                logger.info("No more attributes to process.")
                break

            results, failed_attributes = process_batch_concurrently(attributes)

            if results:
                last_processed_id = max(last_processed_id, max(results))
                save_progress(last_processed_id)

            if failed_attributes:
                logger.warning(f"Failed to process {len(failed_attributes)} attributes. IDs: {failed_attributes}")

            processed_count += len(attributes)

        except (ConnectionError, HTTPError) as e:
            logger.error(f"Connection error encountered: {e}. Retrying in 10 seconds...")
            time.sleep(10)
            continue
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            break

if __name__ == "__main__":
    logger.info(f"Starting attribute processing with {max_workers} worker threads...")
    try:
        process_attributes()
    except Exception as fatal_error:
        logger.error(f"Fatal error: {fatal_error}. Progress saved. Exiting.")
    logger.info("Processing complete.")

