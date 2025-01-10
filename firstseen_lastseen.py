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
pause_duration = 10  # Duration to stop thread creation in seconds

# Determine optimal max_workers for ThreadPoolExecutor
io_multiplier = 2  # Use 2x cores for I/O-bound tasks
cpu_count = os.cpu_count()
max_workers = min(100, io_multiplier * cpu_count)  # Cap max_workers at 100

# Increase the connection pool size
def create_custom_session(pool_connections=500, pool_maxsize=1000):
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

# Event to control thread creation
creation_allowed_event = Event()
creation_allowed_event.set()  # Allow thread creation initially

# Monitor urllib3 log for "Connection pool is full"
urllib3_logger = logging.getLogger("urllib3.connectionpool")
urllib3_logger.setLevel(logging.WARNING)

class ConnectionPoolHandler(logging.Handler):
    def emit(self, record):
        if "Connection pool is full" in record.getMessage():
            logger.warning("Stopping thread creation due to connection pool full...")
            creation_allowed_event.clear()  # Stop thread creation
            time.sleep(pause_duration)  # Pause for 10 seconds
            creation_allowed_event.set()  # Resume thread creation
            logger.info("Resuming thread creation after clearing the connection pool.")

urllib3_logger.addHandler(ConnectionPoolHandler())

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
        while not creation_allowed_event.is_set():
            time.sleep(0.1)  # Wait for thread creation to be allowed

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
        error_logger.error(f"Attribute ID {attribute_id}, Error: {e}, Attribute: {attribute}")
        logger.error(f"Error processing attribute ID {attribute_id}: {e}")
        return attribute_id, False

def process_batch_concurrently(attributes):
    """Process a batch of attributes concurrently."""
    results = []
    failed_attributes = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_attribute = {}

        for attr in attributes:
            while not creation_allowed_event.is_set():
                time.sleep(0.1)  # Wait for thread creation to be allowed

            future = executor.submit(process_single_attribute, attr)
            future_to_attribute[future] = attr

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
