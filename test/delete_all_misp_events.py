from pymisp import PyMISP
from dotenv import load_dotenv
import os
import requests
import threading
from queue import Queue

requests.packages.urllib3.disable_warnings()

# Load environment variables
load_dotenv()
MISP_URL = os.getenv("MISP_BASE_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")

# Initialize PyMISP
misp = PyMISP(MISP_URL, MISP_API_KEY, ssl=False)

# Thread-safe queue for storing event IDs
event_queue = Queue()

def worker():
    """Thread worker function to delete events from the queue."""
    while not event_queue.empty():
        event_id = event_queue.get()
        try:
            misp.delete_event(event_id)
            print(f"Deleted event ID: {event_id}")
        except Exception as e:
            print(f"Error deleting event ID {event_id}: {e}")
        finally:
            event_queue.task_done()

def delete_all_events_in_threads(thread_count=10):
    try:
        # Fetch all events
        events = misp.search_index()
        if not events:
            print("No events found.")
            return

        # Add event IDs to the queue
        for event in events:
            event_queue.put(event['id'])

        # Create and start threads
        threads = []
        for _ in range(thread_count):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish
        event_queue.join()
        for thread in threads:
            thread.join()

        print("All events have been deleted successfully.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    confirmation = input("Are you sure you want to delete all events? This action cannot be undone! (yes/no): ")
    if confirmation.lower() == "yes":
        # Adjust the thread count as needed
        delete_all_events_in_threads(thread_count=10)
    else:
        print("Operation cancelled.")