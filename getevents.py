import os
import json
from pymisp import ExpandedPyMISP

def connect_to_misp(misp_url, misp_key, misp_verifycert=True):
    """Establish connection to MISP server"""
    try:
        return ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    except Exception as e:
        print(f"Error connecting to MISP: {e}")
        return None

def fetch_events_in_range(misp_instance, start_event, end_event):
    """Fetch events within specified range"""
    try:
        events = []
        current_page = 1
        while True:
            batch = misp_instance.search(page=current_page, limit=100)
            batch_events = [event for event in batch if start_event <= int(event['Event']['id']) <= end_event]
            events.extend(batch_events)
            
            if len(batch) < 100 or len(events) >= (end_event - start_event + 1):
                break
            current_page += 1
        
        return events
    except Exception as e:
        print(f"Error fetching events: {e}")
        return []

def create_event_text_file(event, output_folder):
    """Create detailed text file for a single MISP event"""
    try:
        os.makedirs(output_folder, exist_ok=True)
        
        event_id = event.get('Event', {}).get('id', 'unknown')
        txt_filename = os.path.join(output_folder, f'event_{event_id}.txt')
        
        with open(txt_filename, 'w', encoding='utf-8') as f:
            # Event Header
            f.write("=" * 80 + "\n")
            f.write(f"MISP EVENT ID: {event_id}\n")
            f.write("=" * 80 + "\n\n")
            
            # Event Core Details
            event_info = event.get('Event', {})
            core_details = [
                'uuid', 'timestamp', 'published', 'org', 'orgc', 
                'distribution', 'threat_level_id', 'analysis', 'date'
            ]
            
            f.write("[ EVENT CORE DETAILS ]\n")
            f.write("-" * 40 + "\n")
            for detail in core_details:
                value = event_info.get(detail, 'N/A')
                f.write(f"{detail.upper()}: {value}\n")
            f.write("\n")
            
            # Event Info and Description
            f.write("[ EVENT DESCRIPTION ]\n")
            f.write("-" * 40 + "\n")
            f.write(event_info.get('info', 'No description available') + "\n\n")
            
            # Attributes Section
            f.write("[ ATTRIBUTES ]\n")
            f.write("-" * 40 + "\n")
            for attribute in event_info.get('Attribute', []):
                f.write(f"Type: {attribute.get('type', 'N/A')}\n")
                f.write(f"Value: {attribute.get('value', 'N/A')}\n")
                f.write(f"Category: {attribute.get('category', 'N/A')}\n")
                f.write(f"Comment: {attribute.get('comment', 'No comment')}\n")
                f.write("-" * 20 + "\n")
            
            # Raw Event JSON for complete reference
            f.write("[ RAW EVENT JSON ]\n")
            f.write("-" * 40 + "\n")
            json.dump(event, f, indent=2)
        
        print(f"Text file created: {txt_filename}")
    except Exception as e:
        print(f"Error creating text file for event {event_id}: {e}")

def main():
    """Main function to export MISP events to text files"""
    misp_url = input("Enter MISP server URL: ")
    misp_key = input("Enter MISP API key: ")
    
    misp = connect_to_misp(misp_url, misp_key)
    if not misp:
        return
    
    start_event = int(input("Enter first event ID: "))
    end_event = int(input("Enter last event ID: "))
    
    output_folder = input("Enter output folder path (default: misp_event_texts): ") or 'misp_event_texts'
    
    events = fetch_events_in_range(misp, start_event, end_event)
    
    for event in events:
        create_event_text_file(event, output_folder)
    
    print(f"Exported {len(events)} events to {output_folder}")

if __name__ == "__main__":
    main()
