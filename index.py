from pymisp import PyMISP
import csv
import datetime
import json
import logging
import os
from dotenv import load_dotenv
from colorama import init, Fore, Style

# Load environment variables
load_dotenv()

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# === CONFIG ===
MISP_URL = os.getenv('MISP_URL', 'https://your-misp-instance.com')
API_KEY = os.getenv('MISP_API_KEY', 'your-api-key-here')
VERIFY_CERT = os.getenv('MISP_VERIFY_CERT', 'False').lower() == 'true'
DAYS_BACK = int(os.getenv('MISP_DAYS_BACK', '7'))
EVENT_SEARCH = os.getenv('MISP_EVENT_SEARCH', 'False').lower() == 'true'
IOC_TYPES = ['ip-src', 'ip-dst', 'domain', 'url', 'md5', 'sha1', 'sha256', 'filename', 'hostname']

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and icons."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT
    }
    
    ICONS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '💥'
    }
    
    def format(self, record):
        # Get color and icon for log level
        color = self.COLORS.get(record.levelname, Fore.WHITE)
        icon = self.ICONS.get(record.levelname, '📝')
        
        # Format timestamp
        timestamp = datetime.datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Create colored log message
        log_msg = f"{color}{icon} {Style.BRIGHT}{record.levelname:<8}{Style.RESET_ALL}"
        log_msg += f" {Fore.BLUE}[{timestamp}]{Style.RESET_ALL} "
        log_msg += f"{color}{record.getMessage()}{Style.RESET_ALL}"
        
        return log_msg

# === LOGGING ===
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler with custom formatter
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter())
logger.addHandler(console_handler)

# Clear any existing handlers to avoid duplicate logs
logger.propagate = False

def print_banner():
    """Print a beautiful banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  MISP IOC EXTRACTOR  🛡️                   ║
║                                                              ║
║              Extract threat intelligence from MISP           ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)

def print_section(title):
    """Print a section header."""
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*60}")
    print(f"🚀 {title}")
    print(f"{'='*60}{Style.RESET_ALL}")

def print_progress(current, total, description):
    """Print progress indicator."""
    percentage = (current / total) * 100 if total > 0 else 0
    filled = int(percentage // 5)
    bar = '█' * filled + '░' * (20 - filled)
    print(f"\r{Fore.CYAN}📊 {description}: {bar} {percentage:.1f}% ({current}/{total}){Style.RESET_ALL}", end='', flush=True)

def init_misp_connection():
    """Initialize MISP connection and test it."""
    print_section("MISP CONNECTION")
    logger.info(f"🔗 Connecting to MISP at {Fore.YELLOW}{MISP_URL}{Style.RESET_ALL}")
    
    misp = PyMISP(MISP_URL, API_KEY, VERIFY_CERT)
    
    try:
        # Test connection
        user = misp.get_user('me')
        email = user.get('User', {}).get('email', 'Unknown')
        logger.info(f"👤 Connected as: {Fore.CYAN}{email}{Style.RESET_ALL}")
        logger.info(f"🎯 Target IOC types: {Fore.YELLOW}{', '.join(IOC_TYPES[:5])}...{Style.RESET_ALL}")
        return misp
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        raise

def extract_attributes_from_response(response, source_name):
    """Extract attributes from various MISP response formats."""
    if not response:
        return []
    
    attr_list = []
    
    if isinstance(response, dict):
        if 'Attribute' in response:
            attr_list = response['Attribute']
        elif 'response' in response:
            if isinstance(response['response'], list):
                attr_list = response['response']
            elif isinstance(response['response'], dict) and 'Attribute' in response['response']:
                attr_list = response['response']['Attribute']
    elif isinstance(response, list):
        attr_list = response
    
    logger.info(f"📦 Found {Fore.CYAN}{len(attr_list)}{Style.RESET_ALL} attributes from {Fore.YELLOW}{source_name}{Style.RESET_ALL}")
    return attr_list

def extract_events_from_response(response, source_name):
    """Extract events from various MISP response formats."""
    if not response:
        return []
    
    event_list = []
    
    if isinstance(response, list):
        event_list = response
    elif isinstance(response, dict):
        if 'response' in response:
            event_list = response['response']
        elif 'Event' in response:
            event_list = response['Event']
        else:
            # Try to find events in any list value
            for key, value in response.items():
                if isinstance(value, list) and len(value) > 0:
                    event_list = value
                    break
    
    logger.info(f"🎪 Found {Fore.CYAN}{len(event_list)}{Style.RESET_ALL} events from {Fore.YELLOW}{source_name}{Style.RESET_ALL}")
    return event_list

def search_attributes(misp, days_back=None):
    """Search for attributes, optionally filtered by time."""
    try:
        params = {'controller': 'attributes', 'limit': 1000}
        
        if days_back:
            since = (datetime.datetime.utcnow() - datetime.timedelta(days=days_back)).isoformat()
            params['timestamp'] = since
            logger.info(f"🔍 Searching attributes from last {Fore.CYAN}{days_back}{Style.RESET_ALL} days")
        else:
            logger.info("🔍 Searching all attributes")
        
        response = misp.search(**params)
        return extract_attributes_from_response(response, f"attributes {'(filtered)' if days_back else '(all)'}")
        
    except Exception as e:
        logger.error(f"Attribute search failed: {e}")
        return []

def search_events(misp, days_back=None):
    """Search for events, optionally filtered by time."""
    try:
        params = {'controller': 'events', 'limit': 50}
        
        if days_back:
            since = (datetime.datetime.utcnow() - datetime.timedelta(days=days_back)).isoformat()
            params['timestamp'] = since
            logger.info(f"🔍 Searching events from last {Fore.CYAN}{days_back}{Style.RESET_ALL} days")
        else:
            logger.info("🔍 Searching all events")
        
        response = misp.search(**params)
        return extract_events_from_response(response, f"events {'(filtered)' if days_back else '(all)'}")
        
    except Exception as e:
        logger.error(f"Event search failed: {e}")
        return []

def extract_iocs_from_attributes(attributes, source_name):
    """Extract IOCs from attribute list."""
    iocs = []
    
    for i, attr in enumerate(attributes):
        if i % 50 == 0:  # Update progress every 50 items
            print_progress(i + 1, len(attributes), f"Processing {source_name}")
        
        if attr.get('type') in IOC_TYPES:
            iocs.append({
                'value': attr.get('value'),
                'type': attr.get('type'),
                'category': attr.get('category'),
                'event_id': attr.get('event_id'),
                'timestamp': attr.get('timestamp'),
                'source': source_name
            })
    
    print()  # New line after progress bar
    logger.info(f"💎 Extracted {Fore.GREEN}{len(iocs)}{Style.RESET_ALL} IOCs from {Fore.YELLOW}{source_name}{Style.RESET_ALL}")
    return iocs

def extract_iocs_from_events(events, source_name):
    """Extract IOCs from event list."""
    iocs = []
    
    for i, event in enumerate(events):
        if i % 10 == 0:  # Update progress every 10 events
            print_progress(i + 1, len(events), f"Processing {source_name}")
        
        if not isinstance(event, dict):
            continue
            
        event_data = event.get('Event', event)
        event_id = event_data.get('id')
        
        for attr in event_data.get('Attribute', []):
            if attr.get('type') in IOC_TYPES:
                iocs.append({
                    'value': attr.get('value'),
                    'type': attr.get('type'),
                    'category': attr.get('category'),
                    'event_id': event_id,
                    'timestamp': attr.get('timestamp'),
                    'source': source_name
                })
    
    print()  # New line after progress bar
    logger.info(f"💎 Extracted {Fore.GREEN}{len(iocs)}{Style.RESET_ALL} IOCs from {Fore.YELLOW}{source_name}{Style.RESET_ALL}")
    return iocs

def deduplicate_iocs(iocs):
    """Remove duplicate IOCs based on value and type."""
    unique_iocs = []
    seen = set()
    
    logger.info(f"🔄 Deduplicating {Fore.CYAN}{len(iocs)}{Style.RESET_ALL} IOCs...")
    
    for ioc in iocs:
        key = (ioc['value'], ioc['type'])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
    
    removed = len(iocs) - len(unique_iocs)
    logger.info(f"✨ Deduplicated to {Fore.GREEN}{len(unique_iocs)}{Style.RESET_ALL} unique IOCs (removed {Fore.RED}{removed}{Style.RESET_ALL} duplicates)")
    return unique_iocs

def save_iocs_to_csv(iocs, filename='misp_iocs.csv'):
    """Save IOCs to CSV file."""
    if not iocs:
        logger.warning("No IOCs to save")
        return False
    
    try:
        logger.info(f"💾 Saving IOCs to {Fore.YELLOW}{filename}{Style.RESET_ALL}...")
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['value', 'type', 'category', 'event_id', 'timestamp', 'source'])
            
            for i, ioc in enumerate(iocs):
                if i % 100 == 0:  # Update progress every 100 items
                    print_progress(i + 1, len(iocs), "Saving to CSV")
                
                writer.writerow([
                    ioc['value'],
                    ioc['type'],
                    ioc['category'],
                    ioc['event_id'],
                    ioc['timestamp'],
                    ioc['source']
                ])
        
        print()  # New line after progress bar
        logger.info(f"💾 Saved {Fore.GREEN}{len(iocs)}{Style.RESET_ALL} IOCs to {Fore.YELLOW}{filename}{Style.RESET_ALL}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save IOCs to CSV: {e}")
        return False

def print_ioc_summary(iocs):
    """Print summary of IOCs found."""
    if not iocs:
        logger.warning("No IOCs found")
        return
    
    print_section("IOC SUMMARY")
    
    # Type distribution
    type_counts = {}
    for ioc in iocs:
        ioc_type = ioc['type']
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
    
    logger.info(f"📊 IOC type distribution:")
    for ioc_type, count in sorted(type_counts.items()):
        percentage = (count / len(iocs)) * 100
        bar_length = int(percentage / 5)
        bar = '█' * bar_length + '░' * (20 - bar_length)
        print(f"   {Fore.CYAN}{ioc_type:<12}{Style.RESET_ALL} {bar} {Fore.YELLOW}{count:>4}{Style.RESET_ALL} ({percentage:5.1f}%)")
    
    # Show sample IOCs
    print(f"\n{Fore.MAGENTA}🔍 Sample IOCs:{Style.RESET_ALL}")
    for i, ioc in enumerate(iocs[:5]):
        icon = '🌐' if 'ip' in ioc['type'] or 'domain' in ioc['type'] else '🔒' if any(x in ioc['type'] for x in ['md5', 'sha']) else '📄'
        value_display = ioc['value'][:50] + '...' if len(ioc['value']) > 50 else ioc['value']
        print(f"   {icon} {Fore.CYAN}{ioc['type']:<12}{Style.RESET_ALL} {Fore.WHITE}{value_display}{Style.RESET_ALL} {Fore.BLUE}(Event: {ioc['event_id']}){Style.RESET_ALL}")

def _extract_event_list_from_response(events):
    """Extract event list from various MISP response formats."""
    if isinstance(events, list):
        logger.info(f"📊 Events response is a direct list with {len(events)} events")
        return events
    
    if isinstance(events, dict):
        logger.info(f"📊 Events keys: {list(events.keys())}")
        
        # Try known keys first
        if 'response' in events:
            return events['response']
        if 'Event' in events:
            return events['Event']
        
        # Fallback: find any list value
        logger.warning("⚠️ Unexpected dict structure, trying all values...")
        for key, value in events.items():
            if isinstance(value, list) and len(value) > 0:
                logger.info(f"📊 Found potential events in key '{key}': {len(value)} items")
                return value
    
    return []

def _analyze_event_structure(event, index):
    """Analyze and display information about a single event."""
    if not isinstance(event, dict):
        print(f"   {Fore.RED}Event {index+1}: Unexpected event structure: {type(event)}{Style.RESET_ALL}")
        return
    
    # Extract event data
    if 'Event' in event:
        event_data = event['Event']
    else:
        event_data = event
    
    event_id = event_data.get('id', 'unknown')
    event_info = event_data.get('info', 'No info')
    attr_count = len(event_data.get('Attribute', []))
    
    print(f"   {Fore.CYAN}Event {index+1}:{Style.RESET_ALL} ID={Fore.YELLOW}{event_id}{Style.RESET_ALL}, Attributes={Fore.GREEN}{attr_count}{Style.RESET_ALL}")
    print(f"   {Fore.WHITE}Info: {event_info[:50]}...{Style.RESET_ALL}")

def _save_debug_events(events, filename):
    """Save events to JSON file for debugging."""
    try:
        with open(filename, 'w') as f:
            json.dump(events, f, indent=2, default=str)
        logger.info(f"💾 Saved events to {filename}")
    except Exception as e:
        logger.error(f"Failed to save events to {filename}: {e}")

def _count_events_in_response(events_response):
    """Count events in response regardless of format."""
    if isinstance(events_response, list):
        return len(events_response)
    
    if isinstance(events_response, dict):
        if 'response' in events_response:
            return len(events_response.get('response', []))
        return len(events_response)
    
    return 0

def _search_events_with_timestamp(misp, since, days_back):
    """Search events with timestamp filter and handle the response."""
    logger.info(f"🔍 Debug: Searching events from last {days_back} days (since {since[:19]})")
    
    events = misp.search(controller='events', timestamp=since, limit=10)
    logger.info(f"📊 Events response type: {type(events)}")
    
    event_list = _extract_event_list_from_response(events)
    logger.info(f"📊 Found {len(event_list)} events")
    
    # Analyze first 3 events
    for i, event in enumerate(event_list[:3]):
        _analyze_event_structure(event, i)
    
    _save_debug_events(events, 'debug_events.json')
    return True

def _search_events_without_filter(misp):
    """Search events without timestamp filter as fallback."""
    logger.info("💡 Trying event search without timestamp filter...")
    
    events_no_filter = misp.search(controller='events', limit=10)
    logger.info(f"📊 Events without filter type: {type(events_no_filter)}")
    
    no_filter_count = _count_events_in_response(events_no_filter)
    logger.info(f"📊 Events without filter: {no_filter_count} events found")
    
    _save_debug_events(events_no_filter, 'debug_events_no_filter.json')

def debug_event_search(misp, days_back):
    """Debug event search with detailed analysis and file saving."""
    if not EVENT_SEARCH:
        return
    
    print_section("DEBUG EVENT SEARCH")
    
    since = (datetime.datetime.utcnow() - datetime.timedelta(days=days_back)).isoformat()
    
    try:
        _search_events_with_timestamp(misp, since, days_back)
    except Exception as e:
        logger.error(f"Event search failed: {e}")
        try:
            _search_events_without_filter(misp)
        except Exception as e2:
            logger.error(f"Event search without filter also failed: {e2}")

def main():
    """Main execution function."""
    try:
        print_banner()
        
        # Initialize MISP connection
        misp = init_misp_connection()
        
        # Debug event search if enabled
        if EVENT_SEARCH:
            debug_event_search(misp, DAYS_BACK)
        
        print_section("IOC EXTRACTION")
        
        # Collect all IOCs
        all_iocs = []
        
        # Search recent attributes
        logger.info("🎯 Starting recent attributes search...")
        recent_attrs = search_attributes(misp, DAYS_BACK)
        all_iocs.extend(extract_iocs_from_attributes(recent_attrs, 'recent_attributes'))
        
        # Search all attributes if recent search yielded few results
        if len(recent_attrs) < 10:
            logger.info("🔄 Few recent attributes found, searching all attributes...")
            all_attrs = search_attributes(misp)
            all_iocs.extend(extract_iocs_from_attributes(all_attrs, 'all_attributes'))
        
        # Search recent events
        logger.info("🎯 Starting recent events search...")
        recent_events = search_events(misp, DAYS_BACK)
        all_iocs.extend(extract_iocs_from_events(recent_events, 'recent_events'))
        
        # Search all events if recent search yielded few results
        if len(recent_events) < 5:
            logger.info("🔄 Few recent events found, searching all events...")
            all_events = search_events(misp)
            all_iocs.extend(extract_iocs_from_events(all_events, 'all_events'))
        
        # Deduplicate and save
        unique_iocs = deduplicate_iocs(all_iocs)
        print_ioc_summary(unique_iocs)
        save_iocs_to_csv(unique_iocs)
        
        # Final success message
        print(f"\n{Fore.GREEN}{Style.BRIGHT}🎉 EXTRACTION COMPLETE! 🎉{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ Found {Style.BRIGHT}{len(unique_iocs)}{Style.RESET_ALL}{Fore.GREEN} unique IOCs{Style.RESET_ALL}")
        print(f"{Fore.GREEN}💾 Saved to misp_iocs.csv{Style.RESET_ALL}")
        
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        raise

if __name__ == "__main__":
    main()
