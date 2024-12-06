import re
from collections import Counter

def parse_log_file_for_ip(log_file_path):

    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        return []

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_addresses = []

    for log in logs:
        ip_match = re.search(ip_pattern, log)
        if ip_match:
            ip_addresses.append(ip_match.group())

    return ip_addresses

def count_and_display_ip_requests(log_file_path):

    ip_addresses = parse_log_file_for_ip(log_file_path)

    if not ip_addresses:
        print("No IP addresses found in the log file.")
        return


    ip_counts = Counter(ip_addresses)
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    print("\nCount Requests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in sorted_ip_counts:
        print(f"{ip:<20}{count:<15}")


if __name__ == "__main__":

    log_file_path = 'sample_log_file.log'
    count_and_display_ip_requests(log_file_path)
