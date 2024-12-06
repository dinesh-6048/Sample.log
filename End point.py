import re
from collections import Counter

def parse_log_file_for_endpoints(log_file_path):

    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        return []
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (\/[^\s]*)'
    endpoints = []

    for log in logs:
        endpoint_match = re.search(endpoint_pattern, log)
        if endpoint_match:
            endpoints.append(endpoint_match.group(1))

    return endpoints

def find_most_frequent_endpoint(log_file_path):

    endpoints = parse_log_file_for_endpoints(log_file_path)

    if not endpoints:
        print("No endpoints found in the log file.")
        return
    endpoint_counts = Counter(endpoints)
    most_frequent_endpoint = endpoint_counts.most_common(1)

    if most_frequent_endpoint:
        endpoint, count = most_frequent_endpoint[0]
        print("\nMost Frequently Accessed Endpoint:")
        print(f"Endpoint: {endpoint}")
        print(f"Access Count: {count}")
    else:
        print("No endpoint data to analyze.")


if __name__ == "__main__":

    log_file_path = 'sample_log_file.log'
    find_most_frequent_endpoint(log_file_path)
