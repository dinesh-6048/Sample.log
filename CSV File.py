import re
from collections import Counter, defaultdict
import csv

def parse_log_file(log_file_path):

    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        return []

    return logs

def count_requests_per_ip(logs):

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_addresses = [re.search(ip_pattern, log).group() for log in logs if re.search(ip_pattern, log)]
    return Counter(ip_addresses)

def most_accessed_endpoint(logs):

    endpoint_pattern = r'"\w+ (/.+?) HTTP/\d\.\d"'
    endpoints = [re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log)]
    return Counter(endpoints)

def detect_suspicious_activity(logs):

    failed_login_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b.*POST /login HTTP/\d\.\d" 401'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    failed_ips = [re.search(ip_pattern, log).group() for log in logs if re.search(failed_login_pattern, log)]
    return Counter(failed_ips)

def save_results_to_csv(ip_counts, endpoint_counts, suspicious_activity, output_file):

    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        csv_writer.writerow(["Requests per IP"])
        csv_writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            csv_writer.writerow([ip, count])

        csv_writer.writerow([])
        csv_writer.writerow(["Most Accessed Endpoint"])
        csv_writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_counts.items():
            csv_writer.writerow([endpoint, count])

        csv_writer.writerow([])
        csv_writer.writerow(["Suspicious Activity"])
        csv_writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            csv_writer.writerow([ip, count])

if __name__ == "__main__":

    log_file_path = 'sample_log_file.log'

    logs = parse_log_file(log_file_path)
    ip_counts = count_requests_per_ip(logs)
    endpoint_counts = most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    output_file = 'log_analysis_results.csv'
    save_results_to_csv(ip_counts, endpoint_counts, suspicious_activity, output_file)
    print(f"Results saved to {output_file}")
