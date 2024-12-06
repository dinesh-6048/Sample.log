import re
from collections import Counter


def parse_log_file_for_failed_logins(log_file_path):

    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        return []


    failed_login_pattern = r'(\d+\.\d+\.\d+\.\d+) .*\"(?:POST|GET|PUT|DELETE|PATCH|OPTIONS) .+ 401'  # Example for HTTP 401

    failed_logins = []

    for log in logs:
        failed_login_match = re.search(failed_login_pattern, log)
        if failed_login_match:
            failed_logins.append(failed_login_match.group(1))

    return failed_logins

def detect_suspicious_activity(log_file_path, threshold=10):
    failed_logins = parse_log_file_for_failed_logins(log_file_path)

    if not failed_logins:
        print("No failed login attempts found in the log file.")
        return


    failed_login_counts = Counter(failed_logins)

    suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count >= threshold}


    if suspicious_ips:
        print("\nSuspicious Activity (Brute Force Login Attempts):")
        print(f"{'IP Address':<20}{'Failed Login Count':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<20}")
    else:
        print(f"No IP addresses exceeded the {threshold} failed login attempts threshold.")


if __name__ == "__main__":
    log_file_path = 'sample_log_file.log'
    detect_suspicious_activity(log_file_path, threshold=5)
