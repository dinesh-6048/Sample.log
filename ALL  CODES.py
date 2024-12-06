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

        # Write Requests per IP
        csv_writer.writerow(["Requests per IP"])
        csv_writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            csv_writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        csv_writer.writerow([])
        csv_writer.writerow(["Most Accessed Endpoint"])
        csv_writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_counts.items():
            csv_writer.writerow([endpoint, count])

        # Write Suspicious Activity
        csv_writer.writerow([])
        csv_writer.writerow(["Suspicious Activity"])
        csv_writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            csv_writer.writerow([ip, count])

if __name__ == "__main__":

    # Create a sample log file
    log_file_path = 'sample_log_file.log'


    # Parse logs and analyze data
    logs = parse_log_file(log_file_path)
    ip_counts = count_requests_per_ip(logs)
    endpoint_counts = most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Save results to CSV
    output_file = 'log_analysis_results.csv'
    save_results_to_csv(ip_counts, endpoint_counts, suspicious_activity, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":

    # Parse logs and analyze data
    log_file_path = 'sample_log_file.log'
    logs = parse_log_file(log_file_path)

    while True:  # This loop keeps running until the user chooses option 4 to exit
        # Prompt the user for an option
        print("\nChoose an option to display the results:")
        print("1. Count")
        print("2. Endpoint")
        print("3. Failed login")
        print("4. Exit")
        choice = input("Enter the number corresponding to your choice (1, 2, 3, or 4): ")

        # Condition to handle the user's choice
        if choice == '1':
            ip_counts = count_requests_per_ip(logs)
            if ip_counts:
                print("Requests per IP:")
                for count, ip in enumerate(ip_counts.items(), start=1):  # Using 'for' loop with count starting from 1
                    print(f"{count}. IP Address: {ip[0]}, Request Count: {ip[1]}")
            else:
                print("No requests found.")

        elif choice == '2':
            endpoint_counts = most_accessed_endpoint(logs)
            if endpoint_counts:
                print("\nMost Accessed Endpoint:")
                for count, endpoint in enumerate(endpoint_counts.items(), start=1):  # Using 'for' loop with count starting from 1
                    print(f"{count}. Endpoint: {endpoint[0]}, Access Count: {endpoint[1]}")
            else:
                print("No endpoints found.")

        elif choice == '3':
            suspicious_activity = detect_suspicious_activity(logs)
            if suspicious_activity:
                print("\nSuspicious Activity:")
                suspicious_items = list(suspicious_activity.items())
                i = 0
                while i < len(suspicious_items):  # Using 'while' loop to iterate through suspicious activity
                    ip, count = suspicious_items[i]
                    print(f"{i + 1}. IP Address: {ip}, Failed Login Count: {count}")
                    i += 1
            else:
                print("No suspicious activity detected.")

        elif choice == '4':  # Exit condition
            print("Exiting the program.")
            break  # Exit the while loop and stop the program

        else:
            print("Invalid option! Please enter 1, 2, 3, or 4.")


    # Optionally, save results to CSV after displaying the selected data
    output_file = 'log_analysis_results.csv'
    save_results_to_csv(ip_counts, endpoint_counts, suspicious_activity, output_file)
    print(f"\nResults saved to {output_file}")


