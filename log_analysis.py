import csv
from collections import Counter, defaultdict

# File paths
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(file_path):
    """Parses the log file and extracts required information."""
    log_data = []
    with open(file_path, "r") as file:
        for line in file:
            # Splitting the log entry into parts
            parts = line.split()
            ip = parts[0]  # Extract IP Address
            endpoint = parts[6]  # Extract endpoint (URL or path)
            status_code = int(parts[8])  # Extract HTTP status code
            message = " ".join(parts[9:]) if len(parts) > 9 else ""  # Extract optional message

            log_data.append((ip, endpoint, status_code, message))
    return log_data


def count_requests_per_ip(log_data):
    """Counts the number of requests per IP address."""
    ip_counter = Counter(entry[0] for entry in log_data)
    return ip_counter.most_common()


def find_most_frequent_endpoint(log_data):
    """Finds the most frequently accessed endpoint."""
    endpoint_counter = Counter(entry[1] for entry in log_data)
    return endpoint_counter.most_common(1)[0]


def detect_suspicious_activity(log_data, threshold):
    """Detects IPs with suspicious activity based on failed login attempts."""
    failed_attempts = Counter(
        entry[0]
        for entry in log_data
        if entry[2] == 401 or "Invalid credentials" in entry[3].lower()  # Match case-insensitive
    )
    # Filter IPs exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips



def save_results_to_csv(requests_per_ip, most_frequent_endpoint, suspicious_ips, output_file):
    """Saves analysis results to a CSV file."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)

        # Write Requests Per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests_per_ip:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_frequent_endpoint[0], most_frequent_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def display_results(requests_per_ip, most_frequent_endpoint, suspicious_ips):
    """Displays results in a formatted output."""
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in requests_per_ip:
        print(f"{ip:<20}{count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<20}")
    else:
        print("No suspicious activity detected.")


def main():
    """Main function to execute the log analysis."""
    # Parse the log file
    log_data = parse_log_file(LOG_FILE)

    # Analyze the log data
    requests_per_ip = count_requests_per_ip(log_data)
    most_frequent_endpoint = find_most_frequent_endpoint(log_data)
    suspicious_ips = detect_suspicious_activity(log_data, FAILED_LOGIN_THRESHOLD)

    # Display results
    display_results(requests_per_ip, most_frequent_endpoint, suspicious_ips)

    # Save results to CSV
    save_results_to_csv(requests_per_ip, most_frequent_endpoint, suspicious_ips, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
