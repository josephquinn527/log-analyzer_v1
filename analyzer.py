import re
import argparse
from collections import Counter

def extract_ips(log_file):
    ip_pattern = re.compile(r'Failed password.*from (\d{1,3}(?:\.\d{1,3}){3})')
    with open(log_file, 'r') as f:
        lines = f.readlines()

    ips = [ip_pattern.search(line).group(1) for line in lines if ip_pattern.search(line)]
    return Counter(ips)

def main():
    parser = argparse.ArgumentParser(description='Analyze auth.log for failed SSH login IPs')
    parser.add_argument('logfile', help='Path to auth.log file')
    args = parser.parse_args()

    ip_counts = extract_ips(args.logfile)
    print("\nSuspicious IPs (Failed SSH Attempts):")
    for ip, count in ip_counts.most_common():
        print(f"{ip}: {count} attempts")

if __name__ == '__main__':
    main()