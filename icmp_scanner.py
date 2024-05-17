#!/usr/bin/env python3
import argparse
import sys
import re
import signal
import subprocess
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

def sig_handler(sig, frame):
    print(colored(f"\n[!] Aborting...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner using ICMP protocl.")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Set the IP address or range (i.e. 192.168.1.1 or 192.168.1.1-100)")
    args = parser.parse_args()

    return args.target

def input_validation(target_str):
    single_target = re.match(r'^(\d{1,3}\.){3}\d{1,3}$',target_str)
    range_target = re.match(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$', target_str)

    return single_target or range_target

def parse_target(target_str):
    if input_validation(target_str):
        target_str_splitted = target_str.split('.')
        first_three_octets = '.'.join(target_str_splitted[:3])
        if '-' in target_str_splitted[3]:
            start, end = target_str_splitted[3].split('-')
            return [f"{first_three_octets}.{i}" for i in range(int(start), int(end)+1)]
        else:
            return [target_str]
    else:
        print(colored("[!] Invalid input!"))

def host_discovery(target):
    try:
        ping = subprocess.run(["ping", "-c", "1", target], timeout=1, stdout=subprocess.DEVNULL)
        if ping.returncode == 0:
            print(colored(f"[+] The IP {target} is active", 'cyan'))

    except subprocess.TimeoutExpired:
        pass

def run_script():
    target_str = get_arguments()
    targets = parse_target(target_str)
    
    max_threads = 100
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(host_discovery, targets)


if __name__ == "__main__":
    run_script()
