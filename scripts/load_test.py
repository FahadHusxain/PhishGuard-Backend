"""Small dependency-free-of-framework HTTP load smoke test for PhishGuard."""

import argparse
import math
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def percentile(values, percentile_value):
    ordered = sorted(values)
    index = max(0, math.ceil((percentile_value / 100) * len(ordered)) - 1)
    return ordered[index]


def send_request(base_url, target, timeout):
    started = time.perf_counter()
    if target == "health":
        response = requests.get(f"{base_url}/health/live/", timeout=timeout)
    else:
        response = requests.post(
            f"{base_url}/api/v1/predict/",
            json={"url": target},
            timeout=timeout,
        )
    return response.status_code, (time.perf_counter() - started) * 1000


def main():
    parser = argparse.ArgumentParser(
        description="Run a bounded concurrency smoke test against PhishGuard.",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument(
        "--target",
        default="health",
        help="Use 'health' for a read-only test or provide an HTTP(S) URL to analyze.",
    )
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1 or args.timeout <= 0:
        parser.error("requests, concurrency, and timeout must be positive")
    if args.target != "health" and not args.target.startswith(("http://", "https://")):
        parser.error("target must be 'health' or an HTTP(S) URL")

    base_url = args.base_url.rstrip("/")
    started = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(send_request, base_url, args.target, args.timeout)
            for _ in range(args.requests)
        ]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except requests.RequestException:
                results.append((0, 0.0))

    duration = time.perf_counter() - started
    successful_latencies = [
        latency for status, latency in results if 200 <= status < 300
    ]
    failures = len(results) - len(successful_latencies)
    print(f"requests={len(results)} failures={failures} duration={duration:.2f}s")
    print(f"throughput={len(results) / duration:.2f} requests/second")
    if successful_latencies:
        print(
            f"latency_ms median={statistics.median(successful_latencies):.2f} "
            f"p95={percentile(successful_latencies, 95):.2f} "
            f"max={max(successful_latencies):.2f}"
        )
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
