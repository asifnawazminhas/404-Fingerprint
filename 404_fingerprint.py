#!/usr/bin/env python3
import argparse
import csv
import sys
import textwrap
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
import urllib3
import re
from datetime import datetime

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Disable InsecureRequestWarning when using --insecure
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def print_banner():
    banner = """
┌───────────────────────────────────────────────────────────────┐
│                           404 PROFILER                       │
│                Web Error-Page Fingerprint Scanner            │
└───────────────────────────────────────────────────────────────┘
"""
    print(banner)


def colorize(text, color):
    if text is None:
        return text
    return f"{color}{text}{RESET}"


def get_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return None


def detect_server_class(server_header):
    if not server_header:
        return "unknown"
    s = server_header.lower()
    if "nginx" in s:
        return "nginx"
    if "apache" in s:
        return "apache"
    if "iis" in s:
        return "iis"
    if "cloudflare" in s:
        return "cloudflare"
    if "tomcat" in s:
        return "tomcat"
    return "unknown"


def detect_tech_stack(response, body):
    """
    Return a short string guess for the tech stack based on 404 templates / content.
    """
    body_lower = body.lower()
    server_header = response.headers.get("Server", "") or ""
    server_lower = server_header.lower()
    content_type = (response.headers.get("Content-Type") or "").lower()
    stack = []

    # Spring Boot Whitelabel (HTML)
    if "whitelabel error page" in body_lower or "this application has no explicit mapping for /error" in body_lower:
        stack.append("Spring Boot")

    # Spring Boot JSON error (common pattern)
    if "application/json" in content_type:
        # Typical Spring Boot error JSON has these fields
        if (
            '"timestamp"' in body_lower
            and '"status"' in body_lower
            and '"error"' in body_lower
            and '"path"' in body_lower
        ):
            stack.append("Spring Boot (JSON error)")

    # Tomcat default
    if "http status 404" in body_lower and "apache tomcat" in body_lower:
        stack.append("Apache Tomcat")

    # Nginx default
    if "<center><h1>404 not found</h1></center>" in body_lower and "nginx/" in body_lower:
        stack.append("nginx")

    # Flask default 404
    if "the requested url was not found on the server. if you entered the url manually please check your spelling and try again." in body_lower:
        stack.append("Flask")

    # Django default 404
    if "<title>not found</title>" in body_lower and "the requested resource was not found on this server." in body_lower:
        stack.append("Django")

    # FastAPI JSON 404 (heuristic)
    if '"detail"' in body_lower and '"not found"' in body_lower and "fastapi" in body_lower:
        stack.append("FastAPI")

    # PHP-FPM "File not found."
    if "file not found.\n" in body and "primary script unknown" not in body_lower:
        stack.append("PHP-FPM")

    # Laravel-ish 404 (rough heuristic)
    if "the page you were looking for doesn't exist" in body_lower and "laravel" in body_lower:
        stack.append("Laravel")

    # Symfony classic HTML error
    if "oops! an error occurred" in body_lower and "the server returned a \"404 not found\"" in body_lower:
        stack.append("Symfony")

    # API Platform / Symfony JSON-LD Hydra errors
    if '"hydra:title"' in body_lower and '"hydra:description"' in body_lower:
        stack.append("Symfony (API Platform)")

    # Express / Fiber style error
    if "cannot get /" in body_lower:
        stack.append("Express / Fiber")

    # Rails default 404
    if "the page you were looking for doesn't exist" in body_lower and "rails-default-error-page" in body_lower:
        stack.append("Ruby on Rails")

    # ASP.NET classic YSOD
    if "server error in '/' application." in body_lower:
        stack.append("ASP.NET")

    # ASP.NET Core / resource cannot be found
    if "the resource cannot be found." in body_lower and "description: http 404." in body_lower:
        if "asp.net" not in " ".join(stack).lower():
            stack.append("ASP.NET / IIS")

    # Next.js default 404
    if "this page could not be found" in body_lower and "next-error-h1" in body_lower:
        stack.append("NextJS")

    # If we didn't find anything from body, fall back to Server header
    if not stack:
        if "nginx" in server_lower:
            stack.append("nginx (header only)")
        elif "apache" in server_lower:
            stack.append("Apache httpd (header only)")
        elif "microsoft-iis" in server_lower:
            stack.append("IIS (header only)")
        elif "tomcat" in server_lower:
            stack.append("Apache Tomcat (header only)")
        elif server_header:
            stack.append(server_header)
        else:
            stack.append("Unknown")

    # Deduplicate while preserving order
    seen = set()
    result = []
    for s in stack:
        if s not in seen:
            seen.add(s)
            result.append(s)

    return " / ".join(result)


def detect_default_page(body):
    body_lower = body.lower()

    if "whitelabel error page" in body_lower:
        return "Whitelabel Error Page"
    if "http status 404" in body_lower and "status report" in body_lower and "apache tomcat" in body_lower:
        return "Tomcat Default 404"
    if "404 - file or directory not found." in body_lower and "the resource you are looking for might have been removed" in body_lower:
        return "IIS Default 404"
    if "the page you were looking for doesn't exist (404)" in body_lower:
        return "Rails Default 404"
    if "the requested url was not found on the server" in body_lower and "flask" in body_lower:
        return "Flask Default 404"
    if "the requested resource was not found on this server." in body_lower and "<title>not found</title>" in body_lower:
        return "Django Default 404"
    if "<center><h1>404 not found</h1></center>" in body_lower and "nginx/" in body_lower:
        return "nginx Default 404"

    return None


def detect_directory_listing(body):
    body_lower = body.lower()
    if "<title>index of /" in body_lower or "<h1>index of /" in body_lower:
        return True
    if "directory listing for" in body_lower:
        return True
    if "parent directory" in body_lower and "index of /" in body_lower:
        return True
    return False


def extract_markers(body):
    body_lower = body.lower()
    keywords = ["error", "not found", "forbidden", "denied", "oops", "exception"]
    found = []
    for k in keywords:
        if k in body_lower:
            found.append(k)
    return found


def fetch(url, verify=True, timeout=10.0):
    # Spoof a real browser to avoid JSON-only / bot responses
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
            "Gecko/20100101 Firefox/128.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    try:
        resp = requests.get(
            url,
            headers=headers,
            allow_redirects=True,
            verify=verify,
            timeout=timeout,
        )
        return resp, None
    except RequestException as e:
        return None, str(e)


def profile_url(url, args):
    verify = not args.insecure
    result = {
        "url": url,
        "status": None,
        "title": None,
        "server_header": None,
        "server_class": None,
        "tech": None,
        "default_page": None,
        "soft_404": False,
        "dir_listing": False,
        "markers": [],
        "body_len": None,
        "word_count": None,
        "fuzz_results": [],
        "error": None,
        "content_type": None,
    }

    if not args.csv:
        print(f"{BOLD}[+]{RESET} Fetching: {url}")

    resp, err = fetch(url, verify=verify, timeout=args.timeout)
    if err or resp is None:
        if not args.csv and not args.tech_only:
            print(colorize("[-] Could not fetch URL. See error above.", RED))
        result["error"] = err or "Request failed"
        return result

    body = resp.text or ""
    status = resp.status_code
    result["status"] = status
    result["body_len"] = len(body.encode("utf-8", errors="ignore"))
    result["word_count"] = len(body.split())
    title = get_title(body)
    result["title"] = title
    server_header = resp.headers.get("Server")
    result["server_header"] = server_header
    result["server_class"] = detect_server_class(server_header)
    result["content_type"] = resp.headers.get("Content-Type")
    tech = detect_tech_stack(resp, body)
    result["tech"] = tech
    default_page = detect_default_page(body)
    result["default_page"] = default_page
    dir_listing = detect_directory_listing(body)
    result["dir_listing"] = dir_listing
    markers = extract_markers(body)
    result["markers"] = markers

    # Determine soft 404 – template 404 if original is 404 and fuzz paths look similar
    fuzz_paths = [
        "/random123",
        "/admin123",
        "/asdfgh",
        "/no-such-page-xyz",
        "/this-page-should-not-exist-404",
    ]

    baseline_len = result["body_len"] if status == 404 else None
    fuzz_results = []

    base = url.rstrip("/")

    for p in fuzz_paths:
        fuzz_url = urljoin(base + "/", p.lstrip("/"))
        fr_resp, fr_err = fetch(fuzz_url, verify=verify, timeout=args.timeout)
        if fr_err or fr_resp is None:
            fuzz_results.append({"path": p, "status": "err", "len": None, "similar": False})
            continue
        fr_body = fr_resp.text or ""
        fr_len = len(fr_body.encode("utf-8", errors="ignore"))
        similar = False
        if baseline_len is not None and fr_resp.status_code == 404:
            if abs(fr_len - baseline_len) <= 50:
                similar = True
        fuzz_results.append(
            {
                "path": p,
                "status": fr_resp.status_code,
                "len": fr_len,
                "similar": similar,
            }
        )

    result["fuzz_results"] = fuzz_results

    # Soft 404 heuristic – treat as template 404 if original is 404 and most fuzzes are similar
    if status == 404:
        similar_count = sum(1 for fr in fuzz_results if fr["similar"])
        total_404 = sum(1 for fr in fuzz_results if isinstance(fr["status"], int) and fr["status"] == 404)
        if total_404 > 0 and similar_count >= max(1, total_404 - 1):
            result["soft_404"] = True

    return result


def print_verbose_result(res):
    if res["error"]:
        print(colorize("[-] Could not fetch URL. See error above.", RED))
        return

    print()
    print("=== HTTP Info ===")
    print(f"Status: {res['status']}")
    print(f"Title: {res['title']}")
    print(f"Server header: {res['server_header']}")
    print(f"Content-Type: {res['content_type']}")

    tech_colored = colorize(res["tech"], GREEN) if res["tech"] else "Unknown"
    print(f"Tech fingerprint: {tech_colored}")
    print()
    print("=== Fingerprints ===")

    if res["soft_404"]:
        print("[*] Soft 404 detected (template-style 404 across multiple paths)")
    else:
        print("[*] Soft 404 not detected.")

    if res["dir_listing"]:
        print("[*] Directory listing detected.")
    else:
        print("[*] Directory listing not detected.")

    if res["default_page"]:
        print(f"[*] Default server page detected: {res['default_page']}")
    else:
        print("[*] Default server page detected: None")

    if res["markers"]:
        print(f"[*] Detected error phrases: {', '.join(res['markers'])}")
    else:
        print("[*] Detected error phrases: None")

    print()
    print("=== Body Stats ===")
    print(f"Length: {res['body_len']} bytes")
    print(f"Words: {res['word_count']}")
    print()
    print("=== Fuzzing non existing paths (root based) ===")

    for fr in res["fuzz_results"]:
        path = fr["path"]
        status = fr["status"]
        length = fr["len"]
        extra = ""
        if fr["similar"]:
            extra = " (similar to baseline)"
        if status == "err":
            line = f"{path:<30} -> status err, len=None"
        else:
            line = f"{path:<30} -> status {status}, len={length}{extra}"
        print(line)

    print()
    print("=== 404 Summary ===")
    tech_colored_summary = colorize(res["tech"], GREEN) if res["tech"] else "Unknown"
    print(f"- URL: {res['url']}")
    print(f"- Status Code: {res['status']}")
    print(f"- Title: {res['title']}")
    print(f"- Server (header): {res['server_header']}")
    print(f"- Server (class): {res['server_class']}")
    print(f"- Tech Stack Guess: {tech_colored_summary}")
    if res["markers"]:
        print(f"- Interesting Markers: {', '.join(res['markers'])}")
    else:
        print("- Interesting Markers: None")
    print(f"- Possible Soft 404: {'Yes' if res['soft_404'] else 'No'}")
    print(f"- Default Page: {res['default_page'] or 'None'}")
    print(f"- Directory Listing: {'Yes' if res['dir_listing'] else 'No'}")


def write_markdown(results, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# 404 Profiler Report\n\n")
        f.write(f"Generated at: {datetime.utcnow().isoformat()} UTC\n\n")
        f.write("| URL | Status | Tech Stack | Default Page | Soft 404 | Dir Listing | Markers |\n")
        f.write("| --- | ------ | ---------- | ------------ | -------- | ----------- | ------- |\n")
        for r in results:
            status = r["status"] if r["status"] is not None else "err"
            tech = r["tech"] or "Unknown"
            default_page = r["default_page"] or "-"
            soft = "Yes" if r["soft_404"] else "No"
            dlist = "Yes" if r["dir_listing"] else "No"
            markers = ", ".join(r["markers"]) if r["markers"] else "-"
            f.write(f"| {r['url']} | {status} | {tech} | {default_page} | {soft} | {dlist} | {markers} |\n")


def main():
    parser = argparse.ArgumentParser(
        description="404 Profiler – HTTP error-page fingerprinting tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              python3 404_profiler.py https://example.com/doesnotexist
              python3 404_profiler.py -l urls.txt --insecure
              python3 404_profiler.py -l urls.txt --csv > results.csv
              python3 404_profiler.py https://example.com/404 --tech-only
              python3 404_profiler.py -l urls.txt --markdown-out report.md
            """
        ),
    )

    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-l", "--list", help="File with list of URLs (one per line)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout (seconds)")
    parser.add_argument(
        "--markdown-out",
        help="Write a Markdown report of all findings to this file",
    )
    parser.add_argument(
        "--tech-only",
        action="store_true",
        help="Print only a concise per-URL tech summary (URL, status, tech, default_page, soft_404)",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Output CSV (URL,status,tech,default_page,soft_404) to stdout",
    )

    args = parser.parse_args()

    # Collect target URLs
    targets = []

    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    targets.append(line)
        except OSError as e:
            print(colorize(f"[-] Failed to read list file: {e}", RED), file=sys.stderr)
            sys.exit(1)

    if args.url:
        targets.append(args.url)

    if not targets:
        print("[-] You must provide a URL or a list file with -l.", file=sys.stderr)
        sys.exit(1)

    # Show banner only in human interactive mode
    if not args.csv and not args.tech_only:
        print_banner()

    results = []

    # CSV writer setup if needed
    csv_writer = None
    if args.csv:
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerow(["url", "status", "tech", "default_page", "soft_404"])

    for url in targets:
        res = profile_url(url, args)
        results.append(res)

        if args.csv:
            status = res["status"] if res["status"] is not None else ""
            tech = res["tech"] or ""
            default_page = res["default_page"] or ""
            soft = "1" if res["soft_404"] else "0"
            csv_writer.writerow([url, status, tech, default_page, soft])
            continue

        if args.tech_only:
            status = res["status"] if res["status"] is not None else "err"
            tech = res["tech"] or "Unknown"
            tech_colored = colorize(tech, GREEN)
            default_page = res["default_page"] or "-"
            soft = "Yes" if res["soft_404"] else "No"
            print(
                f"{url} | status={status} | tech={tech_colored} | "
                f"default_page={default_page} | soft_404={soft}"
            )
            continue

        # Full verbose output
        print_verbose_result(res)

    if args.markdown_out:
        write_markdown(results, args.markdown_out)
        if not args.csv and not args.tech_only:
            print()
            print(colorize(f"[+] Markdown report written to {args.markdown_out}", GREEN))


if __name__ == "__main__":
    main()
