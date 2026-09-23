#!/usr/bin/env python3
# encoding: UTF-8
################################################################################
# Tasiopoulos Vasilis - tasiopoulos[DOT]vasilis[AT]gmail[DOT]com
# Modernized for Python 3 & Maintained by 1nf1n7y
################################################################################

import os
import re
import sys
import ssl
import urllib.request

# استيراد الملفات الفرعية المرفقة
from updatevulnerabilitylist import updatevuln
from drupcheck import checkifdrupal
from drupupdate import drupupdate

version = "1.0.0 [Beta]"
drupalversion = ""


# تعريف ألوان وتنسيقات ANSI في أعلى الملف أو قبل الدالة
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def scanmultiple():
    urlfile = input("\nGive the path of the txt file: ")
    try:
        with open(urlfile, 'r') as d:
            urlfilelines = d.readlines()
    except Exception as e:
        print(f"\n[-] Error : '{urlfile}' not found ({e})")
        print("[-] Exiting Drupal Scan..\n")
        return

    for url in urlfilelines:
        url = url.strip()
        if not url:
            continue
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        sys.stdout.write(color.BOLD + f"\n [+] Checking for {url} \n " + color.RESET)
        if checkifdrupal(url):
            checksinglesite(url)
        else:
            sys.stdout.write(color.RED + f"\n [!] {url} is not Drupal \n " + color.RESET)


def checksinglesite(siteurl):
    global drupalversion
    drupalversion = ""
    base_url = siteurl.rstrip('/')

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    # 1. Check CHANGELOG.txt and standard plain text documentation files
    text_files = ["/CHANGELOG.txt", "/core/CHANGELOG.txt", "/MAINTAINERS.txt"]
    for tf in text_files:
        try:
            url = base_url + tf
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=6, context=ctx) as response:
                if response.status == 200:
                    lines = response.read().decode('utf-8', errors='ignore').splitlines()
                    for line in lines:
                        if "Drupal " in line:
                            match = re.search(r'Drupal\s+([\d\.\-x]+)', line)
                            if match:
                                drupalversion = match.group(1).rstrip(',')
                                break
            if drupalversion:
                break
        except Exception:
            pass

    # 2. Check HTML meta generator tag AND asset query parameters (?v=X.X or ?X.X)
    if not drupalversion:
        try:
            req = urllib.request.Request(base_url, headers=headers)
            with urllib.request.urlopen(req, timeout=8, context=ctx) as response:
                html = response.read().decode('utf-8', errors='ignore')

                # Meta generator tag
                match = re.search(r'content=["\']Drupal\s+([\d\.]+)', html, re.IGNORECASE)
                if match:
                    drupalversion = match.group(1)

                # Asset query strings (e.g., system.base.css?v=7.59 or drupal.js?7.59)
                if not drupalversion:
                    asset_match = re.search(r'(?:css|js)\?[^"\']*?\b(?:v=)?(7\.\d+|8\.\d+|9\.\d+|10\.\d+)', html, re.IGNORECASE)
                    if asset_match:
                        drupalversion = asset_match.group(1)

                # Structural/global JS fallbacks if exact version is hidden
                if not drupalversion:
                    if "misc/drupal.js" in html or "Drupal.settings" in html or "sites/all/" in html or "sites/default/" in html:
                        drupalversion = "7.x"
                    elif "/core/" in html or "drupalSettings" in html:
                        drupalversion = "8.x"
        except Exception:
            pass

    # 3. Direct core file availability check
    if not drupalversion:
        core_files = ["/modules/system/system.css", "/misc/drupal.js", "/modules/node/node.css"]
        for cf in core_files:
            try:
                url = base_url + cf
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                    if response.status == 200:
                        drupalversion = "7.x"
                        break
            except Exception:
                continue

    # 4. Final fallback
    if not drupalversion:
        drupalversion = "7.x"
        print("[!] Specific version hidden by target. Falling back to generic version: 7.x")

    print(f"[+] Drupal version detected: {drupalversion}")
    matchvulnerability()




def parse_version_tuple(ver_str):
    try:
        parts = [int(p) for p in re.findall(r"\d+", ver_str)]
        return tuple(parts)
    except Exception:
        return ()


def is_version_vulnerable(target_str, description):
    target = parse_version_tuple(target_str)
    if not target or target[0] != 7:
        return False

    desc_lower = description.lower()

    if "drupal 7" not in desc_lower and "7.x" not in desc_lower:
        if re.search(r"drupal\s+(core\s+)?(8|9|10|11)", desc_lower):
            return False

    before_match = re.search(
        r"(?:prior to|before)\s+7\.(\d+)", desc_lower, re.IGNORECASE
    )
    from_match = re.search(
        r"(?:from|after)\s+7\.(\d+)", desc_lower, re.IGNORECASE
    )

    fixed_minor = int(before_match.group(1)) if before_match else None
    start_minor = int(from_match.group(1)) if from_match else 0

    target_minor = target[1] if len(target) > 1 else 0

    if fixed_minor is not None:
        if target_minor >= fixed_minor:
            return False
        if target_minor < start_minor:
            return False
        return True

    earlier_match = re.search(
        r"7\.(\d+)\s+and\s+earlier", desc_lower, re.IGNORECASE
    )
    if earlier_match:
        affected_minor = int(earlier_match.group(1))
        return target_minor <= affected_minor

    if (
        "drupal 7.x" in desc_lower
        and "remote code execution" in desc_lower
        and fixed_minor is None
    ):
        return True

    return False


def format_colored_line(line):
    """تنسيق وتلوين حقول الثغرة"""
    # تلوين عنوان الثغرة (CVE) بالأحمر العريض
    line = re.sub(
        r"(Title:\s*)(CVE-[\d-]+)",
        rf"{CYAN}\1{RESET}{RED}{BOLD}\2{RESET}",
        line,
    )

    # تلوين الرابط باللون الأزرق/السماوي
    line = re.sub(
        r"(Url:\s*)(https?://\S+)",
        rf"{CYAN}\1{RESET}{CYAN}\2{RESET}",
        line,
    )

    # تلوين حقل الوصف
    line = re.sub(
        r"(Descripion:)",
        rf"{YELLOW}\1{RESET}",
        line,
    )

    # تلوين حقل الإصدارات
    line = re.sub(
        r"(Version:\s*\[.*?\])",
        rf"{GREEN}\1{RESET}",
        line,
    )

    return line


def matchvulnerability():
    global drupalversion
    vfile = "vulnerabilities/drupalvulnerabilitieslist.txt"

    if not os.path.exists(vfile):
        print(f"{RED}[-] Vulnerabilities list file not found.{RESET}")
        return

    if not drupalversion:
        print(f"{YELLOW}[!] No version specified to match vulnerabilities.{RESET}")
        return

    print(
        f"\n{BOLD}{CYAN}[+] Matching vulnerabilities specifically for Drupal version: {GREEN}{drupalversion}{RESET}\n"
    )

    with open(vfile, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    matched = 0

    for line in lines:
        if "Descripion:" not in line:
            continue

        description = line[line.index("Descripion:") :].strip()

        if is_version_vulnerable(drupalversion, description):
            matched += 1
            colored_line = format_colored_line(line.strip())
            sys.stdout.write(colored_line + "\n\n")

    if matched == 0:
        print(
            f"{GREEN}[+] No matching vulnerabilities found in local database for Drupal {drupalversion}.{RESET}"
        )
    else:
        print(
            f"{BOLD}{RED}[!] Total vulnerabilities found: {matched}{RESET}"
        )


def modulescanner(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            modurl = resp.read().decode('utf-8', errors='ignore')

        vfile = "vulnerabilities/drupalmodulevulnerabilitieslist.txt"
        if not os.path.exists(vfile):
            print("[-] Module vulnerabilities list file not found.")
            return

        with open(vfile, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for modulename in lines:
            if "Vulnerable module:" in modulename and "Type:" in modulename:
                moduleonlyname = modulename[modulename.index("Vulnerable module:") + 18:modulename.index("Type:")]
                moduleonlyname = moduleonlyname.replace("Module", "").replace("Drupal", "").replace(" ", "").lower().strip()

                if moduleonlyname in modurl.lower():
                    print(color.BOLD + f"\n [.] Found module vulnerability: {moduleonlyname}" + color.RESET)
                    print(f"[.] {modulename.strip()}")
    except Exception as e:
        print(f"[!] Error scanning modules: {e}")


def modulescannerxray(url):
    modulelist = []
    clean_url = url.replace("http://", "").replace("https://", "")
    if not clean_url.startswith("www."):
        clean_url = "www." + clean_url

    xray_url = "http://drupalxray.com/xray/" + clean_url
    try:
        req = urllib.request.Request(xray_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            lines = resp.read().decode('utf-8', errors='ignore').splitlines()

        for line in lines:
            if "<a href=\"http://drupal.org/project/" in line:
                module = line[line.index("target=\"_blank\">") + 16:line.index("</a>")]
                modulelist.append(module)

        print(f"According to drupalxray.com, {url} has the above modules installed:\n")
        for item in modulelist:
            print(f" - {item}")
    except Exception as e:
        print(f"[!] Error connecting to drupalxray.com: {e}")


def main():
    print(f"[+] Version : {version}")
    print("[+] Copyright (C) 2013 - Drupal Scan Development Team.\n")

    while True:
        print("""
  [+] Drupal Scan Toolkit Menu:
  [+] Press "S" to scan a single site.
  [+] Press "L" to scan from a list.
  [+] Press "M" to scan drupal's modules (Experimental).
  [+] Enter "V" to update Vulnerability database.
  [+] Enter "U" for update tool.
  [+] Enter "Q" for quit.
  """)

        option = input("Enter Option: > ").strip()

        if option.lower() == 's':
            siteurl = input("give me the site to check: ").strip()
            if not siteurl.startswith("http://") and not siteurl.startswith("https://"):
                siteurl = "http://" + siteurl
            if checkifdrupal(siteurl):
                checksinglesite(siteurl)
            else:
                sys.stdout.write(color.RED + "\n [!] This site is not Drupal \n " + color.RESET)

        elif option.lower() == 'l':
            scanmultiple()

        elif option.lower() == 'm':
            print("\n  [+] Do you want to use drupalxray.com (y/n)?")
            sub_option = input("Enter Option: > ").strip().lower()
            siteurl = input("give me the site to check: ").strip()
            if not siteurl.startswith("http://") and not siteurl.startswith("https://"):
                siteurl = "http://" + siteurl

            if checkifdrupal(siteurl):
                if sub_option == 'y':
                    modulescannerxray(siteurl)
                else:
                    modulescanner(siteurl)
            else:
                sys.stdout.write(color.RED + "\n [!] This site is not Drupal \n " + color.RESET)

        elif option.lower() == 'v':
            updatevuln()

        elif option.lower() == 'u':
            drupupdate()

        elif option.lower() == 'q':
            print("[-] Exiting Drupal Scan\n")
            sys.exit()


if __name__ == '__main__':
    main()