#!/usr/bin/env python3
# encoding: UTF-8
################################################################################
# Tasiopoulos Vasilis - tasiopoulos[DOT]vasilis[AT]gmail[DOT]com
# Modernized for Python 3
################################################################################

import os
import re
import sys
import urllib.request

# استيراد الملفات الفرعية المرفقة في مشروع drupscan
try:
    from updatevulnerabilitylist import updatevuln
    from drupcheck import checkifdrupal
    from drupupdate import drupupdate
except ImportError:
    pass

version = "1.0.0 [Beta]"
drupalversion = ""


class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERL = '\033[4m'
    RESET = '\033[0;0m'


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

    # 1. المحاولة الأولى: قراءة CHANGELOG.txt
    try:
        url = base_url + "/CHANGELOG.txt"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            lines = response.read().decode('utf-8', errors='ignore').splitlines()
            for line in lines:
                if "Drupal " in line:
                    # استخراج رقم الإصدار عبر Regular Expression
                    match = re.search(r'Drupal\s+([\d\.\-x]+)', line)
                    if match:
                        drupalversion = match.group(1).rstrip(',')
                        break
    except Exception:
        pass

    # 2. المحاولة الثانية (إذا فشلت الأولى): فحص الـ Meta Generator في الصفحة الرئيسية
    if not drupalversion:
        try:
            req = urllib.request.Request(base_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=8) as response:
                html = response.read().decode('utf-8', errors='ignore')
                match = re.search(r'content="Drupal\s+([\d\.]+)', html, re.IGNORECASE)
                if match:
                    drupalversion = match.group(1)
        except Exception:
            pass

    # طباعة النتيجة النهائية
    if drupalversion:
        print(f"[+] Drupal version is {drupalversion}")
        matchvulnerability()
    else:
        print("[!] Cannot identify Drupal's Version (CHANGELOG.txt is hidden or protected)")


def matchvulnerability():
    global drupalversion
    vfile = "vulnerabilities/drupalvulnerabilitieslist.txt"
    if not os.path.exists(vfile):
        print("[-] Vulnerabilities list file not found.")
        return

    if not drupalversion:
        print("[!] No version specified to match vulnerabilities.")
        return

    print(f"\n[+] Matching vulnerabilities specifically for Drupal version: {drupalversion}")
    
    with open(vfile, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    matched = 0
    for line in lines:
        # 1. التأكد من وجود قسم Version داخل السطر
        if "Version:" in line:
            version_part = line[line.index("Version:"):].strip()
            
            # 2. البحث عن رقم الإصدار كمقطع مستقل داخل جزئية Version فقط
            # يتجنب سنوات CVE ومطابقة الأرقام المتداخلة مثل 7.11 أو 6.11
            pattern = r'(?<![\d\.])' + re.escape(drupalversion) + r'(?![\d\.])'
            
            if re.search(pattern, version_part):
                matched += 1
                try:
                    sys.stdout.write(color.BOLD + "\n [.] " + line[:line.index("Type:")] + color.RESET + "\n")
                    sys.stdout.write(color.RED + " [.] " + line[line.index("Type:"):line.index("Descripion:")] + "\n " + color.RESET)
                    sys.stdout.write("[.] " + line[line.index("Url:"):line.index("Version:")] + "\n ")
                    sys.stdout.write(color.GREEN + "[.] " + line[line.index("Descripion:"):line.index("Url:")] + "\n " + color.RESET)
                    sys.stdout.flush()
                except ValueError:
                    print(f"[.] {line.strip()}")

    if matched == 0:
        print(f"[+] No matching vulnerabilities found in local database for Drupal {drupalversion}.")


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