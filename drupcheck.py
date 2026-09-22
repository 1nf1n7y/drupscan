#!/usr/bin/env python3
# encoding: UTF-8

import urllib.request
import sys

def checkifdrupal(siteurl):
    try:
        url = siteurl.rstrip('/') + "/misc/drupal.js"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                return True
    except Exception:
        pass

    try:
        url = siteurl.rstrip('/') + "/CHANGELOG.txt"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            if "Drupal" in content:
                return True
    except Exception:
        pass

    return False

if __name__ == '__main__':
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target
        is_drupal = checkifdrupal(target)
        print(f"[+] Target {target} is Drupal: {is_drupal}")
    else:
        print("Usage: python drupcheck.py <URL>")