#!/usr/bin/env python3
# encoding: UTF-8

import urllib.request
import ssl
import re
import sys

def checkifdrupal(siteurl):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    # قائمة بالبروتوكولات للتجربة (في حال فشل SSL أو عدم التوجيه)
    base_url = siteurl.rstrip('/')
    urls_to_try = [base_url]
    if base_url.startswith("https://"):
        urls_to_try.append(base_url.replace("https://", "http://"))
    elif base_url.startswith("http://"):
        urls_to_try.append(base_url.replace("http://", "https://"))

    # سياق لتجاوز مشاكل شهادات SSL
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for target_url in urls_to_try:
        # 1. فحص الصفحة الرئيسية بحثاً عن بصمات Drupal
        try:
            req = urllib.request.Request(target_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                html = response.read().decode('utf-8', errors='ignore')
                resp_headers = str(response.headers)

                # الترويسات والوسوم
                if "Drupal" in resp_headers or "X-Generator: Drupal" in resp_headers:
                    return True
                if re.search(r'<meta[^>]+name=["\']Generator["\'][^>]+content=["\']Drupal', html, re.I):
                    return True
                
                # مسارات وبصمات الكود لـ Drupal 7/8/9
                drupal_signatures = [
                    "Drupal.settings",
                    "sites/all/themes",
                    "sites/all/modules",
                    "sites/default/files",
                    "misc/drupal.js"
                ]
                if any(sig in html for sig in drupal_signatures):
                    return True
        except Exception:
            pass

        # 2. فحص مسارات الملفات الثابتة مباشرة
        paths = [
            "/misc/drupal.js",
            "/CHANGELOG.txt",
            "/modules/node/node.css",
            "/sites/all/README.txt"
        ]
        for path in paths:
            try:
                req = urllib.request.Request(target_url + path, headers=headers)
                with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                    if response.status == 200:
                        content = response.read().decode('utf-8', errors='ignore')
                        if "Drupal" in content or "Drupal.settings" in content or path.startswith("/sites/"):
                            return True
            except Exception:
                continue

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