# 404-Fingerprint
Advanced 404 error page fingerprinting tool for identifying web frameworks and servers during reconnaissance.

404-Fingerprint reveals backend technologies by analyzing HTTP error pages (HTML, JSON, templates, default framework fallback pages).
It works even when security headers are removed, making it extremely useful for reconnaissance, technology discovery, and responsible disclosure workflows.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/status-active-success" />
  <img src="https://img.shields.io/badge/fingerprinting-404%20error%20pages-orange" />
</p>

---

## Web Servers
```python
- Apache httpd
- nginx
- Microsoft IIS
- Caddy
- Lighttpd
```

## Back-end Frameworks
```python
- Spring Boot (HTML & JSON errors)
- Tomcat
- Flask
- Django
- FastAPI
- Laravel
- Symfony
- API Platform (Hydra JSON-LD)
- Node.js / Express
- Next.js
- Ruby on Rails
- Sinatra
- Jetty
- ASP.NET / ASP.NET Core
```

## Fuzzing
```python
/random123
/admin123
/asdfgh
/no-such-page-xyz
/this-page-should-not-exist-404
```

## Install using

```python
git clone https://github.com/asifnawazminhas/404-Fingerprint
cd 404-Fingerprint
chmod +x 404_fingerprint.py
```

## Install dependencies
```python
pip install requests
```

## 1. Basic fingerprinting
```python
python3 404_fingerprint.py https://example.com/doesnotexist
```

## 2. Ignore SSL warnings
```python
python3 404_fingerprint.py https://expired.badssl.com --insecure
```

## 3. CSV Output
```python
python3 404_fingerprint.py -l urls.txt --csv > results.csv
```

## 4. Markdown recon report
```python
python3 404_fingerprint.py -l urls.txt --markdown-out report.md
```

## Example Detections

### Apache httpd (via default headers)
```bash
python3 404_fingerprint.py https://tomcat.apache.org/
# Tech Stack Guess: Apache httpd (header only)

python3 404_fingerprint.py https://tomcat.apache.org/ --tech-only
# https://tomcat.apache.org/ | status=200 | tech=Apache httpd (header only) | default_page=- | soft_404=No
```

```bash
python3 404_fingerprint.py https://start.spring.io/thispagedoesnotexist
# Tech Stack Guess: Spring Boot

python3 404_fingerprint.py https://start.spring.io/thispagedoesnotexist --tech-only
# https://start.spring.io/thispagedoesnotexist | status=404 | tech=Spring Boot | default_page=Whitelabel Error Page | soft_404=Yes
```

### Credits

404 fingerprinting signatures inspired by research from 0xdf:
[0xdf Research ↗](https://0xdf.gitlab.io/cheatsheets/404#aspnet-core)

License

Released under the MIT License.
