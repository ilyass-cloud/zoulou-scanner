# Security Scan Report

**Run ID:** `4decd3c0`  
**Generated:** 2026-09-15 15:16 UTC  
**Repository:** `/home/user/zoulou_scanner`  

---

## Executive Summary

_LLM analysis was not available or was disabled._

---

## Finding Counts by Severity

| Severity | Count |
|----------|-------|
| 🟠 HIGH | 1 |
| 🟡 MEDIUM | 4 |
| 🔵 LOW | 1 |
| ⚪ INFO | 4 |

---

## Top Risks

| # | Score | Severity | Source | Title | Tool |
|---|-------|----------|--------|-------|------|
| 1 | 70 | 🟠 HIGH | CONTAINER | nginx@1.24.0 in myapp:2.4 – CVE-2024-7347 | container |
| 2 | 40 | 🟡 MEDIUM | DEPS | cryptography@41.0.3 – CVE-2023-49083 | deps |
| 3 | 40 | 🟡 MEDIUM | DEPS | requests@2.25.0 – CVE-2023-32681 | deps |
| 4 | 40 | 🟡 MEDIUM | CONTAINER | cryptography@41.0.3 in myapp:2.4 – CVE-2023-49083 | container |
| 5 | 30 | 🟡 MEDIUM | SECRETS | Generic API key pattern detected in a configuration template | secrets |
| 6 | 25 | ⚪ INFO | NETWORK | Open port 80/tcp on 10.0.0.1 (http/nginx) | network |
| 7 | 25 | ⚪ INFO | NETWORK | Open port 443/tcp on 10.0.0.1 (https/nginx) | network |
| 8 | 20 | 🔵 LOW | SAST | python.lang.security.insecure-hash – MD5 used for a non-cryp… | sast |
| 9 | 20 | ⚪ INFO | NETWORK | Open port 22/tcp on 10.0.0.1 (ssh/OpenSSH) | network |
| 10 | 20 | ⚪ INFO | NETWORK | Open port 3306/tcp on 10.0.0.2 (mysql/MySQL) | network |

---

## Finding Details

### 1. nginx@1.24.0 in myapp:2.4 – CVE-2024-7347

| Field | Value |
|-------|-------|
| **ID** | `2690823947ba176c` |
| **Severity** | 🟠 HIGH |
| **Risk Score** | 70 / 100 |
| **Source** | CONTAINER |
| **Tool** | container |
| **Confidence** | HIGH |
| **Exposure** | unknown |
| **Location** | `image_ref: myapp:2.4, layer_digest: sha256:9f1e2c4b8a7d6503, package_name: nginx, package_version: 1.24.0` |
| **CVE(s)** | CVE-2024-7347 |
| **Exposed via** | `2c6cb54ca87fa376`, `874034f39c5e6450` |

**Description:** nginx mp4 module out-of-bounds read: a crafted MP4 file can crash the worker process or disclose memory.

**Evidence:** `nginx 1.24.0 installed in layer sha256:9f1e2c4b8a7d6503`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-7347

---

### 2. cryptography@41.0.3 – CVE-2023-49083

| Field | Value |
|-------|-------|
| **ID** | `fa3377b95d66ca11` |
| **Severity** | 🟡 MEDIUM |
| **Risk Score** | 40 / 100 |
| **Source** | DEPS |
| **Tool** | deps |
| **Confidence** | LOW → MEDIUM (corroborated by 1 other finding) |
| **Exposure** | unknown |
| **Location** | `manifest_path: requirements.txt, package_name: cryptography, package_version: 41.0.3, ecosystem: pypi` |
| **CVE(s)** | CVE-2023-49083 |
| **Corroborated by** | `cbae9a434b783edf` |

**Description:** NULL dereference when loading a PKCS7 certificate bundle.

**Evidence:** `cryptography==41.0.3 declared in requirements.txt`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-49083

---

### 3. requests@2.25.0 – CVE-2023-32681

| Field | Value |
|-------|-------|
| **ID** | `1a88b81aa91b3a40` |
| **Severity** | 🟡 MEDIUM |
| **Risk Score** | 40 / 100 |
| **Source** | DEPS |
| **Tool** | deps |
| **Confidence** | HIGH |
| **Exposure** | unknown |
| **Location** | `manifest_path: requirements.txt, package_name: requests, package_version: 2.25.0, ecosystem: pypi` |
| **CVE(s)** | CVE-2023-32681 |

**Description:** Proxy-Authorization header forwarded on cross-host redirect.

**Evidence:** `requests==2.25.0 declared in requirements.txt`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-32681

---

### 4. cryptography@41.0.3 in myapp:2.4 – CVE-2023-49083

| Field | Value |
|-------|-------|
| **ID** | `cbae9a434b783edf` |
| **Severity** | 🟡 MEDIUM |
| **Risk Score** | 40 / 100 |
| **Source** | CONTAINER |
| **Tool** | container |
| **Confidence** | HIGH |
| **Exposure** | unknown |
| **Location** | `image_ref: myapp:2.4, layer_digest: sha256:9f1e2c4b8a7d6503, package_name: cryptography, package_version: 41.0.3` |
| **CVE(s)** | CVE-2023-49083 |
| **Corroborated by** | `fa3377b95d66ca11` |

**Description:** NULL dereference when loading a PKCS7 certificate bundle.

**Evidence:** `cryptography 41.0.3 (site-packages) in layer sha256:9f1e2c4b8a7d6503`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-49083

---

### 5. Generic API key pattern detected in a configuration template

| Field | Value |
|-------|-------|
| **ID** | `6641de3761e9bf9f` |
| **Severity** | 🟡 MEDIUM |
| **Risk Score** | 30 / 100 |
| **Source** | SECRETS |
| **Tool** | secrets |
| **Confidence** | LOW |
| **Exposure** | unknown |
| **Location** | `file_path: config/settings.example.yaml, start_line: 31` |

**Description:** Generic API key pattern detected in a configuration template

**Evidence:** `api_key: "sk_live_[REDACTED]"`

---

### 6. Open port 80/tcp on 10.0.0.1 (http/nginx)

| Field | Value |
|-------|-------|
| **ID** | `874034f39c5e6450` |
| **Severity** | ⚪ INFO |
| **Risk Score** | 25 / 100 |
| **Source** | NETWORK |
| **Tool** | network |
| **Confidence** | HIGH |
| **Exposure** | external |
| **Location** | `host: 10.0.0.1, port: 80, protocol: tcp, service: http, product: nginx, product_version: 1.24.0` |
| **Exposed via** | `2690823947ba176c` |

**Description:** Open port detected: 80/tcp running http/nginx on 10.0.0.1

**Evidence:** `10.0.0.1:80/tcp http nginx 1.24.0`

---

### 7. Open port 443/tcp on 10.0.0.1 (https/nginx)

| Field | Value |
|-------|-------|
| **ID** | `2c6cb54ca87fa376` |
| **Severity** | ⚪ INFO |
| **Risk Score** | 25 / 100 |
| **Source** | NETWORK |
| **Tool** | network |
| **Confidence** | HIGH |
| **Exposure** | external |
| **Location** | `host: 10.0.0.1, port: 443, protocol: tcp, service: https, product: nginx, product_version: 1.24.0` |
| **Exposed via** | `2690823947ba176c` |

**Description:** Open port detected: 443/tcp running https/nginx on 10.0.0.1

**Evidence:** `10.0.0.1:443/tcp https nginx 1.24.0`

---

### 8. python.lang.security.insecure-hash – MD5 used for a non-cryptographic checksum; flagged for review.

| Field | Value |
|-------|-------|
| **ID** | `0093e42971bbe019` |
| **Severity** | 🔵 LOW |
| **Risk Score** | 20 / 100 |
| **Source** | SAST |
| **Tool** | sast |
| **Confidence** | HIGH |
| **Exposure** | unknown |
| **Location** | `file_path: app/legacy/checksum.py, start_line: 12` |
| **CWE(s)** | CWE-328 |

**Description:** MD5 used for a non-cryptographic checksum; flagged for review.

**Evidence:** `digest = hashlib.md5(payload).hexdigest()`

---

### 9. Open port 22/tcp on 10.0.0.1 (ssh/OpenSSH)

| Field | Value |
|-------|-------|
| **ID** | `5edfc1803534d1b9` |
| **Severity** | ⚪ INFO |
| **Risk Score** | 20 / 100 |
| **Source** | NETWORK |
| **Tool** | network |
| **Confidence** | HIGH |
| **Exposure** | external |
| **Location** | `host: 10.0.0.1, port: 22, protocol: tcp, service: ssh, product: OpenSSH, product_version: 8.9p1` |

**Description:** Open port detected: 22/tcp running ssh/OpenSSH on 10.0.0.1

**Evidence:** `10.0.0.1:22/tcp ssh OpenSSH 8.9p1`

---

### 10. Open port 3306/tcp on 10.0.0.2 (mysql/MySQL)

| Field | Value |
|-------|-------|
| **ID** | `b75c72284e7b1b1e` |
| **Severity** | ⚪ INFO |
| **Risk Score** | 20 / 100 |
| **Source** | NETWORK |
| **Tool** | network |
| **Confidence** | HIGH |
| **Exposure** | external |
| **Location** | `host: 10.0.0.2, port: 3306, protocol: tcp, service: mysql, product: MySQL, product_version: 8.0.33` |

**Description:** Open port detected: 3306/tcp running mysql/MySQL on 10.0.0.2

**Evidence:** `10.0.0.2:3306/tcp mysql MySQL 8.0.33`

---
